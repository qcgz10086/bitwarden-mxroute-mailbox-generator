import type { GenerateResult } from "../../../packages/contracts/src/index";
import {
  encryptPassword,
  tokenHmac,
  type EncryptPasswordInput,
  type EncryptedPassword,
} from "../../../packages/security/src/crypto";
import {
  randomMailboxPassword,
  randomPrefix,
} from "../../../packages/security/src/random";
import { ServiceError, type ServiceErrorCode } from "./errors";
import type { MxrouteClient } from "./mxroute";
import {
  RepositoryError,
  type ApiTokenRecord,
  type Repository,
  type RepositorySettings,
} from "./repository";

const MAX_CONFLICT_RETRIES = 5;

export type GenerationErrorCode =
  | "INVALID_TOKEN"
  | "GENERATION_DISABLED"
  | "DEFAULT_DOMAIN_UNAVAILABLE"
  | "DAILY_LIMIT"
  | "TOTAL_LIMIT"
  | "MX_UNAUTHORIZED"
  | "MX_NOT_FOUND"
  | "MX_CONFLICT"
  | "MX_RATE_LIMITED"
  | "MX_SERVER"
  | "MX_TIMEOUT"
  | "MX_INVALID_RESPONSE"
  | "INTERNAL_ERROR";

export class GenerationError extends Error {
  readonly name = "GenerationError";

  constructor(
    readonly code: GenerationErrorCode,
    readonly status: number,
    readonly retryable: boolean,
    readonly requestId: string,
  ) {
    super(code);
  }
}

type GenerationRepository = Pick<Repository,
  | "verifyTokenDigest"
  | "getSettings"
  | "reservePendingMailbox"
  | "failPendingMailbox"
  | "transitionMailbox"
  | "appendAudit"
>;

type GenerationMxroute = Pick<MxrouteClient, "createMailbox">;
type IdKind = "request" | "mailbox" | "audit";

export interface MailboxServiceDependencies {
  readonly repository: GenerationRepository;
  readonly mxroute: GenerationMxroute;
  readonly tokenPepper: string;
  readonly encryptionKey: string;
  readonly encryptionKeyVersion: number;
  readonly now?: () => Date;
  readonly randomPrefix?: (length: number) => string;
  readonly randomMailboxPassword?: () => string;
  readonly encryptPassword?: (input: EncryptPasswordInput) => Promise<EncryptedPassword>;
  readonly createId?: (kind: IdKind) => string;
  readonly randomAliasId?: () => number;
}

export class MailboxService {
  private readonly repository: GenerationRepository;
  private readonly mxroute: GenerationMxroute;
  private readonly now: () => Date;
  private readonly generatePrefix: (length: number) => string;
  private readonly generatePassword: () => string;
  private readonly encrypt: (input: EncryptPasswordInput) => Promise<EncryptedPassword>;
  private readonly createId: (kind: IdKind) => string;
  private readonly randomAliasId: () => number;

  constructor(private readonly dependencies: MailboxServiceDependencies) {
    this.repository = dependencies.repository;
    this.mxroute = dependencies.mxroute;
    this.now = dependencies.now ?? (() => new Date());
    this.generatePrefix = dependencies.randomPrefix ?? randomPrefix;
    this.generatePassword = dependencies.randomMailboxPassword ?? randomMailboxPassword;
    this.encrypt = dependencies.encryptPassword ?? encryptPassword;
    this.createId = dependencies.createId ?? defaultId;
    this.randomAliasId = dependencies.randomAliasId ?? randomUint32;
  }

  async generateMailbox(rawToken: string): Promise<GenerateResult> {
    const requestId = this.createId("request");
    const requestedAt = this.now();
    const now = requestedAt.toISOString();

    let token: ApiTokenRecord;
    let settings: RepositorySettings;
    try {
      const digest = await tokenHmac(rawToken, this.dependencies.tokenPepper);
      const verifiedToken = await this.repository.verifyTokenDigest(digest, now);
      if (verifiedToken === null) {
        throw generationError("INVALID_TOKEN", requestId);
      }
      token = verifiedToken;
      settings = await this.repository.getSettings();
    } catch (error) {
      throw normalizeBeforeUpstream(error, requestId);
    }

    if (!settings.generationEnabled) {
      throw generationError("GENERATION_DISABLED", requestId);
    }
    if (settings.defaultDomain === null) {
      throw generationError("DEFAULT_DOMAIN_UNAVAILABLE", requestId);
    }

    const domain = settings.defaultDomain;
    for (let retry = 0; retry <= MAX_CONFLICT_RETRIES; retry += 1) {
      const localPart = this.generatePrefix(settings.prefixLength);
      const password = this.generatePassword();
      const publicId = this.createId("mailbox");
      const email = `${localPart}@${domain}`;
      let encrypted: EncryptedPassword;
      try {
        encrypted = await this.encrypt({
          password,
          key: this.dependencies.encryptionKey,
          publicId,
          email,
          keyVersion: this.dependencies.encryptionKeyVersion,
        });
      } catch {
        throw generationError("INTERNAL_ERROR", requestId);
      }

      try {
        await this.repository.reservePendingMailbox({
          tokenId: token.id,
          date: now.slice(0, 10),
          publicId,
          email,
          localPart,
          domain,
          password: encrypted,
          quotaMb: settings.mailboxQuotaMb,
          now,
        });
      } catch (error) {
        if (isReservationCollision(error) && retry < MAX_CONFLICT_RETRIES) {
          continue;
        }
        throw normalizeBeforeUpstream(error, requestId);
      }

      try {
        await this.mxroute.createMailbox(
          domain,
          localPart,
          password,
          settings.mailboxQuotaMb,
        );
      } catch (error) {
        if (isUncertainUpstreamFailure(error)) {
          throw normalizeUpstream(error, requestId);
        }

        const serviceError = asServiceError(error);
        if (serviceError !== null) {
          await this.failExplicitAttempt(publicId, serviceError.code, now, requestId);
          if (serviceError.code === "MX_CONFLICT" && retry < MAX_CONFLICT_RETRIES) {
            continue;
          }
          throw normalizeUpstream(serviceError, requestId);
        }

        throw generationError("INTERNAL_ERROR", requestId, 503, true);
      }

      try {
        await this.repository.transitionMailbox(publicId, "pending", "active", {
          updatedAt: now,
          failureCode: null,
        });
      } catch {
        throw generationError("INTERNAL_ERROR", requestId, 503, true);
      }

      try {
        await this.repository.appendAudit({
          id: this.createId("audit"),
          actorType: "api_token",
          actorId: token.id,
          action: "mailbox.create",
          email,
          result: "success",
          errorCode: null,
          requestId,
          createdAt: now,
        });
      } catch {
        throw generationError("INTERNAL_ERROR", requestId);
      }

      return {
        alias: {
          id: this.randomAliasId(),
          email,
          enabled: true,
          creation_timestamp: Math.floor(requestedAt.getTime() / 1_000),
          name: null,
          note: null,
        },
        requestId,
      };
    }

    throw generationError("MX_CONFLICT", requestId, 503, true);
  }

  private async failExplicitAttempt(
    publicId: string,
    failureCode: ServiceErrorCode,
    now: string,
    requestId: string,
  ): Promise<void> {
    try {
      await this.repository.failPendingMailbox(publicId, failureCode, now);
    } catch {
      throw generationError("INTERNAL_ERROR", requestId, 503, true);
    }
  }
}

function defaultId(kind: IdKind): string {
  return `${kind}_${crypto.randomUUID()}`;
}

function randomUint32(): number {
  return crypto.getRandomValues(new Uint32Array(1))[0]!;
}

function generationError(
  code: GenerationErrorCode,
  requestId: string,
  status = statusFor(code),
  retryable = retryableFor(code),
): GenerationError {
  return new GenerationError(code, status, retryable, requestId);
}

function statusFor(code: GenerationErrorCode): number {
  if (code === "INVALID_TOKEN") {
    return 401;
  }
  if (code === "DAILY_LIMIT" || code === "TOTAL_LIMIT") {
    return 429;
  }
  if (code === "MX_UNAUTHORIZED" || code === "MX_NOT_FOUND") {
    return 502;
  }
  if (
    code === "GENERATION_DISABLED"
    || code === "DEFAULT_DOMAIN_UNAVAILABLE"
    || code === "MX_CONFLICT"
    || code === "MX_RATE_LIMITED"
    || code === "MX_SERVER"
    || code === "MX_TIMEOUT"
    || code === "MX_INVALID_RESPONSE"
  ) {
    return 503;
  }
  return 500;
}

function retryableFor(code: GenerationErrorCode): boolean {
  return code === "MX_CONFLICT"
    || code === "MX_RATE_LIMITED"
    || code === "MX_SERVER"
    || code === "MX_TIMEOUT"
    || code === "MX_INVALID_RESPONSE";
}

function normalizeBeforeUpstream(error: unknown, requestId: string): GenerationError {
  if (error instanceof GenerationError) {
    return error;
  }
  if (error instanceof RepositoryError) {
    if (error.code === "DAILY_LIMIT" || error.code === "TOTAL_LIMIT") {
      return generationError(error.code, requestId);
    }
  }
  return generationError("INTERNAL_ERROR", requestId);
}

function normalizeUpstream(error: ServiceError, requestId: string): GenerationError {
  return generationError(error.code, requestId);
}

function asServiceError(error: unknown): ServiceError | null {
  return error instanceof ServiceError ? error : null;
}

function isUncertainUpstreamFailure(error: unknown): error is ServiceError {
  return error instanceof ServiceError
    && (
      error.code === "MX_SERVER"
      || error.code === "MX_TIMEOUT"
      || error.code === "MX_INVALID_RESPONSE"
    );
}

function isReservationCollision(error: unknown): boolean {
  return error instanceof RepositoryError
    && (error.code === "EMAIL_EXISTS" || error.code === "PUBLIC_ID_EXISTS");
}
