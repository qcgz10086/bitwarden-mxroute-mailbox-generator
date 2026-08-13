import type {
  AdminIdentity,
  GenerateResult,
  MailboxPage,
} from "../../../packages/contracts/src/index";
import {
  decryptPassword,
  encryptPassword,
  tokenHmac,
  type EncryptPasswordInput,
  type EncryptedPassword,
} from "../../../packages/security/src/crypto";
import {
  randomApiToken,
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
  type AuditPage,
  type PageAuditOptions,
  type PageMailboxesOptions,
  type SettingsPatch,
  type MailboxRecord,
} from "./repository";

const MAX_CONFLICT_RETRIES = 5;
const EXPECTED_MAILBOX_LIMIT = 9600;

export type GenerationErrorCode =
  | "INVALID_TOKEN"
  | "GENERATION_DISABLED"
  | "DEFAULT_DOMAIN_UNAVAILABLE"
  | "DAILY_LIMIT"
  | "TOTAL_LIMIT"
  | "MX_CLIENT"
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
  | "activateMailboxWithAudit"
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
        const created = await this.mxroute.createMailbox(
          domain,
          localPart,
          password,
          settings.mailboxQuotaMb,
        );
        if (
          created.username !== localPart
          || created.email !== email
          || created.quotaMb !== settings.mailboxQuotaMb
          || created.limit !== EXPECTED_MAILBOX_LIMIT
        ) {
          throw new ServiceError("MX_INVALID_RESPONSE");
        }
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
        await this.repository.activateMailboxWithAudit(publicId, now, {
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
        throw generationError("INTERNAL_ERROR", requestId, 503, true);
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

export type AdminErrorCode = ServiceErrorCode
  | "NOT_FOUND"
  | "INVALID_STATE"
  | "INVALID_SETTINGS"
  | "INVALID_INPUT"
  | "INACTIVE_DOMAIN"
  | "CONFIRMATION_MISMATCH"
  | "TOKEN_LIMIT"
  | "INTERNAL_ERROR";

export class AdminError extends Error {
  readonly name = "AdminError";

  constructor(
    readonly code: AdminErrorCode,
    readonly requestId: string,
    readonly retryable = false,
  ) {
    super(code);
  }
}

type AdminMxroute = Pick<MxrouteClient,
  "listDomains" | "getMailbox" | "updateMailbox" | "deleteMailbox"
>;
type AdminRepository = Repository;
type AdminIdKind = "request" | "audit" | "token";

export interface AdministrationServiceDependencies {
  readonly repository: AdminRepository;
  readonly mxroute: AdminMxroute;
  readonly tokenPepper: string;
  readonly encryptionKeys: Readonly<Record<number, string>>;
  readonly encryptionKeyVersion: number;
  readonly now?: () => Date;
  readonly randomMailboxPassword?: () => string;
  readonly randomApiToken?: () => string;
  readonly createId?: (kind: AdminIdKind) => string;
}

export interface AdminSettingsPatch extends SettingsPatch {}

export class AdministrationService {
  private readonly now: () => Date;
  private readonly generatePassword: () => string;
  private readonly generateToken: () => string;
  private readonly createId: (kind: AdminIdKind) => string;

  constructor(private readonly dependencies: AdministrationServiceDependencies) {
    this.now = dependencies.now ?? (() => new Date());
    this.generatePassword = dependencies.randomMailboxPassword ?? randomMailboxPassword;
    this.generateToken = dependencies.randomApiToken ?? randomApiToken;
    this.createId = dependencies.createId ?? ((kind) => `${kind}_${crypto.randomUUID()}`);
  }

  async pageMailboxes(_identity: AdminIdentity, options: PageMailboxesOptions = {}): Promise<MailboxPage> {
    try { return await this.dependencies.repository.pageMailboxes(options); }
    catch (error) { throw new AdminError(repositoryAdminCode(error), this.createId("request")); }
  }

  async pageAudit(_identity: AdminIdentity, options: PageAuditOptions = {}): Promise<AuditPage> {
    try { return await this.dependencies.repository.pageAudit(options); }
    catch (error) { throw new AdminError(repositoryAdminCode(error), this.createId("request")); }
  }

  async revealPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }> {
    const requestId = this.createId("request");
    try {
      const mailbox = await this.dependencies.repository.authorizePasswordRevealWithAudit(
        publicId, this.adminEvent(identity,"mailbox.reveal",null,"success",null,requestId),
      );
      const password = await this.decrypt(mailbox, mailbox.status === "reset_unknown", requestId);
      return { password, requestId };
    } catch (error) {
      const code = error instanceof RepositoryError && error.code === "INVALID_STATE" ? "INVALID_STATE" : "INTERNAL_ERROR";
      await this.audit(identity, "mailbox.reveal", null, "failure", code, requestId);
      throw new AdminError(code, requestId);
    }
  }

  async resetPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }> {
    const requestId = this.createId("request");
    const now = this.now().toISOString();
    const mailbox = await this.requireMailbox(publicId, requestId, identity, "mailbox.reset");
    if (mailbox.status !== "active") {
      await this.audit(identity, "mailbox.reset", mailbox.email, "failure", "INVALID_STATE", requestId);
      throw new AdminError("INVALID_STATE", requestId);
    }
    let password: string;
    try {
      password = this.generatePassword();
      const key = this.dependencies.encryptionKeys[this.dependencies.encryptionKeyVersion];
      if (key === undefined) throw new Error("missing encryption key");
      const encrypted = await encryptPassword({
        password, key, publicId: mailbox.publicId, email: mailbox.email,
        keyVersion: this.dependencies.encryptionKeyVersion,
      });
      await this.dependencies.repository.saveNextPassword(publicId, {
        ciphertext: encrypted.ciphertext, nonce: encrypted.nonce,
        keyVersion: encrypted.keyVersion, updatedAt: now,
      });
    } catch (error) {
      const code = repositoryAdminCode(error);
      await this.audit(identity, "mailbox.reset", mailbox.email, "failure", code, requestId);
      throw new AdminError(code, requestId);
    }
    try {
      await this.dependencies.mxroute.updateMailbox(mailbox.domain, mailbox.localPart, { password });
      try {
        await this.dependencies.repository.completePasswordResetWithAudit(publicId, now, {
          id: this.createId("audit"), actorType: "admin", actorId: identity.subject,
          actorEmail: identity.email, action: "mailbox.reset", email: mailbox.email,
          result: "success", errorCode: null, requestId, createdAt: now,
        });
      } catch {
        await this.dependencies.repository.markResetUnknownWithAudit(publicId,"INTERNAL_ERROR",now,
          this.adminEvent(identity,"mailbox.reset",mailbox.email,"failure","INTERNAL_ERROR",requestId));
        throw new AdminError("INTERNAL_ERROR", requestId, true);
      }
      return { password, requestId };
    } catch (error) {
      if (error instanceof AdminError) throw error;
      const code = serviceCode(error);
      if (code === null) {
        await this.audit(identity,"mailbox.reset",mailbox.email,"failure","INTERNAL_ERROR",requestId);
        throw new AdminError("INTERNAL_ERROR", requestId, true);
      }
      if (isAmbiguous(code)) {
        await this.dependencies.repository.markResetUnknownWithAudit(publicId,code,now,
          this.adminEvent(identity,"mailbox.reset",mailbox.email,"failure",code,requestId));
      } else {
        await this.dependencies.repository.rollbackPasswordResetWithAudit(publicId,code,now,
          this.adminEvent(identity,"mailbox.reset",mailbox.email,"failure",code,requestId));
      }
      throw new AdminError(code, requestId, isAmbiguous(code));
    }
  }

  async deleteMailbox(
    identity: AdminIdentity,
    publicId: string,
    confirmationEmail: string,
  ): Promise<{ requestId: string }> {
    const requestId = this.createId("request");
    const now = this.now().toISOString();
    const mailbox = await this.requireMailbox(publicId, requestId, identity, "mailbox.delete");
    if (confirmationEmail !== mailbox.email) {
      await this.audit(identity, "mailbox.delete", mailbox.email, "failure", "CONFIRMATION_MISMATCH", requestId);
      throw new AdminError("CONFIRMATION_MISMATCH", requestId);
    }
    if (!["active", "failed", "delete_failed", "reset_unknown"].includes(mailbox.status)) {
      await this.audit(identity, "mailbox.delete", mailbox.email, "failure", "INVALID_STATE", requestId);
      throw new AdminError("INVALID_STATE", requestId);
    }
    try {
      await this.dependencies.repository.transitionMailbox(publicId, mailbox.status, "deleting", {
        updatedAt: now, failureCode: null,
      });
    } catch {
      await this.audit(identity, "mailbox.delete", mailbox.email, "failure", "INVALID_STATE", requestId);
      throw new AdminError("INVALID_STATE", requestId);
    }
    try {
      await this.dependencies.mxroute.deleteMailbox(mailbox.domain, mailbox.localPart);
      await this.removeDeleted(identity, mailbox, requestId, now);
      return { requestId };
    } catch (error) {
      const code = serviceCode(error);
      if (code === "MX_NOT_FOUND") {
        await this.removeDeleted(identity, mailbox, requestId, now);
        return { requestId };
      }
      if (code !== null && isAmbiguous(code)) {
        const existence = await this.checkExistence(mailbox);
        if (existence === false) {
          await this.removeDeleted(identity, mailbox, requestId, now);
          return { requestId };
        }
        if (existence === true) {
          await this.dependencies.repository.markDeleteFailedWithAudit(publicId,code,now,
            this.adminEvent(identity,"mailbox.delete",mailbox.email,"failure",code,requestId));
        } else {
          await this.dependencies.repository.recordRecoveryAttempt(publicId, "deleting", now);
        }
      } else if (code !== null) {
        await this.dependencies.repository.markDeleteFailedWithAudit(publicId,code,now,
          this.adminEvent(identity,"mailbox.delete",mailbox.email,"failure",code,requestId));
      }
      const normalized = code ?? "INTERNAL_ERROR";
      if (code === null || (code !== null && isAmbiguous(code) && await this.dependencies.repository.findMailbox(publicId).then(r => r?.status === "deleting"))) {
        await this.audit(identity, "mailbox.delete", mailbox.email, "failure", normalized, requestId);
      }
      throw new AdminError(normalized, requestId, code !== null && isAmbiguous(code));
    }
  }

  async syncDomains(identity: AdminIdentity): Promise<readonly import("./repository").DomainRecord[]> {
    const requestId = this.createId("request");
    const now = this.now().toISOString();
    try {
      const domains = await this.dependencies.mxroute.listDomains();
      await this.dependencies.repository.syncDomainsWithAudit(domains,now,
        this.adminEvent(identity,"domains.sync",null,"success",null,requestId));
      return this.dependencies.repository.listDomains();
    } catch (error) {
      const code = serviceCode(error) ?? "INTERNAL_ERROR";
      await this.audit(identity, "domains.sync", null, "failure", code, requestId);
      throw new AdminError(code, requestId, code !== "INTERNAL_ERROR" && isAmbiguous(code));
    }
  }

  async setDefaultDomain(identity: AdminIdentity, domain: string): Promise<{ requestId: string }> {
    return this.adminMutation(identity, "domains.default", domain, async (event) => {
      await this.dependencies.repository.setDefaultDomainWithAudit(domain,event);
    });
  }

  async updateSettings(identity: AdminIdentity, patch: AdminSettingsPatch): Promise<{ requestId: string }> {
    return this.adminMutation(identity, "settings.update", null, async (event) => {
      validateSettings(patch);
      await this.dependencies.repository.updateSettingsWithAudit(patch,event);
    });
  }

  async createApiToken(identity: AdminIdentity, name: string): Promise<{ id: string; rawToken: string; requestId: string }> {
    const requestId = this.createId("request");
    if (await this.dependencies.repository.countActiveTokens() >= 2) {
      await this.audit(identity, "token.create", null, "failure", "TOKEN_LIMIT", requestId);
      throw new AdminError("TOKEN_LIMIT", requestId);
    }
    const rawToken = this.generateToken();
    const id = this.createId("token");
    const now = this.now().toISOString();
    try {
      await this.dependencies.repository.createTokenDigestWithAudit({
        id, name: name.trim(), digest: await tokenHmac(rawToken, this.dependencies.tokenPepper), createdAt: now,
      }, this.adminEvent(identity,"token.create",null,"success",null,requestId));
      return { id, rawToken, requestId };
    } catch (error) {
      const code = error instanceof RepositoryError && error.code === "TOKEN_LIMIT"
        ? "TOKEN_LIMIT"
        : "INTERNAL_ERROR";
      await this.audit(identity, "token.create", null, "failure", code, requestId);
      throw new AdminError(code, requestId);
    }
  }

  revokeApiToken(identity: AdminIdentity, id: string): Promise<{ requestId: string }> {
    return this.adminMutation(identity, "token.revoke", null, async (event) => {
      await this.dependencies.repository.revokeTokenWithAudit(id,this.now().toISOString(),event);
    });
  }

  async reconcilePending(): Promise<number> {
    return this.reconcile(["pending"]);
  }

  async reconcileResetUnknown(): Promise<number> {
    return this.reconcile(["reset_unknown", "resetting"]);
  }

  async reconcileDeleting(): Promise<number> {
    return this.reconcile(["deleting"]);
  }

  async reconcileAll(): Promise<number> {
    return this.reconcile(["pending", "reset_unknown", "resetting", "deleting"]);
  }

  private async reconcile(statuses: readonly ("pending" | "reset_unknown" | "resetting" | "deleting")[]): Promise<number> {
    const nowDate = this.now();
    const now = nowDate.toISOString();
    const staleBefore = new Date(nowDate.getTime() - 5 * 60_000).toISOString();
    const rows = await this.dependencies.repository.listRecoveryCandidates(statuses, staleBefore, now, 25);
    for (const mailbox of rows) {
      try {
        if (mailbox.status === "pending") {
          const existence = await this.checkExistence(mailbox);
          if (existence === true) {
            await this.dependencies.repository.activateMailboxWithAudit(mailbox.publicId, now, this.systemAudit("mailbox.create.reconcile", mailbox.email, "success", null, now));
          } else if (existence === false) {
            await this.dependencies.repository.failPendingMailboxWithAudit(mailbox.publicId,"MX_NOT_FOUND",now,
              this.systemAudit("mailbox.create.reconcile",mailbox.email,"failure","MX_NOT_FOUND",now));
          } else {
            await this.dependencies.repository.recordRecoveryAttempt(mailbox.publicId, "pending", now);
          }
        } else if (mailbox.status === "reset_unknown" || mailbox.status === "resetting") {
          const password = await this.decrypt(mailbox, true, this.createId("request"));
          await this.dependencies.mxroute.updateMailbox(mailbox.domain, mailbox.localPart, { password });
          await this.dependencies.repository.completePasswordResetWithAudit(
            mailbox.publicId,
            now,
            this.systemAudit("mailbox.reset.reconcile", mailbox.email, "success", null, now),
          );
        } else {
          const existence = await this.checkExistence(mailbox);
          if (existence === false) {
            await this.dependencies.repository.removeMailboxWithAudit(mailbox.publicId, this.systemAudit("mailbox.delete.reconcile", mailbox.email, "success", null, now));
          } else if (existence === true) {
            await this.dependencies.repository.markDeleteFailedWithAudit(mailbox.publicId,"MX_TIMEOUT",now,
              this.systemAudit("mailbox.delete.reconcile",mailbox.email,"failure","MX_TIMEOUT",now));
          } else {
            await this.dependencies.repository.recordRecoveryAttempt(mailbox.publicId, "deleting", now);
          }
        }
      } catch {
        const current = await this.dependencies.repository.findMailbox(mailbox.publicId);
        if (current !== null && current.status === mailbox.status) {
          await this.dependencies.repository.recordRecoveryAttempt(mailbox.publicId, mailbox.status, now).catch(() => undefined);
        }
      }
    }
    return rows.length;
  }

  private async checkExistence(mailbox: MailboxRecord): Promise<boolean | null> {
    try {
      await this.dependencies.mxroute.getMailbox(mailbox.domain, mailbox.localPart);
      return true;
    } catch (error) {
      return serviceCode(error) === "MX_NOT_FOUND" ? false : null;
    }
  }

  private async removeDeleted(identity: AdminIdentity, mailbox: MailboxRecord, requestId: string, now: string): Promise<void> {
    await this.dependencies.repository.removeMailboxWithAudit(mailbox.publicId, {
      id: this.createId("audit"), actorType: "admin", actorId: identity.subject,
      actorEmail: identity.email, action: "mailbox.delete", email: mailbox.email,
      result: "success", errorCode: null, requestId, createdAt: now,
    });
  }

  private async requireMailbox(
    publicId: string,
    requestId: string,
    identity: AdminIdentity,
    action: string,
  ): Promise<MailboxRecord> {
    const mailbox = await this.dependencies.repository.findMailbox(publicId);
    if (mailbox === null) {
      await this.audit(identity, action, null, "failure", "NOT_FOUND", requestId);
      throw new AdminError("NOT_FOUND", requestId);
    }
    return mailbox;
  }

  private async decrypt(mailbox: MailboxRecord, next: boolean, requestId: string): Promise<string> {
    const keyVersion = next ? mailbox.nextPasswordKeyVersion : mailbox.encryptionKeyVersion;
    const key = keyVersion === null ? undefined : this.dependencies.encryptionKeys[keyVersion];
    const ciphertext = next ? mailbox.nextPasswordCiphertext : mailbox.passwordCiphertext;
    const nonce = next ? mailbox.nextPasswordNonce : mailbox.passwordNonce;
    if (keyVersion === null || key === undefined || ciphertext === null || nonce === null) {
      throw new AdminError("INTERNAL_ERROR", requestId);
    }
    try {
      return await decryptPassword({
        encrypted: { ciphertext, nonce, keyVersion },
        key, publicId: mailbox.publicId, email: mailbox.email,
      });
    } catch {
      throw new AdminError("INTERNAL_ERROR", requestId);
    }
  }

  private async adminMutation(
    identity: AdminIdentity,
    action: string,
    email: string | null,
    mutation: (event: import("./repository").AuditEventInput) => Promise<void>,
  ): Promise<{ requestId: string }> {
    const requestId = this.createId("request");
    try {
      await mutation(this.adminEvent(identity,action,email,"success",null,requestId));
      return { requestId };
    } catch (error) {
      const code = repositoryAdminCode(error);
      await this.audit(identity, action, email, "failure", code, requestId);
      throw new AdminError(code, requestId);
    }
  }

  private adminEvent(identity: AdminIdentity, action: string, email: string | null, result: string, errorCode: string | null, requestId: string): import("./repository").AuditEventInput {
    return { id:this.createId("audit"),actorType:"admin",actorId:identity.subject,actorEmail:identity.email,
      action,email,result,errorCode,requestId,createdAt:this.now().toISOString() };
  }

  private audit(identity: AdminIdentity, action: string, email: string | null, result: string, errorCode: string | null, requestId: string): Promise<void> {
    return this.dependencies.repository.appendAudit({
      id: this.createId("audit"), actorType: "admin", actorId: identity.subject,
      actorEmail: identity.email, action, email, result, errorCode, requestId,
      createdAt: this.now().toISOString(),
    });
  }

  private systemAudit(action: string, email: string, result: string, errorCode: string | null, now: string): import("./repository").AuditEventInput {
    return {
      id: this.createId("audit"), actorType: "system", actorId: "scheduled",
      actorEmail: null, action, email, result, errorCode,
      requestId: this.createId("request"), createdAt: now,
    };
  }
}

function validateSettings(patch: AdminSettingsPatch): void {
  const integerInRange = (value: number | undefined, minimum: number, maximum: number): boolean =>
    value === undefined || (Number.isInteger(value) && value >= minimum && value <= maximum);
  if (
    !integerInRange(patch.mailboxQuotaMb, 1, 102_400)
    || !integerInRange(patch.prefixLength, 12, 12)
    || !integerInRange(patch.dailyCreationLimit, 1, 1_000)
    || !integerInRange(patch.totalManagedLimit, 1, 100_000)
    || (patch.generationEnabled !== undefined && typeof patch.generationEnabled !== "boolean")
  ) {
    throw new RepositoryError("INVALID_SETTINGS");
  }
}

function repositoryAdminCode(error: unknown): AdminErrorCode {
  if (error instanceof RepositoryError) {
    if (error.code === "INACTIVE_DOMAIN" || error.code === "INVALID_SETTINGS" || error.code === "INVALID_STATE" || error.code === "INVALID_INPUT") {
      return error.code;
    }
  }
  return "INTERNAL_ERROR";
}

function serviceCode(error: unknown): ServiceErrorCode | null {
  return error instanceof ServiceError ? error.code : null;
}

function isAmbiguous(code: ServiceErrorCode): boolean {
  return code === "MX_TIMEOUT" || code === "MX_SERVER" || code === "MX_INVALID_RESPONSE";
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
  if (code === "MX_CLIENT" || code === "MX_UNAUTHORIZED" || code === "MX_NOT_FOUND") {
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
