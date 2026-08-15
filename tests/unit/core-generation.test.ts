import {
  applyD1Migrations,
  env,
  type D1Migration,
} from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import { decryptPassword, tokenHmac } from "../../packages/security/src/crypto";
import { ServiceError, type ServiceErrorCode } from "../../workers/core/src/errors";
import type { MxrouteMailbox } from "../../workers/core/src/mxroute";
import { Repository } from "../../workers/core/src/repository";
import {
  GenerationError,
  MailboxService,
  type MailboxServiceDependencies,
} from "../../workers/core/src/service";

const NOW = "2026-08-13T10:00:00.000Z";
const DOMAIN = "example.test";
const TOKEN = "valid-raw-api-token";
const TOKEN_ID = "token-primary";
const TOKEN_PEPPER = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const ENCRYPTION_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PASSWORD = "Aa2!bbbbbbbbbbbbbb";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };

interface CreateRequest {
  readonly domain: string;
  readonly user: string;
  readonly password: string;
  readonly quotaMb: number;
}

type FakeOutcome = ServiceErrorCode | "MX_CLIENT" | "success" | MxrouteMailbox;

class FakeMxroute {
  readonly requests: CreateRequest[] = [];
  private readonly outcomes: FakeOutcome[];

  constructor(...outcomes: FakeOutcome[]) {
    this.outcomes = [...outcomes];
  }

  async createMailbox(
    domain: string,
    user: string,
    password: string,
    quotaMb: number,
  ): Promise<MxrouteMailbox> {
    this.requests.push({ domain, user, password, quotaMb });
    const outcome = this.outcomes.shift() ?? "success";
    if (typeof outcome === "object") {
      return outcome;
    }
    if (outcome !== "success") {
      throw new ServiceError(outcome as ServiceErrorCode);
    }
    return { username: user, email: `${user}@${domain}`, quotaMb, limit: 9600 };
  }
}

beforeAll(async () => {
  await applyD1Migrations(env.DB, (env as TestEnv).TEST_MIGRATIONS);
});

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM mailboxes"),
    env.DB.prepare("DELETE FROM creation_counters"),
    env.DB.prepare("DELETE FROM api_tokens"),
    env.DB.prepare("DELETE FROM audit_events"),
    env.DB.prepare("DELETE FROM domains"),
    env.DB.prepare("DELETE FROM settings WHERE key = ?").bind("default_domain"),
    env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind("100", "mailbox_quota_mb"),
    env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind("12", "prefix_length"),
    env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind("30", "daily_creation_limit"),
    env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind("500", "total_managed_limit"),
    env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind("true", "generation_enabled"),
  ]);
});

async function prepareActiveConfiguration(repository: Repository, token = TOKEN): Promise<void> {
  await repository.syncDomains([DOMAIN], NOW);
  await repository.setDefaultDomain(DOMAIN);
  await repository.createTokenDigest({
    id: TOKEN_ID,
    name: "Primary",
    digest: await tokenHmac(token, TOKEN_PEPPER),
    createdAt: NOW,
  });
}

function serviceWith(
  repository: Repository,
  mxroute: FakeMxroute,
  prefixes: readonly string[] = ["23456789abcd"],
  overrides: Partial<MailboxServiceDependencies> = {},
): MailboxService {
  const candidates = [...prefixes];
  let mailboxNumber = 0;
  return new MailboxService({
    repository,
    mxroute,
    tokenPepper: TOKEN_PEPPER,
    encryptionKey: ENCRYPTION_KEY,
    encryptionKeyVersion: 1,
    now: () => new Date(NOW),
    randomPrefix: () => candidates.shift() ?? "zzzzzzzzzzzz",
    randomMailboxPassword: () => PASSWORD,
    createId: (kind) => kind === "request"
      ? "request-01"
      : kind === "audit"
        ? "audit-01"
        : `mailbox-${++mailboxNumber}`,
    randomAliasId: () => 123,
    ...overrides,
  });
}

async function generationError(promise: Promise<unknown>): Promise<GenerationError> {
  const error = await promise.catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(GenerationError);
  return error as GenerationError;
}

describe("MailboxService.generateMailbox", () => {
  it("rejects an invalid token before settings, credential generation, persistence, or MXroute", async () => {
    const repository = new Repository(env.DB);
    const mxroute = new FakeMxroute();
    let generated = false;
    const service = serviceWith(repository, mxroute, undefined, {
      randomPrefix: () => {
        generated = true;
        return "23456789abcd";
      },
    });

    const error = await generationError(service.generateMailbox("invalid-token"));

    expect(error).toMatchObject({
      code: "INVALID_TOKEN",
      status: 401,
      retryable: false,
      requestId: "request-01",
      message: "INVALID_TOKEN",
    });
    expect(generated).toBe(false);
    expect(mxroute.requests).toEqual([]);
    expect((await repository.pageMailboxes()).items).toEqual([]);
  });

  it("rejects a revoked token before credential generation or MXroute", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    await env.DB.prepare("UPDATE api_tokens SET revoked_at = ? WHERE id = ?")
      .bind(NOW, TOKEN_ID).run();
    const mxroute = new FakeMxroute();
    let generated = false;
    const service = serviceWith(repository, mxroute, undefined, {
      randomPrefix: () => {
        generated = true;
        return "23456789abcd";
      },
    });

    await expect(service.generateMailbox(TOKEN)).rejects.toMatchObject({
      code: "INVALID_TOKEN",
      status: 401,
      retryable: false,
    });
    expect(generated).toBe(false);
    expect(mxroute.requests).toEqual([]);
  });

  it("rejects disabled generation before creating credentials or calling MXroute", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    await env.DB.prepare("UPDATE settings SET value = 'false' WHERE key = 'generation_enabled'").run();
    const mxroute = new FakeMxroute();
    let generated = false;
    const service = serviceWith(repository, mxroute, undefined, {
      randomPrefix: () => {
        generated = true;
        return "23456789abcd";
      },
    });

    await expect(service.generateMailbox(TOKEN)).rejects.toMatchObject({
      code: "GENERATION_DISABLED",
      status: 503,
      retryable: false,
    });
    expect(generated).toBe(false);
    expect(mxroute.requests).toEqual([]);
  });

  it("rejects a missing or inactive default domain before credential generation", async () => {
    const repository = new Repository(env.DB);
    await repository.createTokenDigest({
      id: TOKEN_ID,
      name: "Primary",
      digest: await tokenHmac(TOKEN, TOKEN_PEPPER),
      createdAt: NOW,
    });
    const mxroute = new FakeMxroute();
    let generated = false;
    const service = serviceWith(repository, mxroute, undefined, {
      randomPrefix: () => {
        generated = true;
        return "23456789abcd";
      },
    });

    await expect(service.generateMailbox(TOKEN)).rejects.toMatchObject({
      code: "DEFAULT_DOMAIN_UNAVAILABLE",
      status: 503,
      retryable: false,
    });
    expect(generated).toBe(false);
    expect(mxroute.requests).toEqual([]);
  });

  it("rejects a configured default after domain sync makes it inactive", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    await repository.syncDomains(["replacement.test"], NOW);
    const mxroute = new FakeMxroute();

    await expect(serviceWith(repository, mxroute).generateMailbox(TOKEN)).rejects.toMatchObject({
      code: "DEFAULT_DOMAIN_UNAVAILABLE",
      status: 503,
      retryable: false,
    });
    expect(mxroute.requests).toEqual([]);
    expect((await repository.pageMailboxes()).items).toEqual([]);
  });

  it("registers a mailbox without creating credentials or calling MXroute, and returns only alias fields", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute();
    const service = serviceWith(repository, mxroute);

    const result = await service.generateMailbox(TOKEN);

    expect(result).toEqual({
      alias: {
        id: 123,
        email: `23456789abcd@${DOMAIN}`,
        enabled: true,
        creation_timestamp: 1_786_615_200,
        name: null,
        note: null,
      },
      requestId: "request-01",
    });
    expect(mxroute.requests).toEqual([]);
    const mailbox = await repository.findMailbox("mailbox-1");
    expect(mailbox).toMatchObject({
      email: `23456789abcd@${DOMAIN}`,
      quotaMb: 100,
      status: "registered",
      reservationDate: "2026-08-13",
      reservationTokenId: TOKEN_ID,
      failureCode: null,
      encryptionKeyVersion: null,
    });
    expect(mailbox?.passwordCiphertext).toBeNull();
    expect(mailbox?.passwordNonce).toBeNull();
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it("retries a new prefix when the generated email already exists", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const prefixes = ["23456789abc2", "23456789abc3"];
    const mxroute = new FakeMxroute();
    await env.DB.prepare(`INSERT INTO mailboxes(
        public_id, email, local_part, domain, quota_mb, status, created_at, updated_at
      ) VALUES(?, ?, ?, ?, 100, 'registered', ?, ?)`)
      .bind("existing", `23456789abc2@${DOMAIN}`, "23456789abc2", DOMAIN, NOW, NOW).run();

    const result = await serviceWith(repository, mxroute, prefixes).generateMailbox(TOKEN);

    expect(result.alias.email).toBe(`23456789abc3@${DOMAIN}`);
    expect(mxroute.requests).toEqual([]);
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it("does not call MXroute when D1 rejects the registration", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute();
    const failingRepository = new Proxy(repository, {
      get(target, property, receiver) {
        if (property === "registerMailbox") {
          return async () => {
            throw new Error("injected D1 write failure");
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    await expect(serviceWith(failingRepository, mxroute).generateMailbox(TOKEN)).rejects.toMatchObject({
      code: "INTERNAL_ERROR",
      status: 500,
      retryable: false,
    });
    expect(mxroute.requests).toEqual([]);
  });
});
