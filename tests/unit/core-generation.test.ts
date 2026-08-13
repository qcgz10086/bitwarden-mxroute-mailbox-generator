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

  it("creates an encrypted 100 MB mailbox, activates it, audits it, and returns only alias fields", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute("success");
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
    expect(mxroute.requests).toEqual([{
      domain: DOMAIN,
      user: "23456789abcd",
      password: PASSWORD,
      quotaMb: 100,
    }]);
    const mailbox = await repository.findMailbox("mailbox-1");
    expect(mailbox).toMatchObject({
      email: `23456789abcd@${DOMAIN}`,
      quotaMb: 100,
      status: "active",
      failureCode: null,
      encryptionKeyVersion: 1,
    });
    expect(new TextDecoder().decode(mailbox!.passwordCiphertext)).not.toContain(PASSWORD);
    await expect(decryptPassword({
      encrypted: {
        ciphertext: mailbox!.passwordCiphertext,
        nonce: mailbox!.passwordNonce,
        keyVersion: mailbox!.encryptionKeyVersion,
      },
      key: ENCRYPTION_KEY,
      publicId: mailbox!.publicId,
      email: mailbox!.email,
    })).resolves.toBe(PASSWORD);
    const audit = await env.DB.prepare("SELECT * FROM audit_events").first<Record<string, unknown>>();
    expect(audit).toEqual({
      id: "audit-01",
      actor_type: "api_token",
      actor_id: TOKEN_ID,
      actor_email: null,
      action: "mailbox.create",
      email: `23456789abcd@${DOMAIN}`,
      result: "success",
      error_code: null,
      request_id: "request-01",
      created_at: NOW,
    });
  });

  it("fails and releases every conflicted row while retrying five new prefixes", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const prefixes = [
      "23456789abc2",
      "23456789abc3",
      "23456789abc4",
      "23456789abc5",
      "23456789abc6",
      "23456789abc7",
    ];
    const mxroute = new FakeMxroute(
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "success",
    );

    const result = await serviceWith(repository, mxroute, prefixes).generateMailbox(TOKEN);

    expect(result.alias.email).toBe(`23456789abc7@${DOMAIN}`);
    expect(mxroute.requests.map((request) => request.user)).toEqual(prefixes);
    const rows = await env.DB.prepare(`SELECT email, status, failure_code
      FROM mailboxes ORDER BY id`).all<Record<string, unknown>>();
    expect(rows.results).toEqual([
      ...prefixes.slice(0, 5).map((prefix) => ({
        email: `${prefix}@${DOMAIN}`,
        status: "failed",
        failure_code: "MX_CONFLICT",
      })),
      { email: `${prefixes[5]}@${DOMAIN}`, status: "active", failure_code: null },
    ]);
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it("stops after the initial conflict and five new-prefix conflicts", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const prefixes = [
      "23456789abc2",
      "23456789abc3",
      "23456789abc4",
      "23456789abc5",
      "23456789abc6",
      "23456789abc7",
      "23456789abc8",
    ];
    const mxroute = new FakeMxroute(
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "MX_CONFLICT",
      "success",
    );

    await expect(serviceWith(repository, mxroute, prefixes).generateMailbox(TOKEN))
      .rejects.toMatchObject({ code: "MX_CONFLICT", status: 503, retryable: true });
    expect(mxroute.requests.map((request) => request.user)).toEqual(prefixes.slice(0, 6));
    const rows = await env.DB.prepare("SELECT status, failure_code FROM mailboxes ORDER BY id")
      .all<Record<string, unknown>>();
    expect(rows.results).toEqual(Array.from({ length: 6 }, () => ({
      status: "failed",
      failure_code: "MX_CONFLICT",
    })));
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(0);
  });

  it.each([
    ["daily_creation_limit", "0", "DAILY_LIMIT"],
    ["total_managed_limit", "0", "TOTAL_LIMIT"],
  ] as const)("returns quota semantics for %s without calling MXroute", async (setting, value, code) => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    await env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?").bind(value, setting).run();
    const mxroute = new FakeMxroute();

    await expect(serviceWith(repository, mxroute).generateMailbox(TOKEN)).rejects.toMatchObject({
      code,
      status: 429,
      retryable: false,
    });
    expect(mxroute.requests).toEqual([]);
    expect((await repository.pageMailboxes()).items).toEqual([]);
  });

  it.each([
    ["MX_RATE_LIMITED", 503, true],
    ["MX_UNAUTHORIZED", 502, false],
    ["MX_NOT_FOUND", 502, false],
  ] as const)("fails and releases pending state for explicit %s", async (code, status, retryable) => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute(code);

    await expect(serviceWith(repository, mxroute).generateMailbox(TOKEN)).rejects.toMatchObject({
      code,
      status,
      retryable,
    });
    expect(await repository.findMailbox("mailbox-1")).toMatchObject({
      status: "failed",
      failureCode: code,
    });
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(0);
  });

  it.each([400, 403, 422])(
    "fails and releases pending state for explicit HTTP %i client failure",
    async () => {
      const repository = new Repository(env.DB);
      await prepareActiveConfiguration(repository);
      const mxroute = new FakeMxroute("MX_CLIENT");

      await expect(serviceWith(repository, mxroute).generateMailbox(TOKEN)).rejects.toMatchObject({
        code: "MX_CLIENT",
        status: 502,
        retryable: false,
      });
      expect(await repository.findMailbox("mailbox-1")).toMatchObject({
        status: "failed",
        failureCode: "MX_CLIENT",
      });
      const counter = await env.DB.prepare(
        "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
      ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
      expect(counter?.count).toBe(0);
    },
  );

  it.each([
    ["username", { username: "different", email: `23456789abcd@${DOMAIN}`, quotaMb: 100, limit: 9600 }],
    ["email", { username: "23456789abcd", email: `different@${DOMAIN}`, quotaMb: 100, limit: 9600 }],
    ["quota", { username: "23456789abcd", email: `23456789abcd@${DOMAIN}`, quotaMb: 250, limit: 9600 }],
    ["limit", { username: "23456789abcd", email: `23456789abcd@${DOMAIN}`, quotaMb: 100, limit: 4800 }],
  ] as const)("retains pending state when the create response mismatches %s", async (_field, response) => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute(response);

    await expect(serviceWith(repository, mxroute).generateMailbox(TOKEN)).rejects.toMatchObject({
      code: "MX_INVALID_RESPONSE",
      status: 503,
      retryable: true,
    });
    expect(await repository.findMailbox("mailbox-1")).toMatchObject({
      status: "pending",
      failureCode: null,
    });
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it.each([
    "MX_SERVER",
    "MX_TIMEOUT",
    "MX_INVALID_RESPONSE",
  ] as const)("retains encrypted pending state for uncertain %s", async (code) => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute(code);

    const error = await generationError(serviceWith(repository, mxroute).generateMailbox(TOKEN));

    expect(error).toMatchObject({ code, status: 503, retryable: true, requestId: "request-01" });
    const mailbox = await repository.findMailbox("mailbox-1");
    expect(mailbox).toMatchObject({ status: "pending", failureCode: null });
    await expect(decryptPassword({
      encrypted: {
        ciphertext: mailbox!.passwordCiphertext,
        nonce: mailbox!.passwordNonce,
        keyVersion: mailbox!.encryptionKeyVersion,
      },
      key: ENCRYPTION_KEY,
      publicId: mailbox!.publicId,
      email: mailbox!.email,
    })).resolves.toBe(PASSWORD);
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it("does not call MXroute when D1 rejects the pending reservation", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute();
    const failingRepository = new Proxy(repository, {
      get(target, property, receiver) {
        if (property === "reservePendingMailbox") {
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

  it("retains pending state when D1 cannot record activation after upstream success", async () => {
    const repository = new Repository(env.DB);
    await prepareActiveConfiguration(repository);
    const mxroute = new FakeMxroute("success");
    const failingRepository = new Proxy(repository, {
      get(target, property, receiver) {
        if (property === "activateMailboxWithAudit") {
          return async () => {
            throw new Error("injected D1 transition failure");
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    await expect(serviceWith(failingRepository, mxroute).generateMailbox(TOKEN))
      .rejects.toMatchObject({ code: "INTERNAL_ERROR", status: 503, retryable: true });
    expect(await repository.findMailbox("mailbox-1")).toMatchObject({
      status: "pending",
      failureCode: null,
    });
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind("2026-08-13", TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });
});
