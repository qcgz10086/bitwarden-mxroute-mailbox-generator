import {
  applyD1Migrations,
  env,
  type D1Migration,
} from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import {
  Repository,
  type ReservePendingMailboxInput,
} from "../../workers/core/src/repository";

const NOW = "2026-08-13T10:00:00.000Z";
const LATER = "2026-08-13T10:01:00.000Z";
const DATE = "2026-08-13";
const DOMAIN = "example.test";
const TOKEN_ID = "token-primary";
const DIGEST = new Uint8Array([3, 1, 4, 1, 5, 9]);
const CIPHERTEXT = new Uint8Array([10, 20, 30, 40]);
const NONCE = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };

beforeAll(async () => {
  await applyD1Migrations(env.DB, (env as TestEnv).TEST_MIGRATIONS);
});

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM creation_counters"),
    env.DB.prepare("DELETE FROM mailboxes"),
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

function mailboxInput(overrides: Partial<ReservePendingMailboxInput> = {}): ReservePendingMailboxInput {
  return {
    tokenId: TOKEN_ID,
    date: DATE,
    publicId: "mbx_01",
    email: `alpha@${DOMAIN}`,
    localPart: "alpha",
    domain: DOMAIN,
    password: {
      ciphertext: CIPHERTEXT,
      nonce: NONCE,
      keyVersion: 1,
    },
    quotaMb: 100,
    now: NOW,
    ...overrides,
  };
}

async function prepareReservation(repository: Repository): Promise<void> {
  await repository.syncDomains([DOMAIN], NOW);
  await repository.createTokenDigest({
    id: TOKEN_ID,
    name: "Primary",
    digest: DIGEST,
    createdAt: NOW,
  });
}

describe("D1 repository", () => {
  it("loads the seeded defaults without inventing a default domain", async () => {
    const settings = await new Repository(env.DB).getSettings();

    expect(settings).toEqual({
      defaultDomain: null,
      mailboxQuotaMb: 100,
      prefixLength: 12,
      dailyCreationLimit: 30,
      totalManagedLimit: 500,
      generationEnabled: true,
    });
  });

  it("atomically reserves a daily count and encrypted pending mailbox", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);

    await repository.reservePendingMailbox(mailboxInput());

    const mailbox = await repository.findMailbox("mbx_01");
    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind(DATE, TOKEN_ID).first<{ count: number }>();
    expect(mailbox).toMatchObject({
      publicId: "mbx_01",
      email: `alpha@${DOMAIN}`,
      status: "pending",
      quotaMb: 100,
      encryptionKeyVersion: 1,
    });
    expect(Array.from(mailbox!.passwordCiphertext)).toEqual([10, 20, 30, 40]);
    expect(Array.from(mailbox!.passwordNonce)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    expect(counter?.count).toBe(1);
  });

  it("rolls back the counter when unique email enforcement rejects the mailbox", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await repository.reservePendingMailbox(mailboxInput());

    await expect(repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_02",
      localPart: "different",
    }))).rejects.toMatchObject({ code: "EMAIL_EXISTS" });

    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind(DATE, TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it("rolls back a rejected daily-limit reservation", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?")
      .bind("1", "daily_creation_limit").run();
    await repository.reservePendingMailbox(mailboxInput());

    await expect(repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_02",
      email: `beta@${DOMAIN}`,
      localPart: "beta",
    }))).rejects.toMatchObject({ code: "DAILY_LIMIT" });

    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind(DATE, TOKEN_ID).first<{ count: number }>();
    const mailboxes = await env.DB.prepare("SELECT COUNT(*) AS count FROM mailboxes")
      .first<{ count: number }>();
    expect(counter?.count).toBe(1);
    expect(mailboxes?.count).toBe(1);
  });

  it("rolls back the counter increment when the total managed limit rejects an insert", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await env.DB.prepare("UPDATE settings SET value = ? WHERE key = ?")
      .bind("1", "total_managed_limit").run();
    await repository.reservePendingMailbox(mailboxInput());

    await expect(repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_02",
      email: `beta@${DOMAIN}`,
      localPart: "beta",
    }))).rejects.toMatchObject({ code: "TOTAL_LIMIT" });

    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind(DATE, TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(1);
  });

  it("applies allowed transitions and rejects stale or invalid state changes", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await repository.reservePendingMailbox(mailboxInput());

    await repository.transitionMailbox("mbx_01", "pending", "active", { updatedAt: LATER });
    await expect(
      repository.transitionMailbox("mbx_01", "pending", "failed", {
        failureCode: "UPSTREAM_ERROR",
        updatedAt: LATER,
      }),
    ).rejects.toMatchObject({ code: "INVALID_STATE" });
    await expect(
      repository.transitionMailbox("mbx_01", "active", "pending", { updatedAt: LATER }),
    ).rejects.toMatchObject({ code: "INVALID_TRANSITION" });
    expect(await repository.findMailbox("mbx_01")).toMatchObject({
      status: "active",
      failureCode: null,
      updatedAt: LATER,
    });
  });

  it("releases the exact daily reservation after a pending mailbox fails", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await repository.reservePendingMailbox(mailboxInput());

    await repository.transitionMailbox("mbx_01", "pending", "failed", {
      failureCode: "UPSTREAM_CONFLICT",
      updatedAt: LATER,
      releaseReservation: { date: DATE, tokenId: TOKEN_ID },
    });

    const counter = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind(DATE, TOKEN_ID).first<{ count: number }>();
    expect(counter?.count).toBe(0);

    await repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_02",
      email: `beta@${DOMAIN}`,
      localPart: "beta",
    }));

    await expect(repository.transitionMailbox("mbx_01", "pending", "failed", {
      updatedAt: "2026-08-13T10:02:00.000Z",
      releaseReservation: { date: DATE, tokenId: TOKEN_ID },
    })).rejects.toMatchObject({ code: "INVALID_STATE" });
    const afterStaleTransition = await env.DB.prepare(
      "SELECT count FROM creation_counters WHERE date = ? AND token_id = ?",
    ).bind(DATE, TOKEN_ID).first<{ count: number }>();
    expect(afterStaleTransition?.count).toBe(1);
  });

  it("keeps a candidate reset password recoverable until completion", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await repository.reservePendingMailbox(mailboxInput());
    await repository.transitionMailbox("mbx_01", "pending", "active", { updatedAt: LATER });
    const nextCiphertext = new Uint8Array([50, 60, 70]);
    const nextNonce = new Uint8Array([12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

    await repository.saveNextPassword("mbx_01", {
      ciphertext: nextCiphertext,
      nonce: nextNonce,
      updatedAt: "2026-08-13T10:02:00.000Z",
    });
    expect(await repository.findMailbox("mbx_01")).toMatchObject({ status: "resetting" });

    await repository.completePasswordReset("mbx_01", "2026-08-13T10:03:00.000Z");
    const completed = await repository.findMailbox("mbx_01");
    expect(completed?.status).toBe("active");
    expect(Array.from(completed!.passwordCiphertext)).toEqual([50, 60, 70]);
    expect(Array.from(completed!.passwordNonce)).toEqual([12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    expect(completed?.nextPasswordCiphertext).toBeNull();
    expect(completed?.nextPasswordNonce).toBeNull();
  });

  it("pages mailboxes with a stable cursor and literal ordering", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_02",
      email: `beta@${DOMAIN}`,
      localPart: "beta",
      now: "2026-08-13T10:02:00.000Z",
    }));
    await repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_01",
      email: `alpha@${DOMAIN}`,
      localPart: "alpha",
      now: "2026-08-13T10:01:00.000Z",
    }));
    await repository.reservePendingMailbox(mailboxInput({
      publicId: "mbx_03",
      email: `gamma@${DOMAIN}`,
      localPart: "gamma",
      now: "2026-08-13T10:03:00.000Z",
    }));

    const first = await repository.pageMailboxes({
      limit: 2,
      sort: "createdAt",
      direction: "asc",
    });
    const second = await repository.pageMailboxes({
      limit: 2,
      sort: "createdAt",
      direction: "asc",
      cursor: first.nextCursor!,
    });

    expect(first.items.map((item) => item.publicId)).toEqual(["mbx_01", "mbx_02"]);
    expect(first.nextCursor).not.toBeNull();
    expect(second.items.map((item) => item.publicId)).toEqual(["mbx_03"]);
    expect(second.nextCursor).toBeNull();
  });

  it("rejects inactive defaults and stores exactly one active default domain", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains(["first.test", "second.test"], NOW);
    await repository.setDefaultDomain("first.test");
    await repository.setDefaultDomain("second.test");
    await repository.syncDomains(["second.test"], LATER);

    await expect(repository.setDefaultDomain("first.test"))
      .rejects.toMatchObject({ code: "INACTIVE_DOMAIN" });
    const defaults = await env.DB.prepare(
      "SELECT value FROM settings WHERE key = ?",
    ).bind("default_domain").all<{ value: string }>();
    expect(defaults.results).toEqual([{ value: "second.test" }]);
    expect((await repository.getSettings()).defaultDomain).toBe("second.test");
  });

  it("does not expose a configured default after its domain becomes inactive", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains(["first.test", "second.test"], NOW);
    await repository.setDefaultDomain("first.test");

    await repository.syncDomains(["second.test"], LATER);

    expect((await repository.getSettings()).defaultDomain).toBeNull();
  });

  it("verifies active token digests and rejects a revoked token", async () => {
    const repository = new Repository(env.DB);
    await repository.createTokenDigest({
      id: TOKEN_ID,
      name: "Primary",
      digest: DIGEST,
      createdAt: NOW,
    });

    expect(await repository.verifyTokenDigest(DIGEST, LATER)).toMatchObject({
      id: TOKEN_ID,
      name: "Primary",
      lastUsedAt: LATER,
      revokedAt: null,
    });
    await env.DB.prepare("UPDATE api_tokens SET revoked_at = ? WHERE id = ?")
      .bind("2026-08-13T10:02:00.000Z", TOKEN_ID).run();
    expect(await repository.verifyTokenDigest(DIGEST, "2026-08-13T10:03:00.000Z")).toBeNull();
  });

  it("removes only a mailbox already guarded in deleting state", async () => {
    const repository = new Repository(env.DB);
    await prepareReservation(repository);
    await repository.reservePendingMailbox(mailboxInput());
    await repository.transitionMailbox("mbx_01", "pending", "active", { updatedAt: LATER });

    await expect(repository.removeMailbox("mbx_01"))
      .rejects.toMatchObject({ code: "INVALID_STATE" });
    await repository.transitionMailbox("mbx_01", "active", "deleting", { updatedAt: LATER });
    await repository.removeMailbox("mbx_01");
    expect(await repository.findMailbox("mbx_01")).toBeNull();
  });

  it("persists only redacted audit fields", async () => {
    const repository = new Repository(env.DB);
    await repository.appendAudit({
      id: "audit_01",
      actorType: "admin",
      actorId: "admin@example.test",
      action: "mailbox.reveal",
      email: `alpha@${DOMAIN}`,
      result: "success",
      errorCode: null,
      requestId: "request_01",
      createdAt: NOW,
    });

    const row = await env.DB.prepare("SELECT * FROM audit_events WHERE id = ?")
      .bind("audit_01").first<Record<string, unknown>>();
    expect(row).toEqual({
      id: "audit_01",
      actor_type: "admin",
      actor_id: "admin@example.test",
      action: "mailbox.reveal",
      email: `alpha@${DOMAIN}`,
      result: "success",
      error_code: null,
      request_id: "request_01",
      created_at: NOW,
    });
  });
});
