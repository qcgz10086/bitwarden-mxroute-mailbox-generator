import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { AdminIdentity } from "../../packages/contracts/src/index";
import { decryptPassword, encryptPassword, tokenHmac } from "../../packages/security/src/crypto";
import { ServiceError, type ServiceErrorCode } from "../../workers/core/src/errors";
import type { MxrouteMailbox } from "../../workers/core/src/mxroute";
import { Repository } from "../../workers/core/src/repository";
import { AdminError, AdministrationService } from "../../workers/core/src/service";

const NOW = "2026-08-13T10:10:00.000Z";
const STALE = "2026-08-13T10:00:00.000Z";
const DOMAIN = "example.test";
const SECOND_DOMAIN = "second.test";
const EMAIL = `alpha@${DOMAIN}`;
const PASSWORD = "Aa2!bbbbbbbbbbbbbb";
const CANDIDATE = "Cc4!dddddddddddddd";
const TOKEN_PEPPER = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const ENCRYPTION_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ADMIN: AdminIdentity = { subject: "access-subject", email: "admin@example.test" };

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };
type Outcome = "success" | ServiceErrorCode;

class FakeMxroute {
  readonly patches: string[] = [];
  readonly deletes: string[] = [];
  readonly gets: string[] = [];
  listOutcome: readonly string[] | ServiceErrorCode = [DOMAIN];
  patchOutcomes: Outcome[] = [];
  deleteOutcomes: Outcome[] = [];
  getOutcomes: Outcome[] = [];

  async listDomains(): Promise<readonly string[]> {
    if (typeof this.listOutcome === "string") throw new ServiceError(this.listOutcome);
    return this.listOutcome;
  }

  async updateMailbox(domain: string, user: string, patch: { password?: string }): Promise<MxrouteMailbox> {
    this.patches.push(patch.password ?? "");
    const outcome = this.patchOutcomes.shift() ?? "success";
    if (outcome !== "success") throw new ServiceError(outcome);
    return { username: user, email: `${user}@${domain}`, quotaMb: 100, limit: 9600 };
  }

  async deleteMailbox(domain: string, user: string): Promise<void> {
    this.deletes.push(`${user}@${domain}`);
    const outcome = this.deleteOutcomes.shift() ?? "success";
    if (outcome !== "success") throw new ServiceError(outcome);
  }

  readonly creates: string[] = [];
  createOutcomes: Outcome[] = [];

  async createMailbox(domain: string, user: string, password: string, quotaMb: number): Promise<MxrouteMailbox> {
    this.creates.push(`${user}@${domain}`);
    const outcome = this.createOutcomes.shift() ?? "success";
    if (outcome !== "success") throw new ServiceError(outcome);
    return { username: user, email: `${user}@${domain}`, quotaMb, limit: 9600 };
  }

  async getMailbox(domain: string, user: string): Promise<MxrouteMailbox> {
    this.gets.push(`${user}@${domain}`);
    const outcome = this.getOutcomes.shift() ?? "success";
    if (outcome !== "success") throw new ServiceError(outcome);
    return { username: user, email: `${user}@${domain}`, quotaMb: 100, limit: 9600 };
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
    env.DB.prepare("UPDATE settings SET value = '100' WHERE key = 'mailbox_quota_mb'"),
    env.DB.prepare("UPDATE settings SET value = '12' WHERE key = 'prefix_length'"),
    env.DB.prepare("UPDATE settings SET value = '30' WHERE key = 'daily_creation_limit'"),
    env.DB.prepare("UPDATE settings SET value = '500' WHERE key = 'total_managed_limit'"),
    env.DB.prepare("UPDATE settings SET value = 'true' WHERE key = 'generation_enabled'"),
  ]);
});

function adminService(mxroute = new FakeMxroute(), now = NOW): AdministrationService {
  let id = 0;
  return new AdministrationService({
    repository: new Repository(env.DB),
    mxroute,
    tokenPepper: TOKEN_PEPPER,
    encryptionKeys: { 1: ENCRYPTION_KEY },
    encryptionKeyVersion: 1,
    now: () => new Date(now),
    randomMailboxPassword: () => CANDIDATE,
    randomApiToken: () => `raw-token-${++id}`,
    createId: (kind) => `${kind}-${++id}`,
  });
}

async function seedMailbox(status: string = "active", updatedAt = STALE): Promise<void> {
  const encrypted = await encryptPassword({
    password: PASSWORD,
    key: ENCRYPTION_KEY,
    publicId: "mbx-1",
    email: EMAIL,
    keyVersion: 1,
  });
  await new Repository(env.DB).syncDomains([DOMAIN], STALE);
  await env.DB.prepare(`INSERT INTO mailboxes(
      public_id, email, local_part, domain, password_ciphertext, password_nonce,
      encryption_key_version, quota_mb, status, created_at, updated_at,
      reservation_date, reservation_token_id
    ) VALUES(?, ?, 'alpha', ?, ?, ?, 1, 100, ?, ?, ?, NULL, NULL)`)
    .bind("mbx-1", EMAIL, DOMAIN, encrypted.ciphertext.buffer, encrypted.nonce.buffer, status, STALE, updatedAt)
    .run();
}

async function seedRegisteredMailbox(publicId = "mbx-1", email = EMAIL, status = "registered", updatedAt = STALE): Promise<void> {
  await new Repository(env.DB).syncDomains([DOMAIN], STALE);
  await env.DB.prepare(`INSERT INTO mailboxes(
      public_id, email, local_part, domain, quota_mb, status, created_at, updated_at
    ) VALUES(?, ?, 'alpha', ?, 100, ?, ?, ?)`)
    .bind(publicId, email, DOMAIN, status, STALE, updatedAt)
    .run();
}

async function expectAdminError(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(AdminError);
  expect((error as AdminError).code).toBe(code);
}

describe("AdministrationService configuration and tokens", () => {
  it("returns domains, settings, and token metadata without secret values", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains([DOMAIN], NOW);
    const service = adminService();
    const created = await service.createApiToken(ADMIN, "Phone", "operation-phone-0001");

    expect(await service.listDomains(ADMIN)).toEqual([{ domain: DOMAIN, active: true, syncedAt: NOW }]);
    expect(await service.getSettings(ADMIN)).toMatchObject({ mailboxQuotaMb: 100, prefixLength: 12 });
    const tokens = await service.listApiTokens(ADMIN);
    expect(tokens).toEqual([{ id: created.id, name: "Phone", createdAt: NOW, lastUsedAt: null, revokedAt: null,
      status: "pending", pendingExpiresAt: "2026-08-13T10:20:00.000Z" }]);
    expect(JSON.stringify(tokens)).not.toContain(created.rawToken);
  });

  it("syncs domains without deleting missing rows and leaves state unchanged on upstream failure", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains([DOMAIN, SECOND_DOMAIN], STALE);
    await repository.setDefaultDomain(SECOND_DOMAIN);
    const mxroute = new FakeMxroute();
    mxroute.listOutcome = [DOMAIN];
    const service = adminService(mxroute);

    await service.syncDomains(ADMIN);
    expect(await repository.listDomains()).toEqual([
      { domain: DOMAIN, active: true, syncedAt: NOW },
      { domain: SECOND_DOMAIN, active: false, syncedAt: NOW },
    ]);
    expect((await repository.getSettings()).defaultDomain).toBeNull();

    mxroute.listOutcome = "MX_TIMEOUT";
    await expectAdminError(service.syncDomains(ADMIN), "MX_TIMEOUT");
    expect((await repository.listDomains()).map((item) => item.domain)).toEqual([DOMAIN, SECOND_DOMAIN]);
  });

  it("rejects inactive defaults and numeric settings outside server ranges", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains([DOMAIN], NOW);
    const service = adminService();

    await expectAdminError(service.setDefaultDomain(ADMIN, SECOND_DOMAIN), "INACTIVE_DOMAIN");
    await expectAdminError(service.updateSettings(ADMIN, { mailboxQuotaMb: 0 }), "INVALID_SETTINGS");
    await expectAdminError(service.updateSettings(ADMIN, { dailyCreationLimit: 1001 }), "INVALID_SETTINGS");
    await expectAdminError(service.updateSettings(ADMIN, { totalManagedLimit: 100001 }), "INVALID_SETTINGS");
    await expectAdminError(service.updateSettings(ADMIN, { prefixLength: 11 }), "INVALID_SETTINGS");
  });

  it("stores only token HMACs, allows two live tokens, and rejects creation of a third", async () => {
    const service = adminService();
    const first = await service.createApiToken(ADMIN, "Primary", "operation-primary-0001");
    const pendingStorage = await env.DB.prepare(`SELECT hex(pending_token_ciphertext) ciphertext,
      hex(pending_token_nonce) nonce,acknowledged_at FROM api_tokens WHERE id=?`).bind(first.id)
      .first<{ ciphertext: string; nonce: string; acknowledged_at: string | null }>();
    const rawHex = Array.from(new TextEncoder().encode(first.rawToken), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
    expect(pendingStorage).toMatchObject({ acknowledged_at: null });
    expect(pendingStorage?.ciphertext).not.toContain(rawHex);
    expect(pendingStorage?.nonce).not.toContain(rawHex);
    const retry = await service.createApiToken(ADMIN, "Primary", "operation-primary-0001");
    expect(retry).toMatchObject({ id: first.id, rawToken: first.rawToken });
    await service.acknowledgeApiToken(ADMIN, first.id, "operation-primary-0001");
    await expect(service.acknowledgeApiToken(ADMIN, first.id, "operation-primary-0001")).resolves.toHaveProperty("requestId");
    expect(await env.DB.prepare("SELECT COUNT(*) count FROM audit_events WHERE action='token.create.acknowledge'").first("count")).toBe(1);
    expect((await service.listApiTokens(ADMIN)).find((token) => token.id === first.id)).toMatchObject({ status: "active", pendingExpiresAt: null });
    await expectAdminError(service.createApiToken(ADMIN, "Primary", "operation-primary-0001"), "INVALID_STATE");
    const second = await service.createApiToken(ADMIN, "Rotation", "operation-rotation-0001");
    await expectAdminError(service.createApiToken(ADMIN, "Third", "operation-third-0001"), "TOKEN_LIMIT");

    expect(first.rawToken).toMatch(/^raw-token-/);
    expect(second.rawToken).toMatch(/^raw-token-/);
    expect(second.rawToken).not.toBe(first.rawToken);
    const rows = await env.DB.prepare("SELECT token_hmac,pending_token_ciphertext,acknowledged_at FROM api_tokens ORDER BY created_at").all<Record<string, unknown>>();
    expect(rows.results).toHaveLength(2);
    expect(JSON.stringify(rows.results)).not.toContain(first.rawToken);
    expect(rows.results[0]).toMatchObject({ pending_token_ciphertext: null, acknowledged_at: NOW });
    expect(await new Repository(env.DB).verifyTokenDigest(await tokenHmac(first.rawToken, TOKEN_PEPPER), NOW)).not.toBeNull();
    await expect(new Repository(env.DB).createTokenDigest({
      id: "concurrent-third", name: "Concurrent third", digest: new Uint8Array([9]), createdAt: NOW,
    })).rejects.toMatchObject({ code: "TOKEN_LIMIT" });

    await service.revokeApiToken(ADMIN, first.id);
    expect((await service.listApiTokens(ADMIN)).find((token) => token.id === first.id)).toMatchObject({ status: "revoked", pendingExpiresAt: null });
    expect(await new Repository(env.DB).verifyTokenDigest(await tokenHmac(first.rawToken, TOKEN_PEPPER), NOW)).toBeNull();
  });

  it("rejects idempotent acknowledgement from a different Access subject", async () => {
    const service = adminService();
    const created = await service.createApiToken(ADMIN, "Phone", "operation-owner-0001");
    await service.acknowledgeApiToken(ADMIN, created.id, "operation-owner-0001");
    await expectAdminError(service.acknowledgeApiToken({ subject: "other-subject", email: "other@example.test" }, created.id, "operation-owner-0001"), "INVALID_STATE");
  });

  it("revokes and clears expired unacknowledged token issuance", async () => {
    const service = adminService();
    const created = await service.createApiToken(ADMIN, "Abandoned", "operation-abandoned-0001");
    expect(await new Repository(env.DB).verifyTokenDigest(await tokenHmac(created.rawToken, TOKEN_PEPPER), NOW)).toBeNull();
    await env.DB.prepare("UPDATE api_tokens SET pending_expires_at='2000-01-01T00:00:00.000Z'").run();
    expect(await service.reconcileAll()).toBeGreaterThanOrEqual(1);
    const row = await env.DB.prepare("SELECT revoked_at,pending_token_ciphertext,pending_token_nonce FROM api_tokens WHERE id=?")
      .bind(created.id).first<Record<string, unknown>>();
    expect(row).toMatchObject({ pending_token_ciphertext: null, pending_token_nonce: null });
    expect(row?.revoked_at).toBe(NOW);
  });

  it("paginates mailbox and audit records without secret fields", async () => {
    await seedMailbox();
    const service = adminService();
    await service.updateSettings(ADMIN, { generationEnabled: false });
    await service.updateSettings(ADMIN, { generationEnabled: true });

    const mailboxes = await service.pageMailboxes(ADMIN, { limit: 1 });
    const audits = await service.pageAudit(ADMIN, { limit: 1 });
    expect(mailboxes.items).toHaveLength(1);
    expect(JSON.stringify(mailboxes)).not.toContain("ciphertext");
    expect(audits.items).toHaveLength(1);
    expect(audits.nextCursor).not.toBeNull();
    expect(JSON.stringify(audits)).not.toContain(PASSWORD);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid pagination limit %s",
    async (limit) => {
      const service = adminService();
      await expectAdminError(service.pageMailboxes(ADMIN, { limit }), "INVALID_INPUT");
      await expectAdminError(service.pageAudit(ADMIN, { limit }), "INVALID_INPUT");
    },
  );
});

describe("AdministrationService password state machine", () => {
  it("reveals only permitted states and audits identity without password material", async () => {
    await seedMailbox();
    const service = adminService();
    expect(await service.revealPassword(ADMIN, "mbx-1")).toMatchObject({ password: PASSWORD, requestId: expect.any(String) });
    const audit = await env.DB.prepare("SELECT * FROM audit_events").first<Record<string, unknown>>();
    expect(audit).toMatchObject({ actor_type: "admin", actor_id: ADMIN.subject, actor_email: ADMIN.email, action: "mailbox.reveal", email: EMAIL });
    expect(JSON.stringify(audit)).not.toContain(PASSWORD);
    const outcomes = await env.DB.prepare("SELECT result FROM audit_events WHERE action = 'mailbox.reveal'").all<{ result: string }>();
    expect(outcomes.results).toEqual([{ result: "success" }]);

    await env.DB.prepare("UPDATE mailboxes SET status = 'deleting' WHERE public_id = 'mbx-1'").run();
    await expectAdminError(service.revealPassword(ADMIN, "mbx-1"), "INVALID_STATE");
  });

  it("sets and clears a mailbox note with an audit trail and rejects unknown mailboxes", async () => {
    await seedMailbox();
    const service = adminService();

    await service.setMailboxNote(ADMIN, "mbx-1", "primary backup mailbox");
    const afterSet = await env.DB.prepare("SELECT note FROM mailboxes WHERE public_id = 'mbx-1'").first<{ note: string | null }>();
    expect(afterSet?.note).toBe("primary backup mailbox");
    const audit = await env.DB.prepare("SELECT * FROM audit_events WHERE action = 'mailbox.note'").first<Record<string, unknown>>();
    expect(audit).toMatchObject({ actor_type: "admin", actor_id: ADMIN.subject, actor_email: ADMIN.email, action: "mailbox.note", result: "success", email: EMAIL });
    expect(JSON.stringify(audit)).not.toContain("primary backup mailbox");

    await service.setMailboxNote(ADMIN, "mbx-1", null);
    const afterClear = await env.DB.prepare("SELECT note FROM mailboxes WHERE public_id = 'mbx-1'").first<{ note: string | null }>();
    expect(afterClear?.note).toBeNull();

    await expectAdminError(service.setMailboxNote(ADMIN, "mbx-missing", "x"), "NOT_FOUND");
  });

  it("sets, verifies, and rejects the admin password", async () => {
    const service = adminService();
    expect(await service.isAdminPasswordSet()).toBe(false);
    await service.setAdminPassword(ADMIN, "CorrectHorse123");
    expect(await service.isAdminPasswordSet()).toBe(true);
    expect(await service.verifyAdminPassword("CorrectHorse123")).toBe(true);
    expect(await service.verifyAdminPassword("WrongPassword")).toBe(false);
    await expectAdminError(service.setAdminPassword(ADMIN, "short"), "INVALID_INPUT");
    const audit = await env.DB.prepare("SELECT result FROM audit_events WHERE action = 'admin.password'").first<{ result: string }>();
    expect(audit?.result).toBe("success");
  });

  it("confirms a registered mailbox by creating the account, storing an encrypted password, and auditing", async () => {
    await seedRegisteredMailbox();
    const mxroute = new FakeMxroute();
    const service = adminService(mxroute);

    const result = await service.confirmMailbox(ADMIN, "mbx-1");

    expect(result).toMatchObject({ requestId: expect.any(String) });
    expect(mxroute.creates).toEqual([`alpha@${DOMAIN}`]);
    const mailbox = await new Repository(env.DB).findMailbox("mbx-1");
    expect(mailbox).toMatchObject({ status: "active", failureCode: null });
    expect(mailbox?.passwordCiphertext).not.toBeNull();
    await expect(decryptPassword({
      encrypted: {
        ciphertext: mailbox!.passwordCiphertext!,
        nonce: mailbox!.passwordNonce!,
        keyVersion: mailbox!.encryptionKeyVersion!,
      },
      key: ENCRYPTION_KEY,
      publicId: mailbox!.publicId,
      email: mailbox!.email,
    })).resolves.toMatch(/^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?~]{18}$/);
    const audit = await env.DB.prepare("SELECT * FROM audit_events WHERE action = 'mailbox.confirm'").first<Record<string, unknown>>();
    expect(audit).toMatchObject({ actor_type: "admin", action: "mailbox.confirm", email: EMAIL, result: "success" });
    expect(JSON.stringify(audit)).not.toContain("password");
  });

  it("rejects confirming a mailbox that is not registered", async () => {
    await seedMailbox();
    const service = adminService();

    await expectAdminError(service.confirmMailbox(ADMIN, "mbx-1"), "INVALID_STATE");
  });

  it.each(["MX_UNAUTHORIZED", "MX_CLIENT", "MX_CONFLICT"] as const)("marks an explicitly failed confirm as failed with %s", async (code) => {
    await seedRegisteredMailbox();
    const mxroute = new FakeMxroute();
    mxroute.createOutcomes.push(code);
    const service = adminService(mxroute);

    await expectAdminError(service.confirmMailbox(ADMIN, "mbx-1"), code);
    expect((await new Repository(env.DB).findMailbox("mbx-1"))?.status).toBe("failed");
    const audit = await env.DB.prepare("SELECT result FROM audit_events WHERE action = 'mailbox.confirm'").first<{ result: string }>();
    expect(audit?.result).toBe("failure");
  });

  it("keeps an uncertain confirm in activating state for reconciliation", async () => {
    await seedRegisteredMailbox();
    const mxroute = new FakeMxroute();
    mxroute.createOutcomes.push("MX_TIMEOUT");
    const service = adminService(mxroute);

    await expectAdminError(service.confirmMailbox(ADMIN, "mbx-1"), "MX_TIMEOUT");
    const mailbox = await new Repository(env.DB).findMailbox("mbx-1");
    expect(mailbox?.status).toBe("activating");
    expect(mailbox?.passwordCiphertext).not.toBeNull();
  });

  it.each(["corrupt ciphertext", "missing key"])(
    "records one failure and no success for reveal with %s",
    async (failure) => {
      await seedMailbox();
      if (failure === "corrupt ciphertext") {
        await env.DB.prepare("UPDATE mailboxes SET password_ciphertext = ? WHERE public_id = 'mbx-1'")
          .bind(new Uint8Array([1, 2, 3]).buffer).run();
      }
      const service = failure === "missing key"
        ? new AdministrationService({
            repository: new Repository(env.DB), mxroute: new FakeMxroute(),
            tokenPepper: TOKEN_PEPPER, encryptionKeys: {}, encryptionKeyVersion: 1,
            now: () => new Date(NOW), createId: (kind) => `${kind}-${crypto.randomUUID()}`,
          })
        : adminService();

      await expectAdminError(service.revealPassword(ADMIN, "mbx-1"), "INTERNAL_ERROR");

      const outcomes = await env.DB.prepare("SELECT result FROM audit_events WHERE action = 'mailbox.reveal'").all<{ result: string }>();
      expect(outcomes.results).toEqual([{ result: "failure" }]);
    },
  );

  it("returns no plaintext when state changes before final reveal authorization", async () => {
    await seedMailbox();
    const repository = new Repository(env.DB);
    const authorize = vi.spyOn(repository, "recordPasswordRevealSuccessWithAudit")
      .mockImplementationOnce(async (publicId, event) => {
        await env.DB.prepare("UPDATE mailboxes SET status = 'deleting' WHERE public_id = ?").bind(publicId).run();
        authorize.mockRestore();
        await repository.recordPasswordRevealSuccessWithAudit(publicId, event);
      });
    const service = new AdministrationService({
      repository, mxroute: new FakeMxroute(), tokenPepper: TOKEN_PEPPER,
      encryptionKeys: { 1: ENCRYPTION_KEY }, encryptionKeyVersion: 1,
      now: () => new Date(NOW), createId: (kind) => `${kind}-${crypto.randomUUID()}`,
    });

    await expectAdminError(service.revealPassword(ADMIN, "mbx-1"), "INVALID_STATE");

    const outcomes = await env.DB.prepare("SELECT result FROM audit_events WHERE action = 'mailbox.reveal'").all<{ result: string }>();
    expect(outcomes.results).toEqual([{ result: "failure" }]);
  });

  it("commits reset success and rolls explicit failures back to the current password", async () => {
    await seedMailbox();
    const mxroute = new FakeMxroute();
    const service = adminService(mxroute);
    const result = await service.resetPassword(ADMIN, "mbx-1");
    expect(result.password).toBe(CANDIDATE);
    expect(mxroute.patches).toEqual([CANDIDATE]);
    expect((await new Repository(env.DB).findMailbox("mbx-1"))?.status).toBe("active");

    mxroute.patchOutcomes.push("MX_CLIENT");
    await expectAdminError(service.resetPassword(ADMIN, "mbx-1"), "MX_CLIENT");
    const row = await new Repository(env.DB).findMailbox("mbx-1");
    expect(row).toMatchObject({ status: "active", nextPasswordCiphertext: null, failureCode: "MX_CLIENT" });
  });

  it("persists timeout candidates and reconciliation reuses the same password", async () => {
    await seedMailbox();
    const mxroute = new FakeMxroute();
    mxroute.patchOutcomes.push("MX_TIMEOUT", "success");
    const service = adminService(mxroute);

    await expectAdminError(service.resetPassword(ADMIN, "mbx-1"), "MX_TIMEOUT");
    expect((await new Repository(env.DB).findMailbox("mbx-1"))?.status).toBe("reset_unknown");
    expect((await service.revealPassword(ADMIN, "mbx-1")).password).toBe(CANDIDATE);
    await env.DB.prepare("UPDATE mailboxes SET updated_at = ? WHERE public_id = 'mbx-1'").bind(STALE).run();
    await service.reconcileResetUnknown();
    expect(mxroute.patches).toEqual([CANDIDATE, CANDIDATE]);
    const row = await new Repository(env.DB).findMailbox("mbx-1");
    expect(row?.status).toBe("active");
    expect(await decryptPassword({ encrypted: { ciphertext: row!.passwordCiphertext!, nonce: row!.passwordNonce!, keyVersion: 1 }, key: ENCRYPTION_KEY, publicId: row!.publicId, email: row!.email })).toBe(CANDIDATE);
  });

  it("recovers a stale resetting row when promotion and reset_unknown persistence both fail", async () => {
    await seedMailbox();
    const repository = new Repository(env.DB);
    const mxroute = new FakeMxroute();
    const complete = vi.spyOn(repository, "completePasswordResetWithAudit")
      .mockRejectedValueOnce(new Error("promotion failed"));
    const mark = vi.spyOn(repository, "markResetUnknownWithAudit")
      .mockRejectedValueOnce(new Error("mark failed"));
    const service = new AdministrationService({
      repository, mxroute, tokenPepper: TOKEN_PEPPER,
      encryptionKeys: { 1: ENCRYPTION_KEY }, encryptionKeyVersion: 1,
      now: () => new Date(NOW), randomMailboxPassword: () => CANDIDATE,
      createId: (kind) => `${kind}-${crypto.randomUUID()}`,
    });

    await expectAdminError(service.resetPassword(ADMIN, "mbx-1"), "INTERNAL_ERROR");
    expect((await repository.findMailbox("mbx-1"))?.status).toBe("resetting");
    complete.mockRestore();
    mark.mockRestore();
    await env.DB.prepare("UPDATE mailboxes SET updated_at = ? WHERE public_id = 'mbx-1'").bind(STALE).run();
    await service.reconcileResetUnknown();
    expect(mxroute.patches).toEqual([CANDIDATE, CANDIDATE]);
    expect((await repository.findMailbox("mbx-1"))?.status).toBe("active");
  });

  it("guards reveal authorization in D1 after a state change", async () => {
    await seedMailbox();
    await env.DB.prepare("UPDATE mailboxes SET status = 'deleting' WHERE public_id = 'mbx-1'").run();
    await expectAdminError(adminService().revealPassword(ADMIN, "mbx-1"), "INVALID_STATE");
    expect(await env.DB.prepare("SELECT id FROM audit_events WHERE action = 'mailbox.reveal' AND result = 'success'").first()).toBeNull();
  });
});

describe("AdministrationService permanent deletion and recovery", () => {
  it("requires exact email confirmation and removes the secret row while retaining audit", async () => {
    await seedMailbox();
    const service = adminService();
    await expectAdminError(service.deleteMailbox(ADMIN, "mbx-1", EMAIL.toUpperCase()), "CONFIRMATION_MISMATCH");
    await service.deleteMailbox(ADMIN, "mbx-1", EMAIL);
    expect(await new Repository(env.DB).findMailbox("mbx-1")).toBeNull();
    const audit = await env.DB.prepare("SELECT * FROM audit_events WHERE action = 'mailbox.delete' AND result = 'success'").first<Record<string, unknown>>();
    expect(audit).toMatchObject({ result: "success", email: EMAIL, actor_email: ADMIN.email });
    expect(Object.keys(audit ?? {})).not.toContain("password_ciphertext");
  });

  it("treats upstream NOT_FOUND as deletion success and explicit failure as visible delete_failed", async () => {
    await seedMailbox();
    const notFound = new FakeMxroute();
    notFound.deleteOutcomes.push("MX_NOT_FOUND");
    await adminService(notFound).deleteMailbox(ADMIN, "mbx-1", EMAIL);
    expect(await new Repository(env.DB).findMailbox("mbx-1")).toBeNull();

    await env.DB.prepare("DELETE FROM audit_events").run();
    await seedMailbox();
    const failed = new FakeMxroute();
    failed.deleteOutcomes.push("MX_CLIENT");
    await expectAdminError(adminService(failed).deleteMailbox(ADMIN, "mbx-1", EMAIL), "MX_CLIENT");
    expect((await new Repository(env.DB).findMailbox("mbx-1"))?.status).toBe("delete_failed");
  });

  it("resolves delete timeouts by existence check and leaves ambiguous rows recoverable", async () => {
    await seedMailbox();
    const gone = new FakeMxroute();
    gone.deleteOutcomes.push("MX_TIMEOUT");
    gone.getOutcomes.push("MX_NOT_FOUND");
    await adminService(gone).deleteMailbox(ADMIN, "mbx-1", EMAIL);
    expect(await new Repository(env.DB).findMailbox("mbx-1")).toBeNull();

    await env.DB.prepare("DELETE FROM audit_events").run();
    await seedMailbox();
    const exists = new FakeMxroute();
    exists.deleteOutcomes.push("MX_TIMEOUT");
    await expectAdminError(adminService(exists).deleteMailbox(ADMIN, "mbx-1", EMAIL), "MX_TIMEOUT");
    expect((await new Repository(env.DB).findMailbox("mbx-1"))?.status).toBe("delete_failed");
  });

  it("reconciles at most 25 stale pending rows and stops rows after eight attempts", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains([DOMAIN], STALE);
    await repository.createTokenDigest({ id: "recovery-token", name: "Recovery", digest: new Uint8Array([1]), createdAt: STALE });
    const encrypted = await encryptPassword({ password: PASSWORD, key: ENCRYPTION_KEY, publicId: "template", email: EMAIL, keyVersion: 1 });
    for (let index = 0; index < 27; index += 1) {
      await repository.reservePendingMailbox({
        tokenId: "recovery-token", date: "2026-08-13", publicId: `pending-${index}`,
        email: `p${index}@${DOMAIN}`, localPart: `p${index}`, domain: DOMAIN,
        password: encrypted, quotaMb: 100, now: STALE,
      });
    }
    await env.DB.prepare("UPDATE mailboxes SET recovery_attempt_count = 8 WHERE public_id = 'pending-0'").run();
    const mxroute = new FakeMxroute();
    mxroute.getOutcomes = Array.from({ length: 30 }, () => "MX_TIMEOUT");
    await adminService(mxroute).reconcilePending();
    expect(mxroute.gets).toHaveLength(25);
    expect(mxroute.gets).not.toContain(`p0@${DOMAIN}`);
  });

  it("atomically activates existing pending mailboxes and fails missing ones while releasing quota", async () => {
    const repository = new Repository(env.DB);
    await repository.syncDomains([DOMAIN], STALE);
    await repository.createTokenDigest({ id: "pending-token", name: "Pending", digest: new Uint8Array([2]), createdAt: STALE });
    const encrypted = await encryptPassword({ password: PASSWORD, key: ENCRYPTION_KEY, publicId: "template", email: EMAIL, keyVersion: 1 });
    for (const localPart of ["exists", "missing"]) {
      await repository.reservePendingMailbox({
        tokenId: "pending-token", date: "2026-08-13", publicId: `pending-${localPart}`,
        email: `${localPart}@${DOMAIN}`, localPart, domain: DOMAIN,
        password: encrypted, quotaMb: 100, now: STALE,
      });
    }
    const mxroute = new FakeMxroute();
    mxroute.getOutcomes.push("success", "MX_NOT_FOUND");

    await adminService(mxroute).reconcilePending();

    expect((await repository.findMailbox("pending-exists"))?.status).toBe("active");
    expect((await repository.findMailbox("pending-missing"))?.status).toBe("failed");
    const counter = await env.DB.prepare("SELECT count FROM creation_counters WHERE token_id = 'pending-token'").first<{ count: number }>();
    expect(counter?.count).toBe(1);
    expect(await env.DB.prepare("SELECT id FROM audit_events WHERE action = 'mailbox.create.reconcile' AND result = 'success'").first()).not.toBeNull();
  });

  it("removes a stale deleting row only after GET confirms it is absent", async () => {
    await seedMailbox("deleting");
    const mxroute = new FakeMxroute();
    mxroute.getOutcomes.push("MX_NOT_FOUND");

    await adminService(mxroute).reconcileDeleting();

    expect(await new Repository(env.DB).findMailbox("mbx-1")).toBeNull();
    expect(await env.DB.prepare("SELECT id FROM audit_events WHERE action = 'mailbox.delete.reconcile'").first()).not.toBeNull();
  });
});
