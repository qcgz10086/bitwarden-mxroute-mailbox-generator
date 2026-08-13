import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createTestHarness, type TestHarness } from "wrangler";
import { accessFixture } from "../fixtures/access-key";
import type { CoreEnv } from "../../workers/core/src/index";

const ORIGIN = "https://admin.example.test";
const ADMIN = { subject: "access-user", email: "admin@example.com" } as const;
const KEY = Buffer.alloc(32, 17).toString("base64url");
const PEPPER = Buffer.alloc(32, 29).toString("base64url");

type MxMode = "ok" | "conflict" | "rate" | "create-timeout" | "reset-timeout" | "delete-timeout";

describe.sequential("three Worker integration", () => {
  let server: TestHarness;
  let core: ReturnType<TestHarness["getWorker"]>;
  let generator: ReturnType<TestHarness["getWorker"]>;
  let admin: ReturnType<TestHarness["getWorker"]>;
  let mx: { setMode(mode: MxMode): Promise<void>; getWrites(): Promise<Array<{ method: string; path: string; body: Record<string, unknown> }>> };
  let db: D1Database;
  let issueAccess: Awaited<ReturnType<typeof accessFixture>>["issue"];
  let jwks: Awaited<ReturnType<typeof accessFixture>>["jwks"];

  beforeAll(async () => {
    const access = await accessFixture();
    issueAccess = access.issue;
    jwks = access.jwks;
    const outboundFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/cdn-cgi/access/certs") return Response.json(jwks);
      throw new Error(`Unexpected outbound request: ${request.method} ${request.url}`);
    };

    server = createTestHarness({
      workers: [
        {
          configPath: "workers/core/wrangler.jsonc",
          bindingOverrides: { MXROUTE_FETCH: "integration-mxroute" },
          secrets: {
            MXROUTE_SERVER: "mail.test", MXROUTE_USERNAME: "owner",
            MXROUTE_API_KEY: "mx-secret", TOKEN_PEPPER: PEPPER, ENC_KEY_V1: KEY,
          },
        },
        { configPath: "workers/generator/wrangler.jsonc", bindingOverrides: { CORE: "bitwarden-mxroute-core" } },
        {
          configPath: "workers/admin/wrangler.jsonc",
          bindingOverrides: { CORE: "bitwarden-mxroute-core" },
          vars: {
            ACCESS_TEAM_DOMAIN: "https://team.cloudflareaccess.com", ACCESS_AUD: "admin-aud",
            ADMIN_EMAILS: "admin@example.com", ADMIN_ORIGIN: ORIGIN,
          },
        },
        { configPath: "tests/integration/mxroute.wrangler.jsonc" },
      ],
    });
    await server.listen();
    vi.spyOn(globalThis, "fetch").mockImplementation(outboundFetch);
    core = server.getWorker("bitwarden-mxroute-core");
    generator = server.getWorker("bitwarden-mxroute-generator");
    admin = server.getWorker("bitwarden-mxroute-admin");
    mx = await server.getWorker("integration-mxroute").getExport() as unknown as typeof mx;
    await core.applyD1Migrations("DB" as never);
    db = (await core.getEnv() as CoreEnv).DB;
    const rpc = await core.getExport() as unknown as {
      syncDomains(identity: typeof ADMIN): Promise<unknown>;
      setDefaultDomain(identity: typeof ADMIN, domain: string): Promise<unknown>;
    };
    await rpc.syncDomains(ADMIN);
    await rpc.setDefaultDomain(ADMIN, "example.com");
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    await server?.close();
  });

  it("creates through Generator, keeps plaintext out of D1, and completes the Access plus CSRF Admin lifecycle", async () => {
    const { rawToken } = await createToken("bitwarden-primary");
    const response = await generate(rawToken);
    expect(response.status).toBe(201);
    const alias = await response.json() as { email: string };
    expect(alias.email).toMatch(/^[23456789abcdefghjkmnpqrstuvwxyz]{12}@example\.com$/);
    expect(JSON.stringify(alias)).not.toContain("password");
    const create = await lastWrite("POST");
    expect(create?.body.quota, JSON.stringify(await mx.getWrites())).toBe(100);
    expect(create?.body.password).toHaveLength(18);
    const firstPassword = String(create?.body.password);
    await expectNoPlaintext(firstPassword);

    const session = await adminRequest("/api/session");
    expect(session.status).toBe(200);
    const { csrfToken } = await session.json() as { csrfToken: string };
    const cookie = session.headers.get("set-cookie")!.split(";")[0]!;
    const list = await adminRequest("/api/mailboxes");
    const page = await list.json() as { items: Array<{ publicId: string; email: string }> };
    expect(page.items.some((item) => item.email === alias.email)).toBe(true);
    const mailboxRow = page.items.find((item) => item.email === alias.email)!;
    const reveal = await adminMutation(`/api/mailboxes/${mailboxRow.publicId}/reveal`, "POST", {}, csrfToken, cookie);
    expect(reveal.status).toBe(200);
    expect((await reveal.json() as { password: string }).password).toBe(firstPassword);
    const reset = await adminMutation(`/api/mailboxes/${mailboxRow.publicId}/reset`, "POST", {}, csrfToken, cookie);
    expect(reset.status).toBe(200);
    const secondPassword = (await reset.json() as { password: string }).password;
    expect(secondPassword).toHaveLength(18);
    expect(secondPassword).not.toBe(firstPassword);
    expect((await lastWrite("PATCH"))?.body.password).toBe(secondPassword);
    await expectNoPlaintext(secondPassword);
    const deleted = await adminMutation(`/api/mailboxes/${mailboxRow.publicId}`, "DELETE", { confirmationEmail: alias.email }, csrfToken, cookie);
    expect(deleted.status).toBe(200);
    expect((await lastWrite("DELETE"))?.path).toContain(encodeURIComponent(alias.email.split("@")[0]!));
    expect(await db.prepare("SELECT COUNT(*) count FROM mailboxes WHERE public_id=?").bind(mailboxRow.publicId).first("count")).toBe(0);
    await revokeTokenByRawName("bitwarden-primary");
  });

  it("maps conflict, provider throttling, revoked credentials, and forged Access assertions without credential leakage", async () => {
    const created = await createToken("failure-token");
    for (const [failure, expected] of [["conflict", 503], ["rate", 503]] as const) {
      await setMxMode(failure);
      const response = await generate(created.rawToken);
      expect(response.status).toBe(expected);
      const text = await response.text();
      expect(text).not.toContain(created.rawToken);
      expect(text).not.toMatch(/["']password["']\s*:/i);
      const attemptedPassword = String((await lastWrite("POST"))?.body.password ?? "");
      expect(attemptedPassword).toHaveLength(18);
      expect(text).not.toContain(attemptedPassword);
    }
    await setMxMode("ok");
    const rpc = await core.getExport() as unknown as { revokeApiToken(identity: typeof ADMIN, id: string): Promise<unknown> };
    await rpc.revokeApiToken(ADMIN, created.id);
    expect((await generate(created.rawToken)).status).toBe(401);
    const forged = `${await issueAccess()}.forged`;
    const response = await admin.fetch("/api/mailboxes", { headers: { "Cf-Access-Jwt-Assertion": forged } });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "UNAUTHORIZED" });
  });

  it("recovers an upstream-created mailbox after the D1 activation transition fails and repeated cron runs remain idempotent", async () => {
    const { rawToken } = await createToken("activation-failure");
    await db.prepare(`CREATE TRIGGER integration_fail_activation BEFORE UPDATE OF status ON mailboxes
      WHEN NEW.status='active' BEGIN SELECT RAISE(ABORT,'INJECTED_ACTIVATION_FAILURE'); END`).run();
    const response = await generate(rawToken);
    expect(response.status).toBe(503);
    const responseText = await response.text();
    const upstreamPassword = String((await lastWrite("POST"))?.body.password ?? "");
    expect(upstreamPassword).toHaveLength(18);
    expect(responseText).not.toContain(upstreamPassword);
    await expectNoPlaintext(upstreamPassword);
    await db.prepare("DROP TRIGGER integration_fail_activation").run();
    const pending = await db.prepare("SELECT public_id,email FROM mailboxes WHERE status='pending' ORDER BY id DESC LIMIT 1")
      .first<{ public_id: string; email: string }>();
    expect(pending).not.toBeNull();
    await db.prepare("UPDATE mailboxes SET updated_at='2000-01-01T00:00:00.000Z' WHERE public_id=?").bind(pending!.public_id).run();
    await core.scheduled({ cron: "*/5 * * * *", scheduledTime: new Date() });
    await core.scheduled({ cron: "*/5 * * * *", scheduledTime: new Date() });
    expect(await db.prepare("SELECT status FROM mailboxes WHERE public_id=?").bind(pending!.public_id).first("status")).toBe("active");
    await assertRecoverablePasswords();
    await revokeTokenByRawName("activation-failure");
  });

  it("preserves recoverable state across create, reset, and delete timeouts", async () => {
    const { rawToken } = await createToken("timeout-token");
    await setMxMode("create-timeout");
    const timedOut = await generate(rawToken);
    expect(timedOut.status).toBe(503);
    const createTimeoutBody = await timedOut.text();
    const createdPassword = String((await lastWrite("POST"))?.body.password ?? "");
    expect(createdPassword).toHaveLength(18);
    expect(createTimeoutBody).not.toContain(createdPassword);
    await expectNoPlaintext(createdPassword);
    const pending = await db.prepare("SELECT public_id,email FROM mailboxes WHERE status='pending' ORDER BY id DESC LIMIT 1")
      .first<{ public_id: string; email: string }>();
    await db.prepare("UPDATE mailboxes SET updated_at='2000-01-01T00:00:00.000Z' WHERE public_id=?").bind(pending!.public_id).run();
    await setMxMode("ok");
    await core.scheduled({ cron: "*/5 * * * *", scheduledTime: new Date() });
    expect(await db.prepare("SELECT status FROM mailboxes WHERE public_id=?").bind(pending!.public_id).first("status")).toBe("active");

    const { csrfToken, cookie } = await csrf();
    await setMxMode("reset-timeout");
    const reset = await adminMutation(`/api/mailboxes/${pending!.public_id}/reset`, "POST", {}, csrfToken, cookie);
    expect(reset.status).toBe(503);
    const resetBody = await reset.text();
    const candidatePassword = String((await lastWrite("PATCH"))?.body.password ?? "");
    expect(candidatePassword).toHaveLength(18);
    expect(resetBody).not.toContain(candidatePassword);
    await expectNoPlaintext(candidatePassword);
    expect(await db.prepare("SELECT status FROM mailboxes WHERE public_id=?").bind(pending!.public_id).first("status")).toBe("reset_unknown");
    await assertRecoverablePasswords();
    await db.prepare("UPDATE mailboxes SET updated_at='2000-01-01T00:00:00.000Z',recovery_next_at=NULL WHERE public_id=?").bind(pending!.public_id).run();
    await setMxMode("ok");
    await core.scheduled({ cron: "*/5 * * * *", scheduledTime: new Date() });
    expect(await db.prepare("SELECT status FROM mailboxes WHERE public_id=?").bind(pending!.public_id).first("status")).toBe("active");

    await setMxMode("delete-timeout");
    const deleted = await adminMutation(`/api/mailboxes/${pending!.public_id}`, "DELETE", { confirmationEmail: pending!.email }, csrfToken, cookie);
    expect(deleted.status).toBe(200);
    expect(await db.prepare("SELECT COUNT(*) count FROM mailboxes WHERE public_id=?").bind(pending!.public_id).first("count")).toBe(0);
    await setMxMode("ok");
    await assertRecoverablePasswords();
  });

  async function createToken(name: string): Promise<{ id: string; rawToken: string }> {
    const rpc = await core.getExport() as unknown as {
      createApiToken(identity: typeof ADMIN, name: string): Promise<{ id: string; rawToken: string }>;
    };
    return rpc.createApiToken(ADMIN, name);
  }

  async function revokeTokenByRawName(name: string): Promise<void> {
    const row = await db.prepare("SELECT id FROM api_tokens WHERE name=? AND revoked_at IS NULL").bind(name).first<{ id: string }>();
    if (row !== null) {
      const rpc = await core.getExport() as unknown as { revokeApiToken(identity: typeof ADMIN, id: string): Promise<unknown> };
      await rpc.revokeApiToken(ADMIN, row.id);
    }
  }

  async function generate(token: string) {
    return generator.fetch("/api/alias/random/new?hostname=ignored.invalid&mode=ignored", {
      method: "POST", headers: { Authentication: token, "CF-Connecting-IP": `192.0.2.${Math.floor(Math.random() * 200) + 1}` },
    });
  }

  async function setMxMode(value: MxMode): Promise<void> {
    await mx.setMode(value);
  }

  async function lastWrite(method: string): Promise<{ method: string; path: string; body: Record<string, unknown> } | undefined> {
    return (await mx.getWrites()).findLast((request) => request.method === method);
  }

  async function adminRequest(path: string) {
    return admin.fetch(path, { headers: { "Cf-Access-Jwt-Assertion": await issueAccess() } });
  }

  async function csrf(): Promise<{ csrfToken: string; cookie: string }> {
    const response = await adminRequest("/api/session");
    return {
      csrfToken: (await response.json() as { csrfToken: string }).csrfToken,
      cookie: response.headers.get("set-cookie")!.split(";")[0]!,
    };
  }

  async function adminMutation(path: string, method: string, body: object, csrfToken: string, cookie: string) {
    return admin.fetch(path, {
      method,
      headers: {
        "Cf-Access-Jwt-Assertion": await issueAccess(), Origin: ORIGIN,
        "X-CSRF-Token": csrfToken, Cookie: cookie, "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  }

  async function expectNoPlaintext(password: string): Promise<void> {
    const tables = ["mailboxes", "api_tokens", "domains", "settings", "creation_counters", "audit_events"];
    for (const table of tables) {
      const rows = await db.prepare(`SELECT * FROM ${table}`).all<Record<string, unknown>>();
      expect(JSON.stringify(rows.results)).not.toContain(password);
    }
    const passwordHex = Array.from(new TextEncoder().encode(password), (byte) => byte.toString(16).padStart(2, "0"))
      .join("").toUpperCase();
    const blobs = await db.prepare(`SELECT hex(password_ciphertext) current_ciphertext,
      hex(password_nonce) current_nonce, hex(next_password_ciphertext) next_ciphertext,
      hex(next_password_nonce) next_nonce FROM mailboxes`).all<Record<string, string>>();
    expect(JSON.stringify(blobs.results).toUpperCase()).not.toContain(passwordHex);
  }

  async function assertRecoverablePasswords(): Promise<void> {
    const result = await db.prepare(`SELECT status,password_ciphertext,password_nonce,
      next_password_ciphertext,next_password_nonce FROM mailboxes WHERE status IN ('active','pending','resetting','reset_unknown')`).all<{
        status: string; password_ciphertext: unknown; password_nonce: unknown;
        next_password_ciphertext: unknown; next_password_nonce: unknown;
      }>();
    for (const row of result.results) {
      expect(row.password_ciphertext).not.toBeNull();
      expect(row.password_nonce).not.toBeNull();
      if (row.status === "resetting" || row.status === "reset_unknown") {
        expect(row.next_password_ciphertext).not.toBeNull();
        expect(row.next_password_nonce).not.toBeNull();
      }
    }
  }
});
