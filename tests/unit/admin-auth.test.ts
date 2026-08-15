import { createLocalJWKSet, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { AdminIdentity } from "../../packages/contracts/src/index";
import { accessFixture } from "../fixtures/access-key";
import { validateAccess } from "../../workers/admin/src/access";
import { createAdminHandler, type AdminEnv } from "../../workers/admin/src/index";

const ORIGIN = "https://admin.example.com";
const SESSION_KEY = "A".repeat(44);
let fixture: Awaited<ReturnType<typeof accessFixture>>;
let token: string;

beforeAll(async () => {
  fixture = await accessFixture();
  token = await fixture.issue();
});

function authRequest(path = "/api/session", init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("Cf-Access-Jwt-Assertion", token);
  return new Request(`${ORIGIN}${path}`, { ...init, headers });
}

describe("Access JWT validation", () => {
  const config = () => ({ teamDomain: "https://team.cloudflareaccess.com", audience: "admin-aud", adminEmails: " admin@example.com , other@example.com " });
  it("returns only the normalized subject and email", async () => {
    await expect(validateAccess(authRequest(), config(), createLocalJWKSet(fixture.jwks)))
      .resolves.toEqual({ subject: "access-user", email: "admin@example.com" });
  });
  it("creates one remote JWKS resolver per normalized team domain", async () => {
    const remoteToken = await fixture.issue({}, { issuer: "https://cache.cloudflareaccess.com" });
    const request = new Request(ORIGIN, { headers: { "Cf-Access-Jwt-Assertion": remoteToken } });
    const factory = vi.fn(() => createLocalJWKSet(fixture.jwks));
    const cachedConfig = { teamDomain: "https://cache.cloudflareaccess.com/", audience: "admin-aud", adminEmails: "admin@example.com" };
    await validateAccess(request, cachedConfig, undefined, factory);
    await validateAccess(request, cachedConfig, undefined, factory);
    expect(factory).toHaveBeenCalledTimes(1);
  });
  it("rejects missing, invalid, wrongly-scoped and incomplete assertions", async () => {
    const verify = (request: Request) => validateAccess(request, config(), createLocalJWKSet(fixture.jwks));
    await expect(verify(new Request(ORIGIN))).rejects.toMatchObject({ status: 401 });
    const { privateKey } = await generateKeyPair("RS256");
    const bad = await new SignJWT({ email: "admin@example.com" }).setProtectedHeader({ alg: "RS256", kid: "test-key" }).setSubject("x").setIssuer(config().teamDomain).setAudience("admin-aud").setExpirationTime("5m").sign(privateKey);
    await expect(verify(new Request(ORIGIN, { headers: { "Cf-Access-Jwt-Assertion": bad } }))).rejects.toMatchObject({ status: 401 });
    for (const badToken of [
      await fixture.issue({}, { issuer: "https://evil.example" }),
      await fixture.issue({}, { audience: "wrong" }),
      await fixture.issue({}, { expires: "-1s" }),
      await fixture.issue({ email: undefined }),
      await fixture.issue({ email: "intruder@example.com" }),
    ]) await expect(verify(new Request(ORIGIN, { headers: { "Cf-Access-Jwt-Assertion": badToken } }))).rejects.toMatchObject({ status: 401 });
  });
});

function coreDouble() {
  let passwordVersion = 1;
  return {
    pageMailboxes: vi.fn(async () => ({ items: [], nextCursor: null })),
    revealPassword: vi.fn(async () => ({ password: "Secret123", requestId: "r1" })),
    resetPassword: vi.fn(async () => ({ password: "NewSecret123", requestId: "r2" })),
    deleteMailbox: vi.fn(async () => ({ requestId: "r3" })),
    setMailboxNote: vi.fn(async () => ({ requestId: "r8" })),
    confirmMailbox: vi.fn(async () => ({ requestId: "r9" })),
    listDomains: vi.fn(async () => []), syncDomains: vi.fn(async () => []),
    setDefaultDomain: vi.fn(async () => ({ requestId: "r4" })),
    getSettings: vi.fn(async () => ({ defaultDomain: null, mailboxQuotaMb: 100, prefixLength: 12, dailyCreationLimit: 30, totalManagedLimit: 500, generationEnabled: true })),
    updateSettings: vi.fn(async () => ({ requestId: "r5" })),
    listApiTokens: vi.fn(async () => []), createApiToken: vi.fn(async () => ({ id: "t1", rawToken: "raw", requestId: "r6", expiresAt: "2026-08-13T10:20:00.000Z" })),
    acknowledgeApiToken: vi.fn(async () => ({ requestId: "r7" })),
    revokeApiToken: vi.fn(async () => ({ requestId: "r7" })),
    pageAudit: vi.fn(async () => ({ items: [], nextCursor: null })),
    isAdminPasswordSet: vi.fn(async () => false),
    verifyAdminPassword: vi.fn(async () => false),
    setAdminPassword: vi.fn(async () => ({ requestId: "r10", passwordVersion: ++passwordVersion })),
    getAdminPasswordVersion: vi.fn(async () => passwordVersion),
    recordLoginFailure: vi.fn(async () => undefined),
    isLoginBlocked: vi.fn(async () => false),
    clearLoginFailures: vi.fn(async () => undefined),
  };
}

function setup(overrides: Record<string, unknown> = {}) {
  const CORE = coreDouble();
  const ASSETS = { fetch: vi.fn(async () => new Response("asset", { headers: { "Content-Type": "text/html" } })) };
  const env = { CORE, ASSETS, ACCESS_TEAM_DOMAIN: "https://team.cloudflareaccess.com", ACCESS_AUD: "admin-aud", ADMIN_EMAILS: "admin@example.com", ADMIN_ORIGIN: ORIGIN, ADMIN_SESSION_KEY: SESSION_KEY, ...overrides } as unknown as AdminEnv;
  const handler = createAdminHandler({ jwks: createLocalJWKSet(fixture.jwks) });
  return { CORE, ASSETS, fetch: (request: Request) => handler.fetch(request, env) };
}

async function session(setupResult: ReturnType<typeof setup>) {
  const sessionCookie = await login(setupResult);
  const sessionResponse = await setupResult.fetch(authRequest("/api/session", { headers: { Cookie: sessionCookie } }));
  const csrf = (await sessionResponse.json() as { csrfToken: string }).csrfToken;
  const csrfCookie = sessionResponse.headers.get("Set-Cookie")!.split(";")[0]!;
  return { cookie: `${sessionCookie}; ${csrfCookie}`, sessionCookie, csrf };
}

async function login(setupResult: ReturnType<typeof setup>): Promise<string> {
  setupResult.CORE.verifyAdminPassword.mockResolvedValue(true);
  const login = await setupResult.fetch(authRequest("/api/auth/login", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ password: "password123" }) }));
  expect(login.status).toBe(200);
  return login.headers.get("Set-Cookie")!.split(";")[0]!;
}

async function mutate(s: ReturnType<typeof setup>, path: string, method: string, body?: unknown, overrides: Record<string, string> = {}) {
  const { cookie, csrf } = await session(s);
  const init: RequestInit = { method, headers: { Origin: ORIGIN, Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/json", ...overrides } };
  if (body !== undefined) init.body = JSON.stringify(body);
  return s.fetch(authRequest(path, init));
}

describe("Admin worker", () => {
  it("serves the login page when the password gate is enabled and applies security headers", async () => {
    const s = setup({ ADMIN_SESSION_KEY: SESSION_KEY });
    const response = await s.fetch(new Request(`${ORIGIN}/`));
    expect(response.status).toBe(200);
    expect((await response.text())).toContain("auth-form");
    expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect((await s.fetch(authRequest("/api/mailboxes"))).status).toBe(401);
  });
  it("issues a host-only 32-byte CSRF cookie", async () => {
    const s = setup(); const sessionCookie = await login(s);
    const response = await s.fetch(authRequest("/api/session", { headers: { Cookie: sessionCookie } }));
    const data = await response.json() as { csrfToken: string };
    expect(Buffer.from(data.csrfToken, "base64url")).toHaveLength(32);
    const cookie = response.headers.get("Set-Cookie")!;
    expect(cookie).toContain(`csrf=${data.csrfToken}`); expect(cookie).toContain("Secure"); expect(cookie).toContain("SameSite=Strict"); expect(cookie).toContain("Path=/"); expect(cookie).not.toContain("Domain=");
  });
  it("requires exact origin, cookie and header for every mutation", async () => {
    const s = setup(); const { cookie, csrf } = await session(s);
    for (const headers of [
      { Cookie: cookie, "X-CSRF-Token": csrf },
      { Origin: "https://evil.example", Cookie: cookie, "X-CSRF-Token": csrf },
      { Origin: ORIGIN, "X-CSRF-Token": csrf },
      { Origin: ORIGIN, Cookie: cookie, "X-CSRF-Token": "wrong" },
    ]) expect((await s.fetch(authRequest("/api/domains/sync", { method: "POST", headers }))).status).toBe(headers.Cookie === undefined ? 401 : 403);
  });
  it("maps all read routes with typed, capped query input and identity", async () => {
    const s = setup();
    const { cookie } = await session(s);
    const read = (path: string) => s.fetch(authRequest(path, { headers: { Cookie: cookie } }));
    const mailboxCursor = btoa(JSON.stringify({ sort:"email", direction:"asc", value:"a@example.com", publicId:"m1" }));
    const auditCursor = btoa(JSON.stringify({ createdAt:"2026-08-13T00:00:00.000Z", id:"a1" }));
    expect((await read(`/api/mailboxes?limit=100&status=active&domain=example.com&sort=email&direction=asc&search=a&cursor=${encodeURIComponent(mailboxCursor)}`)).status).toBe(200);
    expect(s.CORE.pageMailboxes).toHaveBeenCalledWith({ subject: expect.stringMatching(/^password-admin:v1:/), email: "password-admin@local" }, { limit: 100, status: "active", domain: "example.com", sort:"email", direction:"asc", search:"a", cursor:mailboxCursor });
    for (const [path, spy] of [["/api/domains", s.CORE.listDomains], ["/api/settings", s.CORE.getSettings], ["/api/tokens", s.CORE.listApiTokens], [`/api/audit?limit=2&cursor=${encodeURIComponent(auditCursor)}`, s.CORE.pageAudit]] as const) {
      expect((await read(path)).status).toBe(200); expect(spy).toHaveBeenCalled();
    }
    for (const path of ["/api/mailboxes?limit=101", "/api/mailboxes?limit=NaN", "/api/mailboxes?status=nope", "/api/mailboxes?domain=bad%20domain", "/api/mailboxes?sort=nope", "/api/mailboxes?direction=nope", "/api/audit?limit=0", "/api/settings?unexpected=1"]) expect((await read(path)).status).toBe(400);
  });
  it("rejects structurally malformed mailbox and audit cursors before Core RPC", async () => {
    const s = setup();
    const { cookie } = await session(s);
    for (const path of ["/api/mailboxes?cursor=not-base64", `/api/mailboxes?cursor=${btoa("{}")}`, "/api/audit?cursor=not-base64", `/api/audit?cursor=${btoa("{}")}`]) {
      expect((await s.fetch(authRequest(path, { headers: { Cookie: cookie } }))).status).toBe(400);
    }
    expect(s.CORE.pageMailboxes).not.toHaveBeenCalled();
    expect(s.CORE.pageAudit).not.toHaveBeenCalled();
  });
  it("maps every mutation and never caches password responses", async () => {
    const s = setup(); const id: AdminIdentity = { subject: expect.stringMatching(/^password-admin:v1:/), email: "password-admin@local" } as unknown as AdminIdentity;
    const cases: [string,string,unknown,ReturnType<typeof vi.fn>][] = [
      ["/api/mailboxes/m1/reveal","POST",{},s.CORE.revealPassword], ["/api/mailboxes/m1/reset","POST",{},s.CORE.resetPassword], ["/api/mailboxes/m1","DELETE",{ confirmationEmail:" a@example.com " },s.CORE.deleteMailbox],
      ["/api/domains/sync","POST",{},s.CORE.syncDomains], ["/api/domains/default","PUT",{ domain:"example.com" },s.CORE.setDefaultDomain], ["/api/settings","PUT",{ mailboxQuotaMb:100 },s.CORE.updateSettings],
      ["/api/mailboxes/m1/note","PUT",{ note:" keepalive " },s.CORE.setMailboxNote],
      ["/api/mailboxes/m1/confirm","POST",{},s.CORE.confirmMailbox],
      ["/api/tokens","POST",{ name:"phone", operationId:"operation-phone-0001" },s.CORE.createApiToken], ["/api/tokens/t1","DELETE",{},s.CORE.revokeApiToken],
      ["/api/tokens/t1/acknowledge","POST",{ operationId:"operation-phone-0001" },s.CORE.acknowledgeApiToken],
    ];
    for (const [path,method,body,spy] of cases) { const response=await mutate(s,path,method,body); expect(response.status).toBe(200); expect(spy).toHaveBeenCalled(); expect(response.headers.get("Cache-Control")).toBe("no-store"); }
    expect(s.CORE.deleteMailbox).toHaveBeenCalledWith(id,"m1"," a@example.com ");
    expect(s.CORE.revealPassword).toHaveBeenCalledWith(id,"m1");
    expect(s.CORE.resetPassword).toHaveBeenCalledWith(id,"m1");
    expect(s.CORE.setMailboxNote).toHaveBeenCalledWith(id,"m1","keepalive");
    expect(s.CORE.confirmMailbox).toHaveBeenCalledWith(id,"m1");
    expect(s.CORE.syncDomains).toHaveBeenCalledWith(id);
    expect(s.CORE.setDefaultDomain).toHaveBeenCalledWith(id,"example.com");
    expect(s.CORE.updateSettings).toHaveBeenCalledWith(id,{ mailboxQuotaMb:100 });
    expect(s.CORE.createApiToken).toHaveBeenCalledWith(id,"phone","operation-phone-0001");
    expect(s.CORE.revokeApiToken).toHaveBeenCalledWith(id,"t1");
  });

  it("gates the API behind a password session and issues one on valid login", async () => {
    const s = setup({ ADMIN_SESSION_KEY: SESSION_KEY });
    s.CORE.verifyAdminPassword.mockResolvedValue(true);

    const blocked = await s.fetch(authRequest("/api/mailboxes"));
    expect(blocked.status).toBe(401);
    expect(await blocked.json()).toEqual({ error: "ADMIN_LOGIN_REQUIRED" });

    const login = await s.fetch(authRequest("/api/auth/login", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ password: "password123" }) }));
    expect(login.status).toBe(200);
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    expect(cookie).toMatch(/^admin_session=/);

    const ok = await s.fetch(authRequest("/api/mailboxes", { headers: { Cookie: cookie } }));
    expect(ok.status).toBe(200);
    expect(s.CORE.verifyAdminPassword).toHaveBeenCalledWith("password123");
  });

  it("rejects login when Turnstile is configured but the token fails", async () => {
    const s = setup({ ADMIN_SESSION_KEY: SESSION_KEY, TURNSTILE_SECRET_KEY: "turnstile-secret" });
    const response = await s.fetch(authRequest("/api/auth/login", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ password: "password123", turnstileToken: "stale-token" }) }));
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "INVALID_TURNSTILE" });
    expect(s.CORE.verifyAdminPassword).not.toHaveBeenCalled();
  });

  it("fails closed when ADMIN_SESSION_KEY is missing", async () => {
    const s = setup({ ADMIN_SESSION_KEY: undefined });
    const status = await s.fetch(authRequest("/api/auth/status"));
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ enabled: false, authenticated: false });
    const login = await s.fetch(authRequest("/api/auth/login", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ password: "password123" }) }));
    expect(login.status).toBe(503);
    expect(await login.json()).toEqual({ error: "SERVER_MISCONFIGURED" });
    expect((await s.fetch(authRequest("/api/mailboxes"))).status).toBe(503);
  });

  it("rate limits password login and clears failures on success", async () => {
    const s = setup();
    s.CORE.verifyAdminPassword.mockResolvedValue(false);
    const attempt = () => s.fetch(authRequest("/api/auth/login", {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json", "CF-Connecting-IP": "192.0.2.44" },
      body: JSON.stringify({ password: "wrong" }),
    }));
    for (let attemptNumber = 0; attemptNumber < 5; attemptNumber += 1) {
      expect((await attempt()).status).toBe(401);
    }
    expect(s.CORE.recordLoginFailure).toHaveBeenCalledTimes(10);
    s.CORE.isLoginBlocked.mockResolvedValue(true);
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(await blocked.json()).toEqual({ error: "RATE_LIMITED" });
    s.CORE.isLoginBlocked.mockResolvedValue(false);
    s.CORE.verifyAdminPassword.mockResolvedValue(true);
    expect((await attempt()).status).toBe(200);
    expect(s.CORE.clearLoginFailures).toHaveBeenCalledWith("global");
    expect(s.CORE.clearLoginFailures).toHaveBeenCalledWith("login:192.0.2.44");
  });

  it("resets the admin password through the Access-verified flow and issues a session", async () => {
    const s = setup({ ADMIN_SESSION_KEY: SESSION_KEY });
    const response = await s.fetch(authRequest("/api/auth/reset", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ newPassword: "NewPass123!" }) }));
    expect(response.status).toBe(200);
    expect(s.CORE.setAdminPassword).toHaveBeenCalledWith({ subject: "access-user", email: "admin@example.com" }, "NewPass123!");
    expect(response.headers.get("set-cookie")).toMatch(/admin_session=/);
  });
  it("invalidates old password sessions after an Access password reset", async () => {
    const s = setup({ ADMIN_SESSION_KEY: SESSION_KEY });
    const { sessionCookie } = await session(s);
    expect((await s.fetch(authRequest("/api/mailboxes", { headers: { Cookie: sessionCookie } }))).status).toBe(200);

    const reset = await s.fetch(authRequest("/api/auth/reset", { method: "POST", headers: { Origin: ORIGIN, "Content-Type": "application/json" }, body: JSON.stringify({ newPassword: "NewPass123!" }) }));
    expect(reset.status).toBe(200);
    const newSessionCookie = reset.headers.get("Set-Cookie")!.split(";")[0]!;

    expect((await s.fetch(authRequest("/api/mailboxes", { headers: { Cookie: sessionCookie } }))).status).toBe(401);
    expect((await s.fetch(authRequest("/api/mailboxes", { headers: { Cookie: newSessionCookie } }))).status).toBe(200);
  });
  it("rejects missing confirmations, unexpected/invalid values, oversized bodies, methods and paths", async () => {
    const s = setup();
    for (const [path,method,body] of [["/api/mailboxes/m1","DELETE",{}],["/api/domains/default","PUT",{domain:"bad domain"}],["/api/settings","PUT",{prefixLength:13}],["/api/settings","PUT",{evil:true}],["/api/tokens","POST",{name:""}],["/api/mailboxes/m1/note","PUT",{note:"x".repeat(501)}],["/api/mailboxes/m1/note","PUT",{unexpected:true}]] as const) expect((await mutate(s,path,method,body)).status).toBe(400);
    expect((await mutate(s,"/api/tokens","POST",{ name:"x".repeat(70_000) })).status).toBe(413);
    const { sessionCookie } = await session(s);
    expect((await s.fetch(authRequest("/api", { headers: { Cookie: sessionCookie } }))).status).toBe(404);
    expect((await s.fetch(authRequest("/api/nope", { headers: { Cookie: sessionCookie } }))).status).toBe(404);
    expect((await s.fetch(authRequest("/api/mailboxes", { method:"PATCH", headers: { Cookie: sessionCookie } }))).status).toBe(405);
  });
  it("returns stable non-leaking errors", async () => {
    const s=setup(); const { cookie } = await session(s);
    s.CORE.pageMailboxes.mockRejectedValueOnce(new Error("D1 password upstream stack"));
    const response=await s.fetch(authRequest("/api/mailboxes", { headers: { Cookie: cookie } })); expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error:"INTERNAL_ERROR" });
  });
  it.each([
    ["CONFIRMATION_MISMATCH", "/api/mailboxes/m1", "DELETE", { confirmationEmail:"x@example.com" }, 400, false],
    ["INVALID_STATE", "/api/mailboxes/m1/reveal", "POST", {}, 409, false],
    ["TOKEN_LIMIT", "/api/tokens", "POST", { name:"phone", operationId:"operation-phone-0001" }, 409, false],
    ["MX_TIMEOUT", "/api/mailboxes/m1/reset", "POST", {}, 503, true],
    ["NOT_FOUND", "/api/mailboxes/m1/reveal", "POST", {}, 404, false],
  ])("maps sanitized Core error %s", async (code,path,method,body,status,retryable) => {
    const s=setup();
    const methodName = code === "CONFIRMATION_MISMATCH" ? "deleteMailbox" : code === "TOKEN_LIMIT" ? "createApiToken" : code === "MX_TIMEOUT" ? "resetPassword" : "revealPassword";
    s.CORE[methodName].mockRejectedValueOnce(Object.assign(new Error("secret upstream D1 stack"), { name:"AdminError", code, requestId:"request-safe_123", retryable }));
    const response=await mutate(s,path,method,body);
    expect(response.status).toBe(status);
    expect(await response.json()).toEqual({ error:code, requestId:"request-safe_123", retryable });
  });
  it("collapses unknown or malformed Core errors without leaking fields", async () => {
    const s=setup();
    const { cookie } = await session(s);
    s.CORE.pageMailboxes.mockRejectedValueOnce(Object.assign(new Error("password=secret"), { code:"EVIL", requestId:"bad request id", retryable:true }));
    const response=await s.fetch(authRequest("/api/mailboxes", { headers: { Cookie: cookie } }));
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error:"INTERNAL_ERROR" });
  });
});
