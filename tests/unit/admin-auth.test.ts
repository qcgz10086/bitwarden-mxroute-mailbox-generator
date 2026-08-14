import { createLocalJWKSet, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { AdminIdentity } from "../../packages/contracts/src/index";
import { accessFixture } from "../fixtures/access-key";
import { validateAccess } from "../../workers/admin/src/access";
import { createAdminHandler, type AdminEnv } from "../../workers/admin/src/index";

const ORIGIN = "https://admin.example.com";
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
  };
}

function setup() {
  const CORE = coreDouble();
  const ASSETS = { fetch: vi.fn(async () => new Response("asset", { headers: { "Content-Type": "text/html" } })) };
  const env = { CORE, ASSETS, ACCESS_TEAM_DOMAIN: "https://team.cloudflareaccess.com", ACCESS_AUD: "admin-aud", ADMIN_EMAILS: "admin@example.com", ADMIN_ORIGIN: ORIGIN } as unknown as AdminEnv;
  const handler = createAdminHandler({ jwks: createLocalJWKSet(fixture.jwks) });
  return { CORE, ASSETS, fetch: (request: Request) => handler.fetch(request, env) };
}

async function session(setupResult: ReturnType<typeof setup>) {
  const response = await setupResult.fetch(authRequest());
  const cookie = response.headers.get("Set-Cookie")!;
  const csrf = (await response.json() as { csrfToken: string }).csrfToken;
  return { cookie: cookie.split(";")[0]!, csrf };
}

async function mutate(s: ReturnType<typeof setup>, path: string, method: string, body?: unknown, overrides: Record<string, string> = {}) {
  const { cookie, csrf } = await session(s);
  const init: RequestInit = { method, headers: { Origin: ORIGIN, Cookie: cookie, "X-CSRF-Token": csrf, "Content-Type": "application/json", ...overrides } };
  if (body !== undefined) init.body = JSON.stringify(body);
  return s.fetch(authRequest(path, init));
}

describe("Admin worker", () => {
  it("authenticates static assets before fetching and applies security headers", async () => {
    const s = setup();
    expect((await s.fetch(new Request(`${ORIGIN}/`))).status).toBe(401);
    expect(s.ASSETS.fetch).not.toHaveBeenCalled();
    for (const path of ["/", "/app.js", "/app.css"]) {
      const response = await s.fetch(authRequest(path));
      expect(await response.text()).toBe("asset");
      expect(response.headers.get("Content-Security-Policy")).toContain("frame-ancestors 'none'");
      expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
      expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
      expect(response.headers.get("Cache-Control")).toBe("no-store");
    }
  });
  it("issues a host-only 32-byte CSRF cookie", async () => {
    const s = setup(); const response = await s.fetch(authRequest()); const data = await response.json() as { csrfToken: string };
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
    ]) expect((await s.fetch(authRequest("/api/domains/sync", { method: "POST", headers }))).status).toBe(403);
  });
  it("maps all read routes with typed, capped query input and identity", async () => {
    const s = setup();
    const mailboxCursor = btoa(JSON.stringify({ sort:"email", direction:"asc", value:"a@example.com", publicId:"m1" }));
    const auditCursor = btoa(JSON.stringify({ createdAt:"2026-08-13T00:00:00.000Z", id:"a1" }));
    expect((await s.fetch(authRequest(`/api/mailboxes?limit=100&status=active&domain=example.com&sort=email&direction=asc&search=a&cursor=${encodeURIComponent(mailboxCursor)}`))).status).toBe(200);
    expect(s.CORE.pageMailboxes).toHaveBeenCalledWith({ subject: "access-user", email: "admin@example.com" }, { limit: 100, status: "active", domain: "example.com", sort:"email", direction:"asc", search:"a", cursor:mailboxCursor });
    for (const [path, spy] of [["/api/domains", s.CORE.listDomains], ["/api/settings", s.CORE.getSettings], ["/api/tokens", s.CORE.listApiTokens], [`/api/audit?limit=2&cursor=${encodeURIComponent(auditCursor)}`, s.CORE.pageAudit]] as const) {
      expect((await s.fetch(authRequest(path))).status).toBe(200); expect(spy).toHaveBeenCalled();
    }
    for (const path of ["/api/mailboxes?limit=101", "/api/mailboxes?limit=NaN", "/api/mailboxes?status=nope", "/api/mailboxes?domain=bad%20domain", "/api/mailboxes?sort=nope", "/api/mailboxes?direction=nope", "/api/audit?limit=0", "/api/settings?unexpected=1"]) expect((await s.fetch(authRequest(path))).status).toBe(400);
  });
  it("rejects structurally malformed mailbox and audit cursors before Core RPC", async () => {
    const s = setup();
    for (const path of ["/api/mailboxes?cursor=not-base64", `/api/mailboxes?cursor=${btoa("{}")}`, "/api/audit?cursor=not-base64", `/api/audit?cursor=${btoa("{}")}`]) {
      expect((await s.fetch(authRequest(path))).status).toBe(400);
    }
    expect(s.CORE.pageMailboxes).not.toHaveBeenCalled();
    expect(s.CORE.pageAudit).not.toHaveBeenCalled();
  });
  it("maps every mutation and never caches password responses", async () => {
    const s = setup(); const id: AdminIdentity = { subject: "access-user", email: "admin@example.com" };
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
  it("rejects missing confirmations, unexpected/invalid values, oversized bodies, methods and paths", async () => {
    const s = setup();
    for (const [path,method,body] of [["/api/mailboxes/m1","DELETE",{}],["/api/domains/default","PUT",{domain:"bad domain"}],["/api/settings","PUT",{prefixLength:13}],["/api/settings","PUT",{evil:true}],["/api/tokens","POST",{name:""}],["/api/mailboxes/m1/note","PUT",{note:"x".repeat(501)}],["/api/mailboxes/m1/note","PUT",{unexpected:true}]] as const) expect((await mutate(s,path,method,body)).status).toBe(400);
    expect((await mutate(s,"/api/tokens","POST",{ name:"x".repeat(70_000) })).status).toBe(413);
    expect((await s.fetch(authRequest("/api"))).status).toBe(404);
    expect((await s.fetch(authRequest("/api/nope"))).status).toBe(404);
    expect((await s.fetch(authRequest("/api/mailboxes", { method:"PATCH" }))).status).toBe(405);
  });
  it("returns stable non-leaking errors", async () => {
    const s=setup(); s.CORE.pageMailboxes.mockRejectedValueOnce(new Error("D1 password upstream stack"));
    const response=await s.fetch(authRequest("/api/mailboxes")); expect(response.status).toBe(500);
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
    s.CORE.pageMailboxes.mockRejectedValueOnce(Object.assign(new Error("password=secret"), { code:"EVIL", requestId:"bad request id", retryable:true }));
    const response=await s.fetch(authRequest("/api/mailboxes"));
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error:"INTERNAL_ERROR" });
  });
});
