import type { AdminIdentity, MailboxPage, MailboxStatus } from "../../../packages/contracts/src/index";
import type { JWTVerifyGetKey } from "jose";
import type {
  ApiTokenRecord, AuditPage, DomainRecord, PageAuditOptions, PageMailboxesOptions, RepositorySettings,
} from "../../core/src/repository";
import type { AdminSettingsPatch } from "../../core/src/service";
import { AccessError, validateAccess } from "./access";
import { createCsrfToken, csrfCookie, validateCsrf } from "./csrf";
import { LOGIN_PAGE, RESET_PAGE } from "./pages";

const BODY_LIMIT = 65_536;
const STATUSES: readonly MailboxStatus[] = [
  "registered", "pending", "activating", "active", "failed", "resetting", "reset_unknown", "deleting", "delete_failed",
];
const SECURITY_HEADERS: Readonly<Record<string,string>> = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; img-src 'self'; connect-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; frame-src 'self' https://challenges.cloudflare.com",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};
const CORE_ERROR_STATUS: Readonly<Record<string, number>> = {
  INVALID_INPUT: 400, INVALID_SETTINGS: 400, INACTIVE_DOMAIN: 400,
  CONFIRMATION_MISMATCH: 400, MX_CLIENT: 400,
  NOT_FOUND: 404, MX_NOT_FOUND: 404,
  INVALID_STATE: 409, TOKEN_LIMIT: 409, MX_CONFLICT: 409,
  MX_UNAUTHORIZED: 502, MX_INVALID_RESPONSE: 502,
  MX_RATE_LIMITED: 503, MX_SERVER: 503, MX_TIMEOUT: 503,
  INTERNAL_ERROR: 500,
};

export interface AdminCore {
  pageMailboxes(identity: AdminIdentity, options: PageMailboxesOptions): Promise<MailboxPage>;
  revealPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }>;
  resetPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }>;
  deleteMailbox(identity: AdminIdentity, publicId: string, confirmationEmail: string): Promise<{ requestId: string }>;
  setMailboxNote(identity: AdminIdentity, publicId: string, note: string | null): Promise<{ requestId: string }>;
  confirmMailbox(identity: AdminIdentity, publicId: string): Promise<{ requestId: string }>;
  listDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]>;
  syncDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]>;
  setDefaultDomain(identity: AdminIdentity, domain: string): Promise<{ requestId: string }>;
  getSettings(identity: AdminIdentity): Promise<RepositorySettings>;
  updateSettings(identity: AdminIdentity, patch: AdminSettingsPatch): Promise<RepositorySettings & { requestId: string }>;
  listApiTokens(identity: AdminIdentity): Promise<readonly ApiTokenRecord[]>;
  createApiToken(identity: AdminIdentity, name: string, operationId: string): Promise<{ id: string; rawToken: string; requestId: string; expiresAt: string }>;
  acknowledgeApiToken(identity: AdminIdentity, id: string, operationId: string): Promise<{ requestId: string }>;
  revokeApiToken(identity: AdminIdentity, id: string): Promise<{ requestId: string }>;
  pageAudit(identity: AdminIdentity, options: PageAuditOptions): Promise<AuditPage>;
  isAdminPasswordSet(): Promise<boolean>;
  verifyAdminPassword(password: string): Promise<boolean>;
  setAdminPassword(identity: AdminIdentity, newPassword: string): Promise<{ requestId: string; passwordVersion: number }>;
  getAdminPasswordVersion(): Promise<number>;
  recordLoginFailure(key: string, nowIso: string): Promise<void>;
  isLoginBlocked(key: string, nowIso: string): Promise<boolean>;
  clearLoginFailures(key: string): Promise<void>;
}
export interface AdminEnv {
  readonly CORE: AdminCore;
  readonly ASSETS: Fetcher;
  readonly ACCESS_TEAM_DOMAIN: string;
  readonly ACCESS_AUD: string;
  readonly ADMIN_EMAILS: string;
  readonly ADMIN_ORIGIN: string;
  readonly TURNSTILE_SITE_KEY?: string;
  readonly TURNSTILE_SECRET_KEY?: string;
  readonly ADMIN_SESSION_KEY: string;
}

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string) {
    super(code);
  }
}

export function createAdminHandler(dependencies: { jwks?: JWTVerifyGetKey } = {}) {
  return {
    async fetch(request: Request, env: AdminEnv): Promise<Response> {
      try {
        const url = new URL(request.url);
        const isApi = url.pathname === "/api" || url.pathname.startsWith("/api/");
        const method = request.method.toUpperCase();
        const sessionEnabled = adminSessionKeyConfigured(env.ADMIN_SESSION_KEY);

        if (url.pathname === "/api/auth/status") {
          requireMethod(method, "GET");
          return json({
            enabled: sessionEnabled,
            authenticated: sessionEnabled ? (await adminSessionPayload(request, env)) !== null : false,
            passwordSet: await env.CORE.isAdminPasswordSet(),
            siteKey: env.TURNSTILE_SITE_KEY ?? null,
          }, 200);
        }

        if (!sessionEnabled) {
          throw new HttpError(503, "SERVER_MISCONFIGURED");
        }

        // Reset paths require the existing login method (Cloudflare Access) to verify identity.
        if (url.pathname === "/reset" || url.pathname === "/reset.html" || url.pathname === "/api/auth/reset") {
          const identity = await validateAccess(request, {
            teamDomain: env.ACCESS_TEAM_DOMAIN,
            audience: env.ACCESS_AUD,
            adminEmails: env.ADMIN_EMAILS,
          }, dependencies.jwks);
          if (!isApi) {
            requireMethod(method, "GET");
            return secure(pageHtml(RESET_PAGE));
          }
          requireMethod(method, "POST");
          rejectQuery(url, new Set());
          requireSameOrigin(request, env.ADMIN_ORIGIN);
          const body = await readObject(request, new Set(["newPassword", "turnstileToken"]));
          const newPassword = requireString(body, "newPassword", 128);
          const turnstileToken = typeof body.turnstileToken === "string" ? body.turnstileToken : "";
          if (env.TURNSTILE_SECRET_KEY !== undefined && !(await verifyTurnstile(env.TURNSTILE_SECRET_KEY, turnstileToken, request))) {
            throw new HttpError(400, "INVALID_TURNSTILE");
          }
          const passwordVersion = (await env.CORE.setAdminPassword(identity, newPassword)).passwordVersion;
          await env.CORE.clearLoginFailures("global");
          await env.CORE.clearLoginFailures(loginKey(request));
          return json({ ok: true }, 200, { "Set-Cookie": await issueAdminSession(env.ADMIN_SESSION_KEY, passwordVersion) });
        }

        // Login page status, login, and logout do not require a session.
        const openAuth = url.pathname === "/api/auth/status"
          || url.pathname === "/api/auth/login"
          || url.pathname === "/api/auth/logout";

        let sessionPayload: AdminSessionPayload | null = null;
        if (!openAuth) {
          sessionPayload = await adminSessionPayload(request, env);
          if (sessionPayload === null) {
            if (isApi) {
              return secure(json({ error: "ADMIN_LOGIN_REQUIRED" }, 401));
            }
            const path = url.pathname;
            if (path !== "/" && path !== "/login" && path !== "/login.html" && !path.startsWith("/assets/")) {
              return secure(await env.ASSETS.fetch(request));
            }
            return secure(pageHtml(LOGIN_PAGE));
          }
        }

        if (!isApi) {
          return secure(await env.ASSETS.fetch(request));
        }
        if (url.pathname === "/api/auth/login") {
          requireMethod(method, "POST");
          rejectQuery(url, new Set());
          requireSameOrigin(request, env.ADMIN_ORIGIN);
          const body = await readObject(request, new Set(["password", "turnstileToken"]));
          const password = requireString(body, "password", 128);
          const turnstileToken = typeof body.turnstileToken === "string" ? body.turnstileToken : "";
          if (env.TURNSTILE_SECRET_KEY !== undefined && !(await verifyTurnstile(env.TURNSTILE_SECRET_KEY, turnstileToken, request))) {
            throw new HttpError(400, "INVALID_TURNSTILE");
          }
          const now = new Date().toISOString();
          const globalKey = "global";
          const ipKey = loginKey(request);
          if (await env.CORE.isLoginBlocked(globalKey, now) || await env.CORE.isLoginBlocked(ipKey, now)) {
            throw new HttpError(429, "RATE_LIMITED");
          }
          if (!(await env.CORE.verifyAdminPassword(password))) {
            await env.CORE.recordLoginFailure(globalKey, now);
            await env.CORE.recordLoginFailure(ipKey, now);
            throw new HttpError(401, "INVALID_PASSWORD");
          }
          await env.CORE.clearLoginFailures(globalKey);
          await env.CORE.clearLoginFailures(ipKey);
          const passwordVersion = await env.CORE.getAdminPasswordVersion();
          return json({ ok: true }, 200, { "Set-Cookie": await issueAdminSession(env.ADMIN_SESSION_KEY, passwordVersion) });
        }
        if (url.pathname === "/api/auth/logout") {
          requireMethod(method, "POST");
          rejectQuery(url, new Set());
          return json({ ok: true }, 200, { "Set-Cookie": "admin_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict" });
        }
        if (["POST", "PUT", "DELETE"].includes(method) && !validateCsrf(request, env.ADMIN_ORIGIN)) {
          throw new HttpError(403, "FORBIDDEN");
        }
        if (sessionPayload === null) {
          throw new HttpError(401, "ADMIN_LOGIN_REQUIRED");
        }
        const identity = passwordAdminIdentity(sessionPayload);
        return secure(await route(request, url, method, identity, env.CORE));
      } catch (error) {
        if (error instanceof AccessError) return secure(json({ error: "UNAUTHORIZED" }, 401));
        if (error instanceof HttpError) return secure(json({ error: error.code }, error.status));
        const normalized = normalizeCoreError(error);
        return secure(json(normalized.body, normalized.status));
      }
    },
  };
}

async function route(request: Request, url: URL, method: string, identity: AdminIdentity, core: AdminCore): Promise<Response> {
  const path = url.pathname;
  if (path === "/api/session") {
    requireMethod(method, "GET");
    rejectQuery(url, new Set());
    const token = createCsrfToken();
    return json({ csrfToken: token }, 200, { "Set-Cookie": csrfCookie(token) });
  }
  if (path === "/api/mailboxes") {
    requireMethod(method, "GET");
    return json(await core.pageMailboxes(identity, mailboxQuery(url)));
  }
  let match = path.match(/^\/api\/mailboxes\/([^/]+)\/(reveal|reset)$/);
  if (match) {
    requireMethod(method, "POST");
    rejectQuery(url, new Set());
    await readObject(request, new Set());
    const id = decodeId(match[1]!);
    return json(match[2] === "reveal"
      ? await core.revealPassword(identity, id)
      : await core.resetPassword(identity, id));
  }
  match = path.match(/^\/api\/mailboxes\/([^/]+)\/note$/);
  if (match) {
    requireMethod(method, "PUT");
    rejectQuery(url, new Set());
    const body = await readObject(request, new Set(["note"]));
    const note = requireNullableString(body, "note", 500);
    return json(await core.setMailboxNote(identity, decodeId(match[1]!), note));
  }
  match = path.match(/^\/api\/mailboxes\/([^/]+)\/confirm$/);
  if (match) {
    requireMethod(method, "POST");
    rejectQuery(url, new Set());
    await readObject(request, new Set());
    return json(await core.confirmMailbox(identity, decodeId(match[1]!)));
  }
  match = path.match(/^\/api\/mailboxes\/([^/]+)$/);
  if (match) {
    requireMethod(method, "DELETE");
    rejectQuery(url, new Set());
    const body = await readObject(request, new Set(["confirmationEmail"]));
    return json(await core.deleteMailbox(identity, decodeId(match[1]!), requireExactString(body, "confirmationEmail", 254)));
  }
  if (path === "/api/domains") {
    requireMethod(method, "GET"); rejectQuery(url, new Set());
    return json(await core.listDomains(identity));
  }
  if (path === "/api/domains/sync") {
    requireMethod(method, "POST"); rejectQuery(url, new Set()); await readObject(request, new Set());
    return json(await core.syncDomains(identity));
  }
  if (path === "/api/domains/default") {
    requireMethod(method, "PUT"); rejectQuery(url, new Set());
    const domain = requireString(await readObject(request, new Set(["domain"])), "domain", 253);
    if (!validDomain(domain)) throw new HttpError(400, "INVALID_INPUT");
    return json(await core.setDefaultDomain(identity, domain));
  }
  if (path === "/api/settings" && method === "GET") {
    rejectQuery(url, new Set()); return json(await core.getSettings(identity));
  }
  if (path === "/api/settings") {
    requireMethod(method, "PUT"); rejectQuery(url, new Set());
    const body = await readObject(request, new Set(["mailboxQuotaMb", "prefixLength", "dailyCreationLimit", "totalManagedLimit", "generationEnabled"]));
    validateSettings(body); return json(await core.updateSettings(identity, body as AdminSettingsPatch));
  }
  if (path === "/api/tokens" && method === "GET") {
    rejectQuery(url, new Set()); return json(await core.listApiTokens(identity));
  }
  if (path === "/api/tokens") {
    requireMethod(method, "POST"); rejectQuery(url, new Set());
    const body = await readObject(request, new Set(["name", "operationId"]));
    return json(await core.createApiToken(identity, requireString(body, "name", 100), requireOperationId(body)));
  }
  match = path.match(/^\/api\/tokens\/([^/]+)\/acknowledge$/);
  if (match) {
    requireMethod(method, "POST"); rejectQuery(url, new Set());
    const body = await readObject(request, new Set(["operationId"]));
    return json(await core.acknowledgeApiToken(identity, decodeId(match[1]!), requireOperationId(body)));
  }
  match = path.match(/^\/api\/tokens\/([^/]+)$/);
  if (match) {
    requireMethod(method, "DELETE"); rejectQuery(url, new Set()); await readObject(request, new Set());
    return json(await core.revokeApiToken(identity, decodeId(match[1]!)));
  }
  if (path === "/api/audit") {
    requireMethod(method, "GET"); return json(await core.pageAudit(identity, pageQuery(url)));
  }
  if (["GET", "POST", "PUT", "DELETE"].includes(method)) throw new HttpError(404, "NOT_FOUND");
  throw new HttpError(405, "METHOD_NOT_ALLOWED");
}

function requireOperationId(body: Record<string, unknown>): string {
  const value = requireString(body, "operationId", 128);
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(value)) throw new HttpError(400, "INVALID_INPUT");
  return value;
}

function mailboxQuery(url: URL): PageMailboxesOptions {
  const allowed = new Set(["limit", "cursor", "sort", "direction", "domain", "status", "search"]);
  rejectQuery(url, allowed);
  const out: Record<string, unknown> = { ...pageQuery(url, allowed) };
  for (const key of ["cursor", "search"] as const) {
    const value = url.searchParams.get(key);
    if (value !== null) out[key] = bounded(value, 512);
  }
  const domain = url.searchParams.get("domain");
  if (domain !== null) {
    if (!validDomain(domain)) throw new HttpError(400, "INVALID_INPUT");
    out.domain = domain;
  }
  const sort = url.searchParams.get("sort");
  if (sort !== null) {
    if (!["createdAt", "email", "status"].includes(sort)) throw new HttpError(400, "INVALID_INPUT");
    out.sort = sort;
  }
  const direction = url.searchParams.get("direction");
  if (direction !== null) {
    if (!["asc", "desc"].includes(direction)) throw new HttpError(400, "INVALID_INPUT");
    out.direction = direction;
  }
  const status = url.searchParams.get("status");
  if (status !== null) {
    if (!STATUSES.includes(status as MailboxStatus)) throw new HttpError(400, "INVALID_INPUT");
    out.status = status;
  }
  return out as PageMailboxesOptions;
}

function pageQuery(url: URL, allowed = new Set(["limit", "cursor"])): PageAuditOptions {
  rejectQuery(url, allowed);
  const out: Record<string, unknown> = {};
  const limit = url.searchParams.get("limit");
  if (limit !== null) {
    const number = Number(limit);
    if (!Number.isInteger(number) || number < 1 || number > 100) throw new HttpError(400, "INVALID_INPUT");
    out.limit = number;
  }
  const cursor = url.searchParams.get("cursor");
  if (cursor !== null) {
    const validatedCursor = bounded(cursor, 2048);
    out.cursor = validatedCursor;
    validateCursor(validatedCursor, allowed.has("sort") ? "mailbox" : "audit", out);
  }
  return out as PageAuditOptions;
}

function rejectQuery(url: URL, allowed: Set<string>): void {
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key)) throw new HttpError(400, "INVALID_INPUT");
  }
}

async function readObject(request: Request, allowed: Set<string>): Promise<Record<string, unknown>> {
  const declared = Number(request.headers.get("Content-Length") ?? 0);
  if (declared > BODY_LIMIT) throw new HttpError(413, "PAYLOAD_TOO_LARGE");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > BODY_LIMIT) throw new HttpError(413, "PAYLOAD_TOO_LARGE");
  if (text === "") return {};
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw new HttpError(400, "INVALID_INPUT"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "INVALID_INPUT");
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new HttpError(400, "INVALID_INPUT");
  }
  return value as Record<string, unknown>;
}

function validateSettings(body: Record<string, unknown>): void {
  if (Object.keys(body).length === 0) throw new HttpError(400, "INVALID_INPUT");
  const ranges: Readonly<Record<string, readonly [number, number]>> = {
    mailboxQuotaMb: [1, 102_400], prefixLength: [12, 12],
    dailyCreationLimit: [1, 1_000], totalManagedLimit: [1, 100_000],
  };
  for (const [key, [minimum, maximum]] of Object.entries(ranges)) {
    const value = body[key];
    if (value !== undefined && (!Number.isInteger(value) || Number(value) < minimum || Number(value) > maximum)) {
      throw new HttpError(400, "INVALID_INPUT");
    }
  }
  if (body.generationEnabled !== undefined && typeof body.generationEnabled !== "boolean") {
    throw new HttpError(400, "INVALID_INPUT");
  }
}

function requireString(body: Record<string, unknown>, key: string, maximum: number): string {
  const value = body[key];
  if (typeof value !== "string" || value.trim().length === 0 || value.length > maximum) {
    throw new HttpError(400, "INVALID_INPUT");
  }
  return value.trim();
}

function requireNullableString(body: Record<string, unknown>, key: string, maximum: number): string | null {
  const value = body[key];
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || value.length > maximum) throw new HttpError(400, "INVALID_INPUT");
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

function requireExactString(body: Record<string, unknown>, key: string, maximum: number): string {
  const value = body[key];
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new HttpError(400, "INVALID_INPUT");
  }
  return value;
}

function validDomain(value: string): boolean {
  const labels = value.split(".");
  return value === value.toLowerCase() && value.length <= 253 && labels.length >= 2
    && labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

function decodeId(value: string): string {
  let result: string;
  try { result = decodeURIComponent(value); }
  catch { throw new HttpError(400, "INVALID_INPUT"); }
  if (!/^[A-Za-z0-9_.:-]{1,200}$/.test(result)) throw new HttpError(400, "INVALID_INPUT");
  return result;
}

function bounded(value: string, maximum: number): string {
  if (value.length === 0 || value.length > maximum) throw new HttpError(400, "INVALID_INPUT");
  return value;
}

function requireMethod(actual: string, expected: string): void {
  if (actual !== expected) throw new HttpError(405, "METHOD_NOT_ALLOWED");
}

function requireSameOrigin(request: Request, origin: string): void {
  const header = request.headers.get("Origin");
  if (header !== origin) throw new HttpError(403, "FORBIDDEN");
}

function json(value: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers },
  });
}

function secure(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function pageHtml(html: string): Response {
  return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function validateCursor(
  cursor: string,
  kind: "mailbox" | "audit",
  options: Record<string, unknown>,
): void {
  let value: unknown;
  try { value = JSON.parse(atob(cursor)); }
  catch { throw new HttpError(400, "INVALID_INPUT"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400, "INVALID_INPUT");
  const record = value as Record<string, unknown>;
  if (kind === "audit") {
    if (typeof record.createdAt !== "string" || typeof record.id !== "string"
      || record.createdAt.length === 0 || record.id.length === 0) throw new HttpError(400, "INVALID_INPUT");
    return;
  }
  if (!["createdAt", "email", "status"].includes(String(record.sort))
    || !["asc", "desc"].includes(String(record.direction))
    || typeof record.value !== "string" || typeof record.publicId !== "string"
    || record.value.length === 0 || record.publicId.length === 0
    || (options.sort !== undefined && record.sort !== options.sort)
    || (options.direction !== undefined && record.direction !== options.direction)) {
    throw new HttpError(400, "INVALID_INPUT");
  }
}

function normalizeCoreError(error: unknown): {
  readonly status: number;
  readonly body: { readonly error: string; readonly requestId?: string; readonly retryable?: boolean };
} {
  if (error === null || typeof error !== "object") return { status: 500, body: { error: "INTERNAL_ERROR" } };
  const candidate = error as Record<string, unknown>;
  const code = typeof candidate.code === "string" ? candidate.code : "";
  const status = CORE_ERROR_STATUS[code];
  const requestId = typeof candidate.requestId === "string" ? candidate.requestId : "";
  if (status === undefined || !/^[A-Za-z0-9_.:-]{1,200}$/.test(requestId) || typeof candidate.retryable !== "boolean") {
    return { status: 500, body: { error: "INTERNAL_ERROR" } };
  }
  return { status, body: { error: code, requestId, retryable: candidate.retryable } };
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacKey(key: string, message: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
  return new Uint8Array(digest).slice(0, 16);
}

function cookieValue(cookieHeader: string | null, name: string): string | null {
  if (cookieHeader === null) return null;
  for (const part of cookieHeader.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function loginKey(request: Request): string {
  const direct = request.headers.get("CF-Connecting-IP");
  if (direct !== null && direct.length > 0) return `login:${direct}`;
  const forwarded = request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim();
  return forwarded !== undefined && forwarded.length > 0 ? `login:${forwarded}` : "login:unknown";
}

interface AdminSessionPayload {
  readonly exp: number;
  readonly pwdVersion: number;
  readonly sid: string;
}

function encodeSessionPayload(payload: AdminSessionPayload): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
}

function decodeBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function decodeSessionPayload(value: string): AdminSessionPayload | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(value))) as Partial<AdminSessionPayload>;
    if (
      typeof parsed.exp !== "number"
      || !Number.isFinite(parsed.exp)
      || typeof parsed.pwdVersion !== "number"
      || !Number.isInteger(parsed.pwdVersion)
      || typeof parsed.sid !== "string"
      || parsed.sid.length === 0
    ) {
      return null;
    }
    return { exp: parsed.exp, pwdVersion: parsed.pwdVersion, sid: parsed.sid };
  } catch {
    return null;
  }
}

function adminSessionKeyConfigured(value: string | undefined): boolean {
  if (typeof value !== "string" || value.length < 32 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return false;
  }
  try {
    return decodeBase64Url(value).length >= 32;
  } catch {
    return false;
  }
}

async function adminSessionPayload(request: Request, env: AdminEnv): Promise<AdminSessionPayload | null> {
  const cookie = cookieValue(request.headers.get("Cookie"), "admin_session");
  if (cookie === null) return null;
  const dot = cookie.indexOf(".");
  if (dot <= 0) return null;
  const encodedPayload = cookie.slice(0, dot);
  const signature = cookie.slice(dot + 1);
  const payload = decodeSessionPayload(encodedPayload);
  if (payload === null || payload.exp <= Math.floor(Date.now() / 1_000)) return null;
  const passwordVersion = await env.CORE.getAdminPasswordVersion();
  if (payload.pwdVersion !== passwordVersion) return null;
  const expected = toBase64Url(await hmacKey(env.ADMIN_SESSION_KEY, encodedPayload));
  if (signature.length !== expected.length) return null;
  let difference = 0;
  for (let index = 0; index < signature.length; index += 1) {
    difference |= signature.charCodeAt(index) ^ expected.charCodeAt(index);
  }
  return difference === 0 ? payload : null;
}

function passwordAdminIdentity(payload: AdminSessionPayload): AdminIdentity {
  return {
    subject: `password-admin:v${payload.pwdVersion}:${payload.sid}`,
    email: "password-admin@local",
  };
}

async function issueAdminSession(key: string, passwordVersion: number): Promise<string> {
  const payload = {
    exp: Math.floor(Date.now() / 1_000) + 12 * 3_600,
    pwdVersion: passwordVersion,
    sid: crypto.randomUUID(),
  };
  const encoded = encodeSessionPayload(payload);
  const signature = toBase64Url(await hmacKey(key, encoded));
  return `admin_session=${encoded}.${signature}; Max-Age=${12 * 3_600}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

async function verifyTurnstile(secret: string, token: string, request: Request): Promise<boolean> {
  if (token.length === 0 || token.length > 4_096) return false;
  const body = new FormData();
  body.set("secret", secret);
  body.set("response", token);
  const remote = request.headers.get("CF-Connecting-IP");
  if (remote !== null) body.set("remoteip", remote);
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
    if (!response.ok) return false;
    const data = await response.json() as { success?: unknown };
    return data.success === true;
  } catch {
    return false;
  }
}

export default createAdminHandler();
