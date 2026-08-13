import type { AdminIdentity, MailboxPage, MailboxStatus } from "../../../packages/contracts/src/index";
import type { JWTVerifyGetKey } from "jose";
import type {
  ApiTokenRecord, AuditPage, DomainRecord, PageAuditOptions, PageMailboxesOptions, RepositorySettings,
} from "../../core/src/repository";
import type { AdminSettingsPatch } from "../../core/src/service";
import { AccessError, validateAccess } from "./access";
import { createCsrfToken, csrfCookie, validateCsrf } from "./csrf";

const BODY_LIMIT = 65_536;
const STATUSES: readonly MailboxStatus[] = [
  "pending", "active", "failed", "resetting", "reset_unknown", "deleting", "delete_failed",
];
const SECURITY_HEADERS: Readonly<Record<string,string>> = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
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
  listDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]>;
  syncDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]>;
  setDefaultDomain(identity: AdminIdentity, domain: string): Promise<{ requestId: string }>;
  getSettings(identity: AdminIdentity): Promise<RepositorySettings>;
  updateSettings(identity: AdminIdentity, patch: AdminSettingsPatch): Promise<RepositorySettings & { requestId: string }>;
  listApiTokens(identity: AdminIdentity): Promise<readonly ApiTokenRecord[]>;
  createApiToken(identity: AdminIdentity, name: string): Promise<{ id: string; rawToken: string; requestId: string }>;
  revokeApiToken(identity: AdminIdentity, id: string): Promise<{ requestId: string }>;
  pageAudit(identity: AdminIdentity, options: PageAuditOptions): Promise<AuditPage>;
}
export interface AdminEnv {
  readonly CORE: AdminCore;
  readonly ASSETS: Fetcher;
  readonly ACCESS_TEAM_DOMAIN: string;
  readonly ACCESS_AUD: string;
  readonly ADMIN_EMAILS: string;
  readonly ADMIN_ORIGIN: string;
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
        const identity = await validateAccess(request, {
          teamDomain: env.ACCESS_TEAM_DOMAIN,
          audience: env.ACCESS_AUD,
          adminEmails: env.ADMIN_EMAILS,
        }, dependencies.jwks);
        const url = new URL(request.url);
        if (url.pathname !== "/api" && !url.pathname.startsWith("/api/")) {
          return secure(await env.ASSETS.fetch(request));
        }
        const method = request.method.toUpperCase();
        if (["POST", "PUT", "DELETE"].includes(method) && !validateCsrf(request, env.ADMIN_ORIGIN)) {
          throw new HttpError(403, "FORBIDDEN");
        }
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
    const body = await readObject(request, new Set(["name"]));
    return json(await core.createApiToken(identity, requireString(body, "name", 100)));
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

export default createAdminHandler();
