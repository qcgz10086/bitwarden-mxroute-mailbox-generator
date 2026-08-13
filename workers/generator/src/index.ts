import type {
  AliasResult,
  GenerateResult,
} from "../../../packages/contracts/src/index";
import { preflightResponse, publicResponseHeaders } from "./cors";

const ALIAS_PATH = "/api/alias/random/new";
const HEALTH_PATH = "/healthz";

export interface GeneratorRateLimiter {
  limit(options: { readonly key: string }): Promise<{ readonly success: boolean }>;
}

export interface GeneratorCore {
  generateMailbox(token: string): Promise<GenerateResult>;
}

export interface GeneratorEnv {
  readonly CORE: GeneratorCore;
  readonly PREAUTH_RATE_LIMITER: GeneratorRateLimiter;
  readonly TOKEN_RATE_LIMITER: GeneratorRateLimiter;
}

interface CoreFailure {
  readonly code?: unknown;
  readonly requestId?: unknown;
  readonly retryable?: unknown;
}

export default {
  async fetch(request: Request, env: GeneratorEnv): Promise<Response> {
    const requestId = crypto.randomUUID();
    const url = new URL(request.url);

    if (url.pathname === HEALTH_PATH) {
      if (request.method !== "GET") {
        return methodNotAllowed(requestId, "GET");
      }
      return json({ status: "ok" }, 200, requestId);
    }

    if (url.pathname !== ALIAS_PATH) {
      return error("Not found", 404, requestId);
    }
    if (request.method === "OPTIONS") {
      return preflightResponse(requestId);
    }
    if (request.method !== "POST") {
      return methodNotAllowed(requestId, "POST, OPTIONS");
    }

    const clientAddress = request.headers.get("CF-Connecting-IP") ?? "unknown";
    const preauth = await safeLimit(env.PREAUTH_RATE_LIMITER, clientAddress);
    if (preauth === null) {
      return error("Mailbox service temporarily unavailable", 503, requestId);
    }
    if (!preauth.success) {
      return error("Too many requests", 429, requestId);
    }

    const token = request.headers.get("Authentication");
    if (token === null || token.length === 0) {
      return error("Invalid API token", 401, requestId);
    }

    let fingerprint: string;
    try {
      fingerprint = await tokenFingerprint(token);
    } catch {
      return error("Mailbox service temporarily unavailable", 503, requestId);
    }
    const tokenLimit = await safeLimit(env.TOKEN_RATE_LIMITER, fingerprint);
    if (tokenLimit === null) {
      return error("Mailbox service temporarily unavailable", 503, requestId);
    }
    if (!tokenLimit.success) {
      return error("Too many requests", 429, requestId);
    }

    try {
      const result = await env.CORE.generateMailbox(token);
      return json(publicAlias(result.alias), 201, safeRequestId(result.requestId) ?? requestId);
    } catch (caught) {
      return mappedCoreError(caught, requestId);
    }
  },
};

async function safeLimit(
  limiter: GeneratorRateLimiter,
  key: string,
): Promise<{ readonly success: boolean } | null> {
  try {
    return await limiter.limit({ key });
  } catch {
    return null;
  }
}

function publicAlias(alias: AliasResult): AliasResult {
  return {
    id: alias.id,
    email: alias.email,
    enabled: true,
    creation_timestamp: alias.creation_timestamp,
    name: null,
    note: null,
  };
}

async function tokenFingerprint(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return Array.from(new Uint8Array(digest).slice(0, 16), (byte) =>
    byte.toString(16).padStart(2, "0")).join("");
}

function mappedCoreError(caught: unknown, fallbackRequestId: string): Response {
  const failure = isObject(caught) ? caught as CoreFailure : {};
  const requestId = safeRequestId(failure.requestId) ?? fallbackRequestId;
  const code = typeof failure.code === "string" ? failure.code : "INTERNAL_ERROR";

  if (code === "INVALID_TOKEN") {
    return error("Invalid API token", 401, requestId);
  }
  if (code === "DAILY_LIMIT" || code === "TOTAL_LIMIT") {
    return error("Mailbox creation limit reached", 429, requestId);
  }
  if (code === "MX_CLIENT" || code === "MX_UNAUTHORIZED" || code === "MX_NOT_FOUND") {
    return error("Mailbox provider rejected the request", 502, requestId);
  }
  if (
    failure.retryable === true
    || code === "GENERATION_DISABLED"
    || code === "DEFAULT_DOMAIN_UNAVAILABLE"
    || code === "MX_CONFLICT"
    || code === "MX_RATE_LIMITED"
    || code === "MX_SERVER"
    || code === "MX_TIMEOUT"
    || code === "MX_INVALID_RESPONSE"
  ) {
    return error("Mailbox service temporarily unavailable", 503, requestId);
  }
  return error("Mailbox creation failed", 500, requestId);
}

function safeRequestId(value: unknown): string | null {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value)
    ? value
    : null;
}

function isObject(value: unknown): value is object {
  return value !== null && typeof value === "object";
}

function methodNotAllowed(requestId: string, allow: string): Response {
  const response = error("Method not allowed", 405, requestId);
  response.headers.set("Allow", allow);
  return response;
}

function error(message: string, status: number, requestId: string): Response {
  return json({ error: message }, status, requestId);
}

function json(
  body: AliasResult | Record<string, unknown>,
  status: number,
  requestId: string,
): Response {
  const headers = publicResponseHeaders(requestId);
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}
