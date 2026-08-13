import { describe, expect, it, vi } from "vitest";

import type { GenerateResult } from "../../packages/contracts/src/index";
import generator, {
  type GeneratorEnv,
  type GeneratorRateLimiter,
} from "../../workers/generator/src/index";

const ENDPOINT = "https://generator.example.test/api/alias/random/new";
const TOKEN = "raw-token-that-must-never-be-a-rate-limit-key";
const ALIAS = {
  id: 123,
  email: "q8v2ka7m3p4x@example.test",
  enabled: true as const,
  creation_timestamp: 1_786_612_345,
  name: null,
  note: null,
};

interface FakeLimiter extends GeneratorRateLimiter {
  readonly limit: ReturnType<typeof vi.fn<GeneratorRateLimiter["limit"]>>;
}

function limiter(success = true): FakeLimiter {
  return { limit: vi.fn(async () => ({ success })) };
}

function environment(options: {
  readonly preauth?: FakeLimiter;
  readonly token?: FakeLimiter;
  readonly generate?: (token: string) => Promise<GenerateResult>;
} = {}): GeneratorEnv {
  return {
    CORE: {
      generateMailbox: vi.fn(options.generate ?? (async () => ({
        alias: ALIAS,
        requestId: "core-request-01",
      }))),
    },
    PREAUTH_RATE_LIMITER: options.preauth ?? limiter(),
    TOKEN_RATE_LIMITER: options.token ?? limiter(),
  };
}

function request(init: RequestInit = {}, query = ""): Request {
  return new Request(`${ENDPOINT}${query}`, {
    method: "POST",
    headers: {
      Authentication: TOKEN,
      "CF-Connecting-IP": "203.0.113.9",
      "Content-Type": "application/json",
      ...init.headers,
    },
    body: JSON.stringify({ ignored: true }),
    ...init,
  });
}

async function dispatch(input: Request, env = environment()): Promise<Response> {
  return generator.fetch(input, env);
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return response.json<Record<string, unknown>>();
}

function expectPublicHeaders(response: Response): void {
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
  expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
  expect(response.headers.get("X-Request-Id")).toMatch(/^[A-Za-z0-9._:-]{1,128}$/);
}

function expectNoCredentialFields(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(expectNoCredentialFields);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    expect(key).not.toMatch(/password|credential|authentication|api.?key|token/i);
    expectNoCredentialFields(nested);
  }
}

describe("Generator Worker", () => {
  it("returns the exact SimpleLogin alias body and extracts Authentication", async () => {
    const env = environment();

    const response = await dispatch(request(), env);

    expect(response.status).toBe(201);
    expect(await json(response)).toEqual(ALIAS);
    expect(env.CORE.generateMailbox).toHaveBeenCalledOnce();
    expect(env.CORE.generateMailbox).toHaveBeenCalledWith(TOKEN);
    expect(response.headers.get("X-Request-Id")).toBe("core-request-01");
    expectPublicHeaders(response);
  });

  it("rebuilds the public alias DTO instead of forwarding unexpected Core fields", async () => {
    const poisonedAlias = {
      ...ALIAS,
      password: "MustNeverReachBitwarden2",
      upstreamCredential: "mxroute-private",
    };
    const env = environment({ generate: async () => ({
      alias: poisonedAlias,
      requestId: "core-request-02",
    }) });

    const response = await dispatch(request(), env);
    const body = await json(response);

    expect(body).toEqual(ALIAS);
    expectNoCredentialFields(body);
    expect(JSON.stringify(body)).not.toContain("MustNeverReachBitwarden2");
  });

  it("accepts hostname and mode but does not send either to Core", async () => {
    const env = environment();
    const response = await dispatch(
      request({}, "?hostname=attacker.example&mode=uuid"),
      env,
    );

    expect(response.status).toBe(201);
    expect(env.CORE.generateMailbox).toHaveBeenCalledWith(TOKEN);
    expect(env.CORE.generateMailbox).toHaveBeenCalledTimes(1);
  });

  it("applies pre-auth throttling to the connecting IP before reading credentials", async () => {
    const preauth = limiter(false);
    const env = environment({ preauth });
    const response = await dispatch(request({ headers: {
      "CF-Connecting-IP": "198.51.100.44",
      Authentication: "should-not-be-read-or-hashed",
    } }), env);

    expect(response.status).toBe(429);
    expect(preauth.limit).toHaveBeenCalledWith({ key: "198.51.100.44" });
    expect(env.TOKEN_RATE_LIMITER.limit).not.toHaveBeenCalled();
    expect(env.CORE.generateMailbox).not.toHaveBeenCalled();
    expect(await json(response)).toEqual({ error: "Too many requests" });
    expectPublicHeaders(response);
  });

  it("rejects a missing token after only the pre-auth limiter", async () => {
    const env = environment();
    const response = await dispatch(request({ headers: {
      "CF-Connecting-IP": "203.0.113.9",
      "Content-Type": "application/json",
    } }), env);

    expect(response.status).toBe(401);
    expect(await json(response)).toEqual({ error: "Invalid API token" });
    expect(env.PREAUTH_RATE_LIMITER.limit).toHaveBeenCalledOnce();
    expect(env.TOKEN_RATE_LIMITER.limit).not.toHaveBeenCalled();
    expect(env.CORE.generateMailbox).not.toHaveBeenCalled();
  });

  it("uses only the first 16 SHA-256 bytes as the token rate-limit key", async () => {
    const tokenLimiter = limiter();
    const env = environment({ token: tokenLimiter });
    await dispatch(request(), env);

    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(TOKEN));
    const expected = Array.from(new Uint8Array(digest).slice(0, 16), (byte) =>
      byte.toString(16).padStart(2, "0")).join("");
    expect(tokenLimiter.limit).toHaveBeenCalledWith({ key: expected });
    expect(expected).not.toContain(TOKEN);
  });

  it("stops before Core when the token fingerprint is throttled", async () => {
    const env = environment({ token: limiter(false) });
    const response = await dispatch(request(), env);

    expect(response.status).toBe(429);
    expect(await json(response)).toEqual({ error: "Too many requests" });
    expect(env.CORE.generateMailbox).not.toHaveBeenCalled();
  });

  it("returns a stable protected response when a rate-limiter binding fails", async () => {
    const failedLimiter: FakeLimiter = {
      limit: vi.fn(async () => {
        throw new Error("binding internals and raw token must stay private");
      }),
    };
    const env = environment({ preauth: failedLimiter });

    const response = await dispatch(request(), env);

    expect(response.status).toBe(503);
    expect(await json(response)).toEqual({ error: "Mailbox service temporarily unavailable" });
    expectPublicHeaders(response);
    expect(env.CORE.generateMailbox).not.toHaveBeenCalled();
  });

  it("returns 405 for a known route with a closed method set", async () => {
    const env = environment();
    const response = await dispatch(new Request(ENDPOINT, { method: "GET" }), env);

    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("POST, OPTIONS");
    expect(await json(response)).toEqual({ error: "Method not allowed" });
    expect(env.PREAUTH_RATE_LIMITER.limit).not.toHaveBeenCalled();
    expectPublicHeaders(response);
  });

  it("returns 404 for every unknown path without invoking bindings", async () => {
    const env = environment();
    const response = await dispatch(new Request("https://generator.example.test/api/other"), env);

    expect(response.status).toBe(404);
    expect(await json(response)).toEqual({ error: "Not found" });
    expect(env.PREAUTH_RATE_LIMITER.limit).not.toHaveBeenCalled();
    expect(env.CORE.generateMailbox).not.toHaveBeenCalled();
    expectPublicHeaders(response);
  });

  it("maps retryable Core failures to a stable 503 without leaking details", async () => {
    const env = environment({ generate: async () => {
      throw Object.assign(new Error("D1 SELECT secret_password MXroute raw response"), {
        code: "MX_TIMEOUT",
        status: 503,
        retryable: true,
        requestId: "core-timeout-01",
        password: "MustNeverLeak2",
      });
    } });
    const response = await dispatch(request(), env);
    const body = await json(response);

    expect(response.status).toBe(503);
    expect(body).toEqual({ error: "Mailbox service temporarily unavailable" });
    expect(JSON.stringify(body)).not.toMatch(/D1|SELECT|MXroute|MustNeverLeak|raw response/i);
    expect(response.headers.get("X-Request-Id")).toBe("core-timeout-01");
  });

  it.each(["DAILY_LIMIT", "TOTAL_LIMIT"])("maps %s to quota HTTP 429", async (code) => {
    const env = environment({ generate: async () => {
      throw { code, status: 429, retryable: false, requestId: `core-${code}` };
    } });
    const response = await dispatch(request(), env);

    expect(response.status).toBe(429);
    expect(await json(response)).toEqual({ error: "Mailbox creation limit reached" });
  });

  it("handles CORS preflight without authentication or limiter calls", async () => {
    const env = environment();
    const response = await dispatch(new Request(ENDPOINT, {
      method: "OPTIONS",
      headers: {
        Origin: "chrome-extension://bitwarden",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authentication, Content-Type",
      },
    }), env);

    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Methods")).toBe("POST, OPTIONS");
    expect(response.headers.get("Access-Control-Allow-Headers")).toBe("Authentication, Content-Type");
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
    expect(env.PREAUTH_RATE_LIMITER.limit).not.toHaveBeenCalled();
    expectPublicHeaders(response);
  });

  it("serves an isolated health check with the same cache and sniffing protections", async () => {
    const env = environment();
    const response = await dispatch(new Request("https://generator.example.test/healthz"), env);

    expect(response.status).toBe(200);
    expect(await json(response)).toEqual({ status: "ok" });
    expect(env.PREAUTH_RATE_LIMITER.limit).not.toHaveBeenCalled();
    expectPublicHeaders(response);
  });

  it("never returns password-shaped fields from success, local error, or Core error bodies", async () => {
    const responses = [
      await dispatch(request(), environment()),
      await dispatch(request({ headers: { "CF-Connecting-IP": "203.0.113.9" } }), environment()),
      await dispatch(request(), environment({ generate: async () => {
        throw { code: "INTERNAL_ERROR", password: "Secret2", requestId: "core-error" };
      } })),
    ];

    for (const response of responses) expectNoCredentialFields(await json(response));
  });
});
