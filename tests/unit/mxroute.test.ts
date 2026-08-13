import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MxrouteClient,
  type MxrouteFetch,
} from "../../workers/core/src/mxroute";

const credentials = {
  server: "eagle.mxlogin.com",
  username: "directadmin-user",
  apiKey: "mxroute-secret-key",
};

function success(data: unknown, status = 200): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function clientWith(response: Response, onRequest?: (request: Request) => void): MxrouteClient {
  const fetch: MxrouteFetch = async (input, init) => {
    onRequest?.(new Request(input, init));
    return response;
  };
  return new MxrouteClient(credentials, { fetch });
}

describe("MxrouteClient", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("lists only domain names through the fixed authenticated endpoint", async () => {
    let request: Request | undefined;
    const client = clientWith(success(["first.test", "second.test"]), (captured) => {
      request = captured;
    });

    await expect(client.listDomains()).resolves.toEqual(["first.test", "second.test"]);

    expect(request?.url).toBe("https://api.mxroute.com/domains");
    expect(request?.method).toBe("GET");
    expect(request?.headers.get("X-Server")).toBe("eagle.mxlogin.com");
    expect(request?.headers.get("X-Username")).toBe("directadmin-user");
    expect(request?.headers.get("X-API-Key")).toBe("mxroute-secret-key");
    expect(request?.headers.get("Content-Type")).toBeNull();
  });

  it("encodes mailbox path components before retrieving typed mailbox facts", async () => {
    let request: Request | undefined;
    const client = clientWith(success({
      username: "alpha",
      email: "alpha@team/example.test",
      quota: 100,
      limit: 9600,
      usage: 2.5,
      sent: 3,
      suspended: false,
    }), (captured) => {
      request = captured;
    });

    await expect(client.getMailbox("team/example.test", "alpha/beta")).resolves.toEqual({
      username: "alpha",
      email: "alpha@team/example.test",
      quotaMb: 100,
      limit: 9600,
    });

    expect(request?.url).toBe(
      "https://api.mxroute.com/domains/team%2Fexample.test/email-accounts/alpha%2Fbeta",
    );
    expect(request?.method).toBe("GET");
  });

  it("creates a mailbox with the documented JSON body and typed result", async () => {
    let request: Request | undefined;
    const client = clientWith(success({
      username: "alpha",
      email: "alpha@example.test",
      quota: 100,
      limit: 9600,
      usage: 0,
      sent: 0,
      suspended: false,
    }, 201), (captured) => {
      request = captured;
    });

    await expect(client.createMailbox("example.test", "alpha", "MailboxPass1", 100)).resolves.toEqual({
      username: "alpha",
      email: "alpha@example.test",
      quotaMb: 100,
      limit: 9600,
    });

    expect(request?.url).toBe("https://api.mxroute.com/domains/example.test/email-accounts");
    expect(request?.method).toBe("POST");
    expect(request?.headers.get("Content-Type")).toBe("application/json");
    await expect(request?.json()).resolves.toEqual({
      username: "alpha",
      password: "MailboxPass1",
      quota: 100,
      limit: 9600,
    });
  });

  it("updates a mailbox through the encoded PATCH endpoint", async () => {
    let request: Request | undefined;
    const client = clientWith(success({
      username: "alpha",
      email: "alpha@example.test",
      quota: 250,
      limit: 400,
      usage: 0,
      sent: 0,
      suspended: false,
    }), (captured) => {
      request = captured;
    });

    await expect(client.updateMailbox("example/test", "alpha/beta", {
      password: "NextMailboxPass1",
      quotaMb: 250,
      limit: 400,
    })).resolves.toEqual({
      username: "alpha",
      email: "alpha@example.test",
      quotaMb: 250,
      limit: 400,
    });

    expect(request?.url).toBe(
      "https://api.mxroute.com/domains/example%2Ftest/email-accounts/alpha%2Fbeta",
    );
    expect(request?.method).toBe("PATCH");
    expect(request?.headers.get("Content-Type")).toBe("application/json");
    await expect(request?.json()).resolves.toEqual({
      password: "NextMailboxPass1",
      quota: 250,
      limit: 400,
    });
  });

  it("deletes a mailbox and treats an upstream 404 as idempotent success", async () => {
    let request: Request | undefined;
    const client = clientWith(new Response(null, { status: 404 }), (captured) => {
      request = captured;
    });

    await expect(client.deleteMailbox("example/test", "alpha/beta")).resolves.toBeUndefined();

    expect(request?.url).toBe(
      "https://api.mxroute.com/domains/example%2Ftest/email-accounts/alpha%2Fbeta",
    );
    expect(request?.method).toBe("DELETE");
  });

  it("preserves a query 404 as a normalized not-found error without credential leakage", async () => {
    const client = clientWith(new Response(JSON.stringify({
      success: false,
      error: { message: `credentials: ${credentials.apiKey}` },
    }), { status: 404 }));

    const error = await client.getMailbox("example.test", "missing").catch((caught: unknown) => caught);

    expect(error).toMatchObject({ code: "MX_NOT_FOUND", message: "MX_NOT_FOUND" });
    expect((error as Error).message).not.toContain(credentials.server);
    expect((error as Error).message).not.toContain(credentials.username);
    expect((error as Error).message).not.toContain(credentials.apiKey);
  });

  it.each([
    [401, "MX_UNAUTHORIZED"],
    [409, "MX_CONFLICT"],
    [429, "MX_RATE_LIMITED"],
    [500, "MX_SERVER"],
  ] as const)("normalizes HTTP %i to %s", async (status, code) => {
    const client = clientWith(new Response("upstream response that must stay private", { status }));

    await expect(client.listDomains()).rejects.toMatchObject({ code, message: code });
  });

  it.each([400, 403, 422])("normalizes explicit HTTP %i client failure to MX_CLIENT", async (status) => {
    const client = clientWith(new Response("explicit client failure", { status }));

    await expect(client.listDomains()).rejects.toMatchObject({
      code: "MX_CLIENT",
      message: "MX_CLIENT",
    });
  });

  it("normalizes a 10-second aborted fetch to a timeout", async () => {
    vi.useFakeTimers();
    const fetch: MxrouteFetch = async (_input, init) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        reject(new DOMException("request aborted", "AbortError"));
      }, { once: true });
    });
    const client = new MxrouteClient(credentials, { fetch });

    const result = client.listDomains();
    let settled = false;
    void result.then(() => {
      settled = true;
    }, () => {
      settled = true;
    });
    const assertion = expect(result).rejects.toMatchObject({
      code: "MX_TIMEOUT",
      message: "MX_TIMEOUT",
    });
    await vi.advanceTimersByTimeAsync(9_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);

    await assertion;
  });

  it("keeps the timeout active while a successful response body stalls", async () => {
    vi.useFakeTimers();
    const fetch: MxrouteFetch = async (_input, init) => new Response(new ReadableStream({
      start(controller) {
        init?.signal?.addEventListener("abort", () => {
          controller.error(new DOMException("body aborted", "AbortError"));
        }, { once: true });
      },
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
    const client = new MxrouteClient(credentials, { fetch });

    const result = client.listDomains();
    let outcome: unknown = "pending";
    void result.then(
      () => { outcome = "resolved"; },
      (error: unknown) => { outcome = error; },
    );
    await vi.advanceTimersByTimeAsync(10_000);

    expect(outcome).toMatchObject({ code: "MX_TIMEOUT", message: "MX_TIMEOUT" });
  });

  it("normalizes body-stream transport failures without misreporting malformed JSON", async () => {
    const fetch: MxrouteFetch = async () => new Response(new ReadableStream({
      start(controller) {
        controller.error(new TypeError("connection reset"));
      },
    }), { status: 200, headers: { "Content-Type": "application/json" } });
    const client = new MxrouteClient(credentials, { fetch });

    await expect(client.listDomains()).rejects.toMatchObject({
      code: "MX_SERVER",
      message: "MX_SERVER",
    });
  });

  it("rejects malformed, unsuccessful, and missing-data JSON responses", async () => {
    const malformed = clientWith(new Response("not-json", { status: 200 }));
    const unsuccessful = clientWith(new Response(JSON.stringify({
      success: false,
      data: ["first.test"],
    }), { status: 200 }));
    const missingData = clientWith(new Response(JSON.stringify({ success: true }), { status: 200 }));

    await expect(malformed.listDomains()).rejects.toMatchObject({
      code: "MX_INVALID_RESPONSE",
      message: "MX_INVALID_RESPONSE",
    });
    await expect(unsuccessful.listDomains()).rejects.toMatchObject({
      code: "MX_INVALID_RESPONSE",
      message: "MX_INVALID_RESPONSE",
    });
    await expect(missingData.listDomains()).rejects.toMatchObject({
      code: "MX_INVALID_RESPONSE",
      message: "MX_INVALID_RESPONSE",
    });
  });
});
