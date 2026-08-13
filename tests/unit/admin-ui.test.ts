import { describe, expect, it, vi } from "vitest";
import type { MailboxSummary } from "../../packages/contracts/src/index";
import {
  AdminApi,
  formatMailboxRow,
  text,
  validateDeleteConfirmation,
  validateSettingsInput,
} from "../../workers/admin/ui/app";

const mailbox: MailboxSummary = {
  publicId: "m-1",
  email: "<img src=x onerror=alert(1)>",
  domain: "<svg onload=alert(1)>",
  quotaMb: 100,
  status: "active",
  createdAt: "2026-08-13T00:00:00.000Z",
  failureCode: null,
};

describe("admin UI safe helpers", () => {
  it("assigns hostile values only through textContent", () => {
    let assigned = "";
    const node = {
      get textContent() { return assigned; },
      set textContent(value: string | null) { assigned = value ?? ""; },
      set innerHTML(_value: string) { throw new Error("innerHTML must not be used"); },
    };
    text(node, mailbox.email);
    expect(assigned).toBe(mailbox.email);
  });

  it("formats mailbox data without producing markup", () => {
    expect(formatMailboxRow(mailbox)).toEqual({
      email: mailbox.email,
      domain: mailbox.domain,
      quota: "100 MB",
      status: "active",
      created: "2026-08-13 00:00:00 UTC",
      failure: "—",
    });
  });

  it("requires an exact complete email for permanent deletion", () => {
    expect(validateDeleteConfirmation("case@example.com", "case@example.com")).toBe(true);
    expect(validateDeleteConfirmation("case@example.com", "CASE@example.com")).toBe(false);
    expect(validateDeleteConfirmation("case@example.com", " case@example.com ")).toBe(false);
    expect(validateDeleteConfirmation("case@example.com", "case@example.co")).toBe(false);
  });

  it("enforces the browser settings bounds", () => {
    expect(validateSettingsInput({ mailboxQuotaMb: 1, dailyCreationLimit: 1, totalManagedLimit: 1 })).toEqual([]);
    expect(validateSettingsInput({ mailboxQuotaMb: 102_400, dailyCreationLimit: 1_000, totalManagedLimit: 100_000 })).toEqual([]);
    expect(validateSettingsInput({ mailboxQuotaMb: 0, dailyCreationLimit: 1_001, totalManagedLimit: 100_001 })).toEqual([
      "Mailbox quota must be an integer from 1 to 102400 MB.",
      "Daily creation limit must be an integer from 1 to 1000.",
      "Total managed limit must be an integer from 1 to 100000.",
    ]);
  });
});

describe("AdminApi", () => {
  it("gets a session and sends CSRF only on same-origin mutations", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path === "/api/session") return new Response(JSON.stringify({ csrfToken: "csrf-value" }), { headers: { "Content-Type": "application/json" } });
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    });
    const api = new AdminApi(fetcher);
    await api.initialize();
    await api.get("/api/mailboxes?limit=50");
    await api.mutate("/api/settings", "PUT", { mailboxQuotaMb: 100 });

    expect(fetcher.mock.calls[0]?.[0]).toBe("/api/session");
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ credentials: "same-origin", method: "GET" });
    const mutation = fetcher.mock.calls[2]?.[1];
    expect(new Headers(mutation?.headers).get("X-CSRF-Token")).toBe("csrf-value");
    expect(new Headers(mutation?.headers).get("Content-Type")).toBe("application/json");
    expect(mutation?.body).toBe(JSON.stringify({ mailboxQuotaMb: 100 }));
  });

  it("does not leak response bodies through errors", async () => {
    const api = new AdminApi(async () => new Response(JSON.stringify({ error: "INVALID_STATE", secret: "upstream details" }), { status: 409 }));
    await expect(api.get("/api/mailboxes")).rejects.toThrow("Request failed (INVALID_STATE).");
  });

  it("rejects absolute or cross-origin paths before fetching", async () => {
    const fetcher = vi.fn();
    const api = new AdminApi(fetcher);
    await expect(api.get("https://evil.example/steal")).rejects.toThrow("Only same-origin API paths are allowed.");
    expect(fetcher).not.toHaveBeenCalled();
  });
});
