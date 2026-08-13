import { describe, expect, it, vi } from "vitest";
import type { MailboxSummary } from "../../packages/contracts/src/index";
import {
  AdminApi,
  RecoveryPager,
  SecretCellController,
  SingleDisplaySecret,
  activeDomainNames,
  bindSensitiveLifecycleEvents,
  formatMailboxRow,
  runAction,
  text,
  validateDeleteConfirmation,
  validateSettingsInput,
} from "../../workers/admin/ui/app";
import { findUnsafeAssetContent } from "../../scripts/admin-asset-policy.mjs";

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

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("sensitive event workflows", () => {
  it("integrates dialog, visibility, navigation, and page-hide events with secret cleanup", () => {
    class Events {
      listeners = new Map<string, Array<() => void>>();
      addEventListener(name: string, listener: () => void) { this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]); }
      dispatch(name: string) { for (const listener of this.listeners.get(name) ?? []) listener(); }
    }
    const visibility = new Events(); const navigation = new Events(); const dialog = new Events();
    const clearMailbox = vi.fn(); const clearToken = vi.fn(); let hidden = false;
    bindSensitiveLifecycleEvents({ visibility, navigation, tokenDialog: dialog, isHidden: () => hidden }, clearMailbox, clearToken);
    visibility.dispatch("visibilitychange"); expect(clearMailbox).not.toHaveBeenCalled();
    hidden = true; visibility.dispatch("visibilitychange"); navigation.dispatch("hashchange"); dialog.dispatch("close"); navigation.dispatch("pagehide");
    expect(clearMailbox).toHaveBeenCalledTimes(3); expect(clearToken).toHaveBeenCalledTimes(2);
  });
  it("invalidates hidden and overlapping password responses before they can reach the DOM", async () => {
    const node = { textContent: "" };
    const timers: Array<() => void> = [];
    const first = deferred<string>(); const second = deferred<string>();
    const controller = new SecretCellController(node, () => true, (callback) => { timers.push(callback); return timers.length; }, () => undefined);
    const stale = controller.begin();
    const current = controller.begin();
    first.promise.then((password) => stale.accept(password));
    second.promise.then((password) => current.accept(password));
    first.resolve("OldSecret123"); await first.promise; await Promise.resolve();
    expect(node.textContent).toBe("••••••••••••••••••"); expect(controller.value()).toBeNull();
    second.resolve("NewSecret123"); await second.promise; await Promise.resolve();
    expect(node.textContent).toBe("NewSecret123"); expect(controller.value()).toBe("NewSecret123");
    controller.conceal();
    expect(current.signal.aborted).toBe(true); expect(node.textContent).toBe("••••••••••••••••••");
    expect(current.accept("Resurrected123")).toBe(false);
  });

  it("rejects a late response after navigation and clears accepted secrets on the fake 60-second timer", () => {
    const node = { textContent: "" }; let connected = true; const timers: Array<() => void> = [];
    const controller = new SecretCellController(node, () => connected, (callback) => { timers.push(callback); return timers.length; }, () => undefined);
    const late = controller.begin(); connected = false;
    expect(late.accept("LateSecret123")).toBe(false); expect(node.textContent).not.toContain("LateSecret123");
    connected = true; const accepted = controller.begin(); expect(accepted.accept("TimedSecret123")).toBe(true);
    timers.at(-1)?.(); expect(controller.value()).toBeNull(); expect(node.textContent).toBe("••••••••••••••••••");
  });

  it("copies only when a direct copy event supplies a clipboard callback", async () => {
    const controller = new SecretCellController({ textContent: "" }, () => true);
    expect(controller.begin().accept("CopySecret123")).toBe(true);
    const write = vi.fn(async () => undefined);
    await controller.copyTo(write);
    expect(write).toHaveBeenCalledWith("CopySecret123");
    controller.conceal(); await expect(controller.copyTo(write)).resolves.toBe(false);
    expect(write).toHaveBeenCalledTimes(1);
  });

  it("routes each asynchronous event failure to status exactly once", async () => {
    const report = vi.fn();
    await runAction(async () => { throw new Error("clipboard denied"); }, report);
    expect(report).toHaveBeenCalledTimes(1);
    expect(report).toHaveBeenCalledWith(expect.objectContaining({ message: "clipboard denied" }));
    await runAction(async () => undefined, report);
    expect(report).toHaveBeenCalledTimes(1);
  });

  it("allows only one token creation response and clears it on dialog Escape/close", async () => {
    const gate = new SingleDisplaySecret(); const first = gate.begin(); const second = gate.begin();
    expect(first).not.toBeNull(); expect(second).toBeNull();
    expect(first?.accept("raw-token-one")).toBe(true); expect(gate.value()).toBe("raw-token-one");
    expect(gate.begin()).toBeNull();
    const write = vi.fn(async () => undefined); await gate.copyTo(write); expect(write).toHaveBeenCalledWith("raw-token-one");
    gate.close(); expect(gate.value()).toBeNull();
    expect(first?.accept("late-token")).toBe(false);
    expect(gate.begin()).not.toBeNull();
  });

  it("filters default-domain choices to active domains and keeps exact delete semantics", () => {
    expect(activeDomainNames([{ domain: "active.example", active: true }, { domain: "old.example", active: false }])).toEqual(["active.example"]);
    expect(validateDeleteConfirmation("victim@example.com", "victim@example.com")).toBe(true);
    expect(validateDeleteConfirmation("victim@example.com", " victim@example.com")).toBe(false);
  });
});

describe("recovery pagination", () => {
  it("preserves per-status cursors and appends every page without silently truncating", async () => {
    const calls: string[] = [];
    const pager = new RecoveryPager(async (status, cursor) => {
      calls.push(`${status}:${cursor ?? "first"}`);
      return cursor ? { items: [{ ...mailbox, publicId: `${status}-2`, status }], nextCursor: null }
        : { items: [{ ...mailbox, publicId: `${status}-1`, status }], nextCursor: `${status}-next` };
    }, ["pending", "delete_failed"]);
    await pager.loadInitial();
    expect(pager.statusesWithMore()).toEqual(["pending", "delete_failed"]);
    await pager.loadMore("pending");
    expect(pager.items("pending")).toHaveLength(2); expect(pager.statusesWithMore()).toEqual(["delete_failed"]);
    expect(calls).toEqual(["pending:first", "delete_failed:first", "pending:pending-next"]);
  });
});

describe("admin asset policy", () => {
  it.each(["//cdn.example/app.js", "data:text/javascript,alert(1)", "javascript:alert(1)", "wss://evil.example", "blob:opaque", "import('local-package')", "import('ftp://evil.example/x.js')", "//# sourceMappingURL=x.map", "eval('x')"])("rejects remote or executable asset content: %s", (fixture) => {
    expect(findUnsafeAssetContent(fixture)).not.toBeNull();
  });
  it("accepts bundled same-origin application output", () => {
    expect(findUnsafeAssetContent("const path='/api/mailboxes';document.querySelector('#app');")).toBeNull();
  });
});
