import { describe, expect, it, vi } from "vitest";
import type { MailboxPage, MailboxStatus, MailboxSummary } from "../../packages/contracts/src/index";
import {
  AdminApi,
  RecoveryPager,
  SecretCellController,
  SingleDisplaySecret,
  TokenCreationWorkflow,
  activeDomainNames,
  bindSensitiveLifecycleEvents,
  formatMailboxRow,
  runAction,
  performExactDelete,
  runDisabled,
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

  it("forwards an AbortSignal from a secret operation to fetch", async () => {
    const fetcher = vi.fn(async (path: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify(path === "/api/session" ? { csrfToken: "csrf" } : { password: "secret" })));
    const api = new AdminApi(fetcher); await api.initialize(); const controller = new AbortController();
    await api.mutate("/api/mailboxes/m1/reveal", "POST", {}, controller.signal);
    expect(fetcher.mock.calls[1]?.[1]?.signal).toBe(controller.signal);
    await api.get("/api/mailboxes?status=pending", controller.signal);
    expect(fetcher.mock.calls[2]?.[1]?.signal).toBe(controller.signal);
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

  it("compensates exactly once when pagehide wins the race with successful token creation", async () => {
    const creation = deferred<{ id: string; rawToken: string }>();
    const create = vi.fn(() => creation.promise); const revoke = vi.fn(async () => undefined); const display = vi.fn(); const clear = vi.fn();
    const workflow = new TokenCreationWorkflow({ create, revoke, display, clear, report: vi.fn() });
    const pending = workflow.create("phone"); workflow.pagehide();
    creation.resolve({ id: "token-1", rawToken: "one-time-raw" });
    await expect(pending).resolves.toBe("revoked");
    expect(create).toHaveBeenCalledTimes(1); expect(revoke).toHaveBeenCalledExactlyOnceWith("token-1");
    expect(display).not.toHaveBeenCalled(); expect(JSON.stringify(revoke.mock.calls)).not.toContain("one-time-raw");
  });

  it("revokes an unsaved displayed token on pagehide but retains a successfully copied token", async () => {
    const revoke = vi.fn(async () => undefined); const display = vi.fn();
    const workflow = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "t1", rawToken: "raw1" })), revoke, display, clear: vi.fn(), report: vi.fn() });
    await expect(workflow.create("first")).resolves.toBe("displayed"); workflow.pagehide(); await workflow.compensation();
    expect(revoke).toHaveBeenCalledExactlyOnceWith("t1");

    const secondRevoke = vi.fn(async () => undefined); const copied = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "t2", rawToken: "raw2" })), revoke: secondRevoke, display: vi.fn(), clear: vi.fn(), report: vi.fn() });
    await copied.create("second"); await copied.copyTo(async () => undefined); copied.pagehide(); await copied.compensation();
    expect(secondRevoke).not.toHaveBeenCalled();
  });

  it("keeps compensation failures secret-free and reports only while context remains", async () => {
    const report = vi.fn(); const display = vi.fn();
    const workflow = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "t1", rawToken: "never-log-this" })), revoke: vi.fn(async () => { throw new Error("upstream leaked body"); }), display, clear: vi.fn(), report });
    await workflow.create("x"); workflow.pagehide(); await workflow.compensation();
    expect(display).toHaveBeenCalledTimes(1); expect(report).not.toHaveBeenCalled();
    expect(JSON.stringify(report.mock.calls)).not.toContain("never-log-this");
  });

  it("compensates a created token when display throws without misreporting creation failure", async () => {
    const revoke = vi.fn(async () => undefined); const report = vi.fn(); const clear = vi.fn();
    const workflow = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "created-id", rawToken: "display-secret" })), revoke, display: vi.fn(() => { throw new Error("DOM detached: display-secret"); }), clear, report });
    await expect(workflow.create("broken-display")).resolves.toBe("display-compensated");
    expect(revoke).toHaveBeenCalledExactlyOnceWith("created-id"); expect(clear).toHaveBeenCalled(); expect(workflow.busy()).toBe(false);
    expect(report).toHaveBeenCalledWith("TOKEN_DISPLAY_FAILED_COMPENSATED"); expect(report).not.toHaveBeenCalledWith("TOKEN_CREATE_FAILED");
    expect(JSON.stringify(report.mock.calls)).not.toContain("display-secret");
  });

  it("keeps display-compensation failure secret-free and the workflow reusable", async () => {
    const report = vi.fn(); const revoke = vi.fn(async () => { throw new Error("secret upstream detail"); });
    const workflow = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "created-id", rawToken: "raw-never-report" })), revoke, display: vi.fn(() => { throw new Error("display failed raw-never-report"); }), clear: vi.fn(), report });
    await expect(workflow.create("broken-display")).resolves.toBe("display-compensation-failed");
    expect(revoke).toHaveBeenCalledExactlyOnceWith("created-id"); expect(workflow.busy()).toBe(false);
    expect(report).toHaveBeenCalledWith("TOKEN_DISPLAY_FAILED_COMPENSATION_FAILED");
    expect(JSON.stringify(report.mock.calls)).not.toContain("raw-never-report");
  });

  it("does not mark a token saved when close invalidates it while clipboard is pending", async () => {
    const clipboard = deferred<void>(); const revoke = vi.fn(async () => undefined);
    const workflow = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "t-close", rawToken: "raw-close" })), revoke, display: vi.fn(), clear: vi.fn(), report: vi.fn() });
    await workflow.create("close"); const copying = workflow.copyTo(() => clipboard.promise); workflow.closeWithoutSave(); clipboard.resolve();
    await expect(copying).resolves.toBe(false); await workflow.compensation(); expect(revoke).toHaveBeenCalledExactlyOnceWith("t-close");
  });

  it("does not announce saved when pagehide invalidates a pending clipboard write", async () => {
    const clipboard = deferred<void>(); const revoke = vi.fn(async () => undefined);
    const workflow = new TokenCreationWorkflow({ create: vi.fn(async () => ({ id: "t-hide", rawToken: "raw-hide" })), revoke, display: vi.fn(), clear: vi.fn(), report: vi.fn() });
    await workflow.create("hide"); const copying = workflow.copyTo(() => clipboard.promise); workflow.pagehide(); clipboard.resolve();
    await expect(copying).resolves.toBe(false); await workflow.compensation(); expect(revoke).toHaveBeenCalledExactlyOnceWith("t-hide");
  });

  it("filters default-domain choices to active domains and keeps exact delete semantics", () => {
    expect(activeDomainNames([{ domain: "active.example", active: true }, { domain: "old.example", active: false }])).toEqual(["active.example"]);
    expect(validateDeleteConfirmation("victim@example.com", "victim@example.com")).toBe(true);
    expect(validateDeleteConfirmation("victim@example.com", " victim@example.com")).toBe(false);
  });

  it("wires exact delete body and closes the dialog only after success", async () => {
    const mutate = vi.fn(async () => ({ requestId: "r" })); const close = vi.fn();
    await expect(performExactDelete("m1", "mail@example.com", "wrong@example.com", mutate, close)).resolves.toBe(false);
    expect(mutate).not.toHaveBeenCalled(); expect(close).not.toHaveBeenCalled();
    await expect(performExactDelete("m1", "mail@example.com", "mail@example.com", mutate, close)).resolves.toBe(true);
    expect(mutate).toHaveBeenCalledWith("/api/mailboxes/m1", "DELETE", { confirmationEmail: "mail@example.com" }); expect(close).toHaveBeenCalledTimes(1);
  });

  it("disables a real event control for the duration and ignores rapid re-entry", async () => {
    const button = { disabled: false }; const operation = deferred<void>(); const action = vi.fn(() => operation.promise);
    const first = runDisabled(button, action); const second = runDisabled(button, action);
    expect(button.disabled).toBe(true); await expect(second).resolves.toBe(false); expect(action).toHaveBeenCalledTimes(1);
    operation.resolve(); await expect(first).resolves.toBe(true); expect(button.disabled).toBe(false);
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

  it("deduplicates rapid load-more and ignores a late page invalidated by refresh", async () => {
    const late = deferred<MailboxPage>(); let initial = 0; let staleSignal: AbortSignal | undefined;
    const fetchPage = vi.fn(async (status: MailboxStatus, cursor?: string, signal?: AbortSignal): Promise<MailboxPage> => {
      if (cursor) { staleSignal = signal; return late.promise; }
      initial += 1; return { items: [{ ...mailbox, publicId: `${status}-${initial}`, status }], nextCursor: initial === 1 ? "old-next" : null };
    });
    const pager = new RecoveryPager(fetchPage, ["pending"]); await pager.refresh();
    const more1 = pager.loadMore("pending"); const more2 = pager.loadMore("pending");
    expect(fetchPage).toHaveBeenCalledTimes(2); expect(pager.statusBusy("pending")).toBe(true);
    const refresh = pager.refresh(); expect(pager.refreshBusy()).toBe(true);
    expect(staleSignal?.aborted).toBe(true);
    late.resolve({ items: [{ ...mailbox, publicId: "stale", status: "pending" }], nextCursor: null });
    await Promise.all([more1, more2, refresh]);
    expect(pager.items("pending").map((item) => item.publicId)).not.toContain("stale");
    expect(fetchPage).toHaveBeenCalledTimes(3);
  });

  it("deduplicates rapid refresh calls", async () => {
    const page = deferred<MailboxPage>(); const fetchPage = vi.fn(() => page.promise); const pager = new RecoveryPager(fetchPage, ["pending"]);
    const first = pager.refresh(); const second = pager.refresh(); expect(fetchPage).toHaveBeenCalledTimes(1);
    page.resolve({ items: [], nextCursor: null }); await Promise.all([first, second]); expect(pager.refreshBusy()).toBe(false);
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
