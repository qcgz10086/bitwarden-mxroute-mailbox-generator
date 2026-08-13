import type { MailboxPage, MailboxStatus, MailboxSummary } from "../../../packages/contracts/src/index";

declare const document: any;
declare const window: any;
declare const navigator: { clipboard: { writeText(value: string): Promise<void> } };
declare function confirm(message: string): boolean;
declare const Option: new (text?: string, value?: string) => any;
type HTMLElement = any;
type HTMLInputElement = any;
type HTMLSelectElement = any;
type HTMLTableRowElement = any;
type HTMLTableCellElement = any;
type HTMLButtonElement = any;
type HTMLTableSectionElement = any;
type HTMLDialogElement = any;
type Node = any;

interface TextTarget { textContent: string | null; }
export function text(node: TextTarget, value: unknown): void { node.textContent = value === null || value === undefined ? "" : String(value); }

export function formatMailboxRow(mailbox: MailboxSummary) {
  return {
    email: mailbox.email,
    domain: mailbox.domain,
    quota: `${mailbox.quotaMb} MB`,
    status: mailbox.status,
    created: `${mailbox.createdAt.slice(0, 10)} ${mailbox.createdAt.slice(11, 19)} UTC`,
    failure: mailbox.failureCode ?? "—",
  } as const;
}

export function validateDeleteConfirmation(email: string, confirmation: string): boolean { return confirmation === email; }

export function activeDomainNames(domains: readonly { domain: string; active: boolean }[]): string[] {
  return domains.filter((item) => item.active).map((item) => item.domain);
}
export async function runAction(action: () => void | Promise<void>, report: (error: unknown) => void): Promise<void> {
  try { await action(); } catch (error) { report(error); }
}
interface EventSource { addEventListener(name: string, listener: () => void): void; }
export function bindSensitiveLifecycleEvents(
  sources: { visibility: EventSource; navigation: EventSource; tokenDialog: EventSource; isHidden: () => boolean },
  clearMailbox: () => void,
  clearToken: () => void,
): void {
  sources.visibility.addEventListener("visibilitychange", () => { if (sources.isHidden()) clearMailbox(); });
  sources.navigation.addEventListener("hashchange", clearMailbox);
  sources.navigation.addEventListener("pagehide", () => { clearMailbox(); clearToken(); });
  sources.tokenDialog.addEventListener("close", clearToken);
}

export interface SecretTicket {
  readonly signal: AbortSignal;
  accept(value: string): boolean;
}
export class SecretCellController {
  private secret: string | null = null;
  private generation = 0;
  private activeRequest: AbortController | null = null;
  private timer: unknown = null;
  constructor(
    private readonly node: TextTarget,
    private readonly isCurrent: () => boolean,
    private readonly setTimer: (callback: () => void, milliseconds: number) => unknown = setTimeout,
    private readonly clearTimer: (timer: unknown) => void = (timer) => clearTimeout(timer as ReturnType<typeof setTimeout>),
  ) { this.mask(); }
  begin(): SecretTicket {
    this.conceal();
    const request = new AbortController(); this.activeRequest = request;
    const generation = this.generation; let accepted = false;
    return {
      signal: request.signal,
      accept: (value) => {
        if (accepted || request.signal.aborted || generation !== this.generation || !this.isCurrent()) return false;
        accepted = true;
        this.secret = value; text(this.node, value);
        this.timer = this.setTimer(() => this.conceal(), 60_000);
        return true;
      },
    };
  }
  conceal(): void {
    this.generation += 1; this.activeRequest?.abort(); this.activeRequest = null;
    this.secret = null; if (this.timer !== null) this.clearTimer(this.timer); this.timer = null; this.mask();
  }
  value(): string | null { return this.secret; }
  async copyTo(writeText: (value: string) => Promise<void>): Promise<boolean> {
    const current = this.secret; if (current === null || !this.isCurrent()) return false;
    await writeText(current); return true;
  }
  private mask(): void { text(this.node, "••••••••••••••••••"); }
}

export interface SingleSecretTicket { accept(value: string): boolean; cancel(): void; }
export class SingleDisplaySecret {
  private secret: string | null = null;
  private inFlight = false;
  private generation = 0;
  begin(): SingleSecretTicket | null {
    if (this.inFlight || this.secret !== null) return null;
    this.inFlight = true; const generation = ++this.generation;
    return {
      accept: (value) => {
        if (!this.inFlight || generation !== this.generation) return false;
        this.inFlight = false; this.secret = value; return true;
      },
      cancel: () => { if (generation === this.generation) this.inFlight = false; },
    };
  }
  close(): void { this.generation += 1; this.inFlight = false; this.secret = null; }
  value(): string | null { return this.secret; }
  busy(): boolean { return this.inFlight || this.secret !== null; }
  async copyTo(writeText: (value: string) => Promise<void>): Promise<boolean> {
    const current = this.secret; if (current === null) return false; await writeText(current); return true;
  }
}

export interface SettingsInput { mailboxQuotaMb: number; dailyCreationLimit: number; totalManagedLimit: number; }
export function validateSettingsInput(value: SettingsInput): string[] {
  const errors: string[] = [];
  if (!Number.isInteger(value.mailboxQuotaMb) || value.mailboxQuotaMb < 1 || value.mailboxQuotaMb > 102_400) errors.push("Mailbox quota must be an integer from 1 to 102400 MB.");
  if (!Number.isInteger(value.dailyCreationLimit) || value.dailyCreationLimit < 1 || value.dailyCreationLimit > 1_000) errors.push("Daily creation limit must be an integer from 1 to 1000.");
  if (!Number.isInteger(value.totalManagedLimit) || value.totalManagedLimit < 1 || value.totalManagedLimit > 100_000) errors.push("Total managed limit must be an integer from 1 to 100000.");
  return errors;
}

type BrowserRequestInit = RequestInit & { credentials?: "same-origin" };
type Fetcher = (input: RequestInfo | URL, init?: BrowserRequestInit) => Promise<Response>;
export class AdminApi {
  private csrfToken: string | null = null;
  constructor(private readonly fetcher: Fetcher = fetch as Fetcher) {}
  async initialize(): Promise<void> { const session = await this.request<{ csrfToken: string }>("/api/session", { method: "GET" }); this.csrfToken = session.csrfToken; }
  get<T>(path: string): Promise<T> { return this.request<T>(path, { method: "GET" }); }
  mutate<T>(path: string, method: "POST" | "PUT" | "DELETE", body: object = {}, signal?: AbortSignal): Promise<T> {
    if (!this.csrfToken) throw new Error("Session is not initialized.");
    const init: BrowserRequestInit = { method, headers: { "Content-Type": "application/json", "X-CSRF-Token": this.csrfToken }, body: JSON.stringify(body) };
    if (signal) init.signal = signal;
    return this.request<T>(path, init);
  }
  private async request<T>(path: string, init: RequestInit): Promise<T> {
    if (!path.startsWith("/api/") || (path[0] === "/" && path[1] === "/") || path.includes("\\")) throw new Error("Only same-origin API paths are allowed.");
    const response = await this.fetcher(path, { ...init, credentials: "same-origin", headers: { Accept: "application/json", ...init.headers } });
    const data = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) throw new Error(`Request failed (${typeof data.error === "string" ? data.error : response.status}).`);
    return data as T;
  }
}

interface Domain { domain: string; active: boolean; syncedAt: string; }
interface Settings extends SettingsInput { defaultDomain: string | null; prefixLength: number; generationEnabled: boolean; }
interface ApiToken { id: string; name: string; createdAt: string; lastUsedAt: string | null; revokedAt: string | null; }
interface AuditRecord { id: string; actorType: string; actorId: string; actorEmail: string | null; action: string; email: string | null; result: string; errorCode: string | null; requestId: string; createdAt: string; }

export class RecoveryPager {
  private readonly pages = new Map<MailboxStatus, { items: MailboxSummary[]; cursor: string | null }>();
  constructor(
    private readonly fetchPage: (status: MailboxStatus, cursor?: string) => Promise<MailboxPage>,
    private readonly statuses: readonly MailboxStatus[],
  ) {}
  async loadInitial(): Promise<void> { for (const status of this.statuses) await this.load(status, false); }
  async loadMore(status: MailboxStatus): Promise<void> { if (this.pages.get(status)?.cursor) await this.load(status, true); }
  items(status: MailboxStatus): readonly MailboxSummary[] { return this.pages.get(status)?.items ?? []; }
  statusesWithMore(): MailboxStatus[] { return this.statuses.filter((status) => this.pages.get(status)?.cursor); }
  private async load(status: MailboxStatus, append: boolean): Promise<void> {
    const previous = this.pages.get(status); const cursor = append ? previous?.cursor ?? undefined : undefined;
    const page = await this.fetchPage(status, cursor);
    this.pages.set(status, { items: append ? [...(previous?.items ?? []), ...page.items] : [...page.items], cursor: page.nextCursor });
  }
}

const byId = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const status = (message: string): void => text(byId("live-status"), message);
const api = new AdminApi();
let mailboxCursor: string | null = null;
let auditCursor: string | null = null;
let domains: readonly Domain[] = [];
const clearMailboxSecrets = new Set<() => void>();
function concealAllMailboxSecrets(): void { for (const clear of clearMailboxSecrets) clear(); }
const recoveryStatuses: readonly MailboxStatus[] = ["pending", "resetting", "reset_unknown", "deleting", "delete_failed", "failed"];
const recoveryPager = new RecoveryPager(async (state, cursor) => {
  const params = new URLSearchParams({ limit: "100", status: state }); if (cursor) params.set("cursor", cursor);
  return api.get<MailboxPage>(`/api/mailboxes?${params}`);
}, recoveryStatuses);

function cell(row: HTMLTableRowElement, value: unknown): HTMLTableCellElement { const node = row.insertCell(); text(node, value); return node; }
function button(label: string, action: () => void | Promise<void>, danger = false): HTMLButtonElement {
  const node = document.createElement("button"); node.type = "button"; text(node, label); if (danger) node.className = "danger";
  node.addEventListener("click", () => { void runAction(action, fail); }); return node;
}
function fail(error: unknown): void { status(error instanceof Error ? error.message : "Request failed."); }

async function loadMailboxes(cursor?: string): Promise<void> {
  concealAllMailboxSecrets(); clearMailboxSecrets.clear();
  const params = new URLSearchParams({ limit: "50" });
  const search = byId<HTMLInputElement>("mailbox-search").value.trim();
  const domain = byId<HTMLSelectElement>("mailbox-domain").value;
  const state = byId<HTMLSelectElement>("mailbox-status").value;
  if (search) params.set("search", search); if (domain) params.set("domain", domain); if (state) params.set("status", state); if (cursor) params.set("cursor", cursor);
  const page = await api.get<MailboxPage>(`/api/mailboxes?${params}`); mailboxCursor = page.nextCursor;
  const body = byId<HTMLTableSectionElement>("mailbox-rows"); body.replaceChildren();
  for (const mailbox of page.items) renderMailbox(body, mailbox);
  byId<HTMLButtonElement>("mailbox-next").disabled = !mailboxCursor; status(`Loaded ${page.items.length} mailboxes.`);
}

function renderMailbox(body: HTMLTableSectionElement, mailbox: MailboxSummary): void {
  const row = body.insertRow(); const display = formatMailboxRow(mailbox);
  cell(row, display.email); cell(row, display.domain); cell(row, display.quota); cell(row, display.status); cell(row, display.created);
  const passwordCell = cell(row, "••••••••••••••••••"); passwordCell.className = "secret";
  const secret = new SecretCellController(passwordCell, () => row.isConnected && !document.hidden);
  clearMailboxSecrets.add(() => secret.conceal());
  const requestPassword = async (kind: "reveal" | "reset") => {
    const ticket = secret.begin();
    try {
      const result = await api.mutate<{ password: string }>(`/api/mailboxes/${encodeURIComponent(mailbox.publicId)}/${kind}`, "POST", {}, ticket.signal);
      if (ticket.accept(result.password)) status(`${kind === "reset" ? "New" : "Mailbox"} password shown for ${mailbox.email}; it will clear in 60 seconds.`);
    } catch (error) { if (!ticket.signal.aborted) throw error; }
  };
  const actions = row.insertCell(); actions.className = "actions";
  actions.append(button("Reveal", () => requestPassword("reveal")), button("Copy", async () => { if (!await secret.copyTo((value) => navigator.clipboard.writeText(value))) return status("Reveal the password before copying."); status("Password copied."); }), button("Hide", () => secret.conceal()));
  actions.append(button("Reset", async () => { if (confirm(`Reset the password for ${mailbox.email}?`)) await requestPassword("reset"); }, true));
  actions.append(button("Delete", () => openDelete(mailbox, () => secret.conceal()), true));
  row.addEventListener("focusout", (event: { relatedTarget: Node | null }) => { if (!row.contains(event.relatedTarget)) secret.conceal(); });
}

function openDelete(mailbox: MailboxSummary, conceal: () => void): void {
  conceal(); concealAllMailboxSecrets(); const dialog = byId<HTMLDialogElement>("delete-dialog"); const input = byId<HTMLInputElement>("delete-confirmation");
  text(byId("delete-email"), mailbox.email); input.value = ""; input.dataset.email = mailbox.email; input.dataset.id = mailbox.publicId; dialog.showModal(); input.focus();
}

async function loadDomains(): Promise<void> {
  domains = await api.get<readonly Domain[]>("/api/domains"); const body = byId<HTMLTableSectionElement>("domain-rows"); body.replaceChildren();
  const filter = byId<HTMLSelectElement>("mailbox-domain"); const selected = filter.value; filter.replaceChildren(new Option("All domains", ""));
  const active = new Set(activeDomainNames(domains));
  for (const domain of domains) { const row = body.insertRow(); cell(row, domain.domain); cell(row, domain.active ? "Active" : "Inactive"); cell(row, domain.syncedAt); if (active.has(domain.domain)) filter.append(new Option(domain.domain, domain.domain)); }
  filter.value = selected; status(`Loaded ${domains.length} domains.`);
}

async function loadSettings(): Promise<void> {
  const settings = await api.get<Settings>("/api/settings");
  byId<HTMLInputElement>("quota").value = String(settings.mailboxQuotaMb); byId<HTMLInputElement>("daily-limit").value = String(settings.dailyCreationLimit); byId<HTMLInputElement>("total-limit").value = String(settings.totalManagedLimit); byId<HTMLInputElement>("generation-enabled").checked = settings.generationEnabled;
  const select = byId<HTMLSelectElement>("default-domain"); select.replaceChildren(new Option("Select an active domain", "")); for (const domain of activeDomainNames(domains)) select.append(new Option(domain, domain)); select.value = settings.defaultDomain ?? "";
}

async function loadTokens(): Promise<void> {
  const tokens = await api.get<readonly ApiToken[]>("/api/tokens"); const body = byId<HTMLTableSectionElement>("token-rows"); body.replaceChildren();
  for (const token of tokens) { const row = body.insertRow(); cell(row, token.name); cell(row, token.createdAt); cell(row, token.lastUsedAt ?? "Never"); cell(row, token.revokedAt ? "Revoked" : "Active"); const actions = row.insertCell(); if (!token.revokedAt) actions.append(button("Revoke", async () => { if (!confirm(`Revoke token ${token.name}?`)) return; await api.mutate(`/api/tokens/${encodeURIComponent(token.id)}`, "DELETE"); await loadTokens(); }, true)); }
}

async function loadAudit(cursor?: string): Promise<void> {
  const params = new URLSearchParams({ limit: "50" }); if (cursor) params.set("cursor", cursor); const page = await api.get<{ items: readonly AuditRecord[]; nextCursor: string | null }>(`/api/audit?${params}`); auditCursor = page.nextCursor;
  const body = byId<HTMLTableSectionElement>("audit-rows"); body.replaceChildren(); for (const item of page.items) { const row = body.insertRow(); cell(row, item.createdAt); cell(row, item.actorEmail ?? item.actorId); cell(row, item.action); cell(row, item.email ?? "—"); cell(row, item.result); cell(row, item.errorCode ?? "—"); cell(row, item.requestId); } byId<HTMLButtonElement>("audit-next").disabled = !auditCursor;
}

function renderRecovery(): void {
  const body = byId<HTMLTableSectionElement>("recovery-rows"); body.replaceChildren();
  for (const state of recoveryStatuses) for (const item of recoveryPager.items(state)) { const row = body.insertRow(); cell(row, item.email); cell(row, item.status); cell(row, item.failureCode ?? "—"); cell(row, item.createdAt); }
  const more = recoveryPager.statusesWithMore(); byId<HTMLButtonElement>("recovery-more").disabled = more.length === 0;
  text(byId("recovery-truncation"), more.length ? `More records are available for: ${more.join(", ")}.` : "All recovery records are displayed.");
}
async function loadRecovery(): Promise<void> { await recoveryPager.loadInitial(); renderRecovery(); }
async function loadMoreRecovery(): Promise<void> {
  for (const state of recoveryPager.statusesWithMore()) await recoveryPager.loadMore(state); renderRecovery();
}

function bind(): void {
  const tokenGate = new SingleDisplaySecret(); const tokenButton = byId<HTMLButtonElement>("create-token");
  byId("mailbox-filter").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); void loadMailboxes().catch(fail); }); byId("mailbox-next").addEventListener("click", () => { if (mailboxCursor) void loadMailboxes(mailboxCursor).catch(fail); });
  byId("sync-domains").addEventListener("click", () => void api.mutate<readonly Domain[]>("/api/domains/sync", "POST").then(async () => { await loadDomains(); await loadSettings(); }).catch(fail));
  byId("default-domain-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const domain = byId<HTMLSelectElement>("default-domain").value; if (!domains.some((item) => item.active && item.domain === domain)) return status("Choose an active domain."); void api.mutate("/api/domains/default", "PUT", { domain }).then(() => status("Default domain saved.")).catch(fail); });
  byId("settings-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const value = { mailboxQuotaMb: Number(byId<HTMLInputElement>("quota").value), dailyCreationLimit: Number(byId<HTMLInputElement>("daily-limit").value), totalManagedLimit: Number(byId<HTMLInputElement>("total-limit").value) }; const errors = validateSettingsInput(value); if (errors.length) return status(errors.join(" ")); void api.mutate("/api/settings", "PUT", { ...value, generationEnabled: byId<HTMLInputElement>("generation-enabled").checked }).then(() => status("Settings saved.")).catch(fail); });
  byId("token-form").addEventListener("submit", (event: { preventDefault(): void }) => {
    event.preventDefault(); const name = byId<HTMLInputElement>("token-name").value.trim(); if (!name) return;
    const ticket = tokenGate.begin(); if (!ticket) return status("Save or dismiss the current token before creating another."); tokenButton.disabled = true;
    void api.mutate<{ rawToken: string }>("/api/tokens", "POST", { name }).then(async (result) => {
      if (!ticket.accept(result.rawToken)) return;
      concealAllMailboxSecrets(); text(byId("raw-token"), tokenGate.value()); byId<HTMLDialogElement>("token-dialog").showModal(); await loadTokens();
    }).catch((error) => { ticket.cancel(); fail(error); }).finally(() => { tokenButton.disabled = tokenGate.busy(); });
  });
  byId("copy-token").addEventListener("click", () => { void tokenGate.copyTo((value) => navigator.clipboard.writeText(value)).then((copied) => { if (copied) status("Token copied."); }).catch(fail); });
  const clearToken = () => { tokenGate.close(); text(byId("raw-token"), ""); tokenButton.disabled = false; };
  const tokenDialog = byId<HTMLDialogElement>("token-dialog");
  byId("dismiss-token").addEventListener("click", () => { const dialog = byId<HTMLDialogElement>("token-dialog"); clearToken(); dialog.close(); });
  byId("delete-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const input = byId<HTMLInputElement>("delete-confirmation"); if (!validateDeleteConfirmation(input.dataset.email ?? "", input.value)) return status("Type the complete email address exactly."); void api.mutate(`/api/mailboxes/${encodeURIComponent(input.dataset.id ?? "")}`, "DELETE", { confirmationEmail: input.value }).then(async () => { byId<HTMLDialogElement>("delete-dialog").close(); await loadMailboxes(); await loadRecovery(); status("Mailbox permanently deleted."); }).catch(fail); });
  byId("cancel-delete").addEventListener("click", () => byId<HTMLDialogElement>("delete-dialog").close()); byId("audit-next").addEventListener("click", () => { if (auditCursor) void loadAudit(auditCursor).catch(fail); }); byId("refresh-recovery").addEventListener("click", () => void loadRecovery().catch(fail)); byId("recovery-more").addEventListener("click", () => void loadMoreRecovery().catch(fail));
  bindSensitiveLifecycleEvents({ visibility: document, navigation: window, tokenDialog, isHidden: () => document.hidden }, concealAllMailboxSecrets, clearToken);
}

async function start(): Promise<void> { bind(); await api.initialize(); await loadDomains(); await Promise.all([loadMailboxes(), loadSettings(), loadTokens(), loadAudit(), loadRecovery()]); status("Management data loaded."); }
if (typeof document !== "undefined") void start().catch(fail);
