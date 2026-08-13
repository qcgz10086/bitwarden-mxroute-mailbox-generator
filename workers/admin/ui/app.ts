import type { MailboxPage, MailboxStatus, MailboxSummary } from "../../../packages/contracts/src/index";

declare const document: any;
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
  mutate<T>(path: string, method: "POST" | "PUT" | "DELETE", body: object = {}): Promise<T> {
    if (!this.csrfToken) throw new Error("Session is not initialized.");
    return this.request<T>(path, { method, headers: { "Content-Type": "application/json", "X-CSRF-Token": this.csrfToken }, body: JSON.stringify(body) });
  }
  private async request<T>(path: string, init: RequestInit): Promise<T> {
    if (!path.startsWith("/api/") || path.startsWith("//") || path.includes("\\")) throw new Error("Only same-origin API paths are allowed.");
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

const byId = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const status = (message: string): void => text(byId("live-status"), message);
const api = new AdminApi();
let mailboxCursor: string | null = null;
let auditCursor: string | null = null;
let domains: readonly Domain[] = [];
const clearMailboxSecrets = new Set<() => void>();

function cell(row: HTMLTableRowElement, value: unknown): HTMLTableCellElement { const node = row.insertCell(); text(node, value); return node; }
function button(label: string, action: () => void | Promise<void>, danger = false): HTMLButtonElement {
  const node = document.createElement("button"); node.type = "button"; text(node, label); if (danger) node.className = "danger";
  node.addEventListener("click", () => void action()); return node;
}
function fail(error: unknown): void { status(error instanceof Error ? error.message : "Request failed."); }

async function loadMailboxes(cursor?: string): Promise<void> {
  const params = new URLSearchParams({ limit: "50" });
  const search = byId<HTMLInputElement>("mailbox-search").value.trim();
  const domain = byId<HTMLSelectElement>("mailbox-domain").value;
  const state = byId<HTMLSelectElement>("mailbox-status").value;
  if (search) params.set("search", search); if (domain) params.set("domain", domain); if (state) params.set("status", state); if (cursor) params.set("cursor", cursor);
  const page = await api.get<MailboxPage>(`/api/mailboxes?${params}`); mailboxCursor = page.nextCursor;
  for (const clear of clearMailboxSecrets) clear(); clearMailboxSecrets.clear();
  const body = byId<HTMLTableSectionElement>("mailbox-rows"); body.replaceChildren();
  for (const mailbox of page.items) renderMailbox(body, mailbox);
  byId<HTMLButtonElement>("mailbox-next").disabled = !mailboxCursor; status(`Loaded ${page.items.length} mailboxes.`);
}

function renderMailbox(body: HTMLTableSectionElement, mailbox: MailboxSummary): void {
  const row = body.insertRow(); const display = formatMailboxRow(mailbox);
  cell(row, display.email); cell(row, display.domain); cell(row, display.quota); cell(row, display.status); cell(row, display.created);
  const passwordCell = cell(row, "••••••••••••••••••"); passwordCell.className = "secret";
  let password: string | null = null; let clearTimer: ReturnType<typeof setTimeout> | null = null;
  const conceal = () => { password = null; text(passwordCell, "••••••••••••••••••"); if (clearTimer) clearTimeout(clearTimer); clearTimer = null; };
  clearMailboxSecrets.add(conceal);
  const reveal = async () => { conceal(); const result = await api.mutate<{ password: string }>(`/api/mailboxes/${encodeURIComponent(mailbox.publicId)}/reveal`, "POST"); password = result.password; text(passwordCell, password); clearTimer = setTimeout(conceal, 60_000); status(`Password revealed for ${mailbox.email}; it will clear in 60 seconds.`); };
  const actions = row.insertCell(); actions.className = "actions";
  actions.append(button("Reveal", () => reveal().catch(fail)), button("Copy", async () => { if (!password) return status("Reveal the password before copying."); await navigator.clipboard.writeText(password); status("Password copied."); }), button("Hide", conceal));
  actions.append(button("Reset", async () => { if (!confirm(`Reset the password for ${mailbox.email}?`)) return; conceal(); const result = await api.mutate<{ password: string }>(`/api/mailboxes/${encodeURIComponent(mailbox.publicId)}/reset`, "POST"); password = result.password; text(passwordCell, password); clearTimer = setTimeout(conceal, 60_000); status("Password reset. Copy it now; it will clear in 60 seconds."); }, true));
  actions.append(button("Delete", () => openDelete(mailbox, conceal), true));
  row.addEventListener("focusout", (event: { relatedTarget: Node | null }) => { if (!row.contains(event.relatedTarget)) conceal(); });
}

function openDelete(mailbox: MailboxSummary, conceal: () => void): void {
  conceal(); const dialog = byId<HTMLDialogElement>("delete-dialog"); const input = byId<HTMLInputElement>("delete-confirmation");
  text(byId("delete-email"), mailbox.email); input.value = ""; input.dataset.email = mailbox.email; input.dataset.id = mailbox.publicId; dialog.showModal(); input.focus();
}

async function loadDomains(): Promise<void> {
  domains = await api.get<readonly Domain[]>("/api/domains"); const body = byId<HTMLTableSectionElement>("domain-rows"); body.replaceChildren();
  const filter = byId<HTMLSelectElement>("mailbox-domain"); const selected = filter.value; filter.replaceChildren(new Option("All domains", ""));
  for (const domain of domains) { const row = body.insertRow(); cell(row, domain.domain); cell(row, domain.active ? "Active" : "Inactive"); cell(row, domain.syncedAt); if (domain.active) filter.append(new Option(domain.domain, domain.domain)); }
  filter.value = selected; status(`Loaded ${domains.length} domains.`);
}

async function loadSettings(): Promise<void> {
  const settings = await api.get<Settings>("/api/settings");
  byId<HTMLInputElement>("quota").value = String(settings.mailboxQuotaMb); byId<HTMLInputElement>("daily-limit").value = String(settings.dailyCreationLimit); byId<HTMLInputElement>("total-limit").value = String(settings.totalManagedLimit); byId<HTMLInputElement>("generation-enabled").checked = settings.generationEnabled;
  const select = byId<HTMLSelectElement>("default-domain"); select.replaceChildren(new Option("Select an active domain", "")); for (const domain of domains.filter((item) => item.active)) select.append(new Option(domain.domain, domain.domain)); select.value = settings.defaultDomain ?? "";
}

async function loadTokens(): Promise<void> {
  const tokens = await api.get<readonly ApiToken[]>("/api/tokens"); const body = byId<HTMLTableSectionElement>("token-rows"); body.replaceChildren();
  for (const token of tokens) { const row = body.insertRow(); cell(row, token.name); cell(row, token.createdAt); cell(row, token.lastUsedAt ?? "Never"); cell(row, token.revokedAt ? "Revoked" : "Active"); const actions = row.insertCell(); if (!token.revokedAt) actions.append(button("Revoke", async () => { if (!confirm(`Revoke token ${token.name}?`)) return; await api.mutate(`/api/tokens/${encodeURIComponent(token.id)}`, "DELETE"); await loadTokens(); }, true)); }
}

async function loadAudit(cursor?: string): Promise<void> {
  const params = new URLSearchParams({ limit: "50" }); if (cursor) params.set("cursor", cursor); const page = await api.get<{ items: readonly AuditRecord[]; nextCursor: string | null }>(`/api/audit?${params}`); auditCursor = page.nextCursor;
  const body = byId<HTMLTableSectionElement>("audit-rows"); body.replaceChildren(); for (const item of page.items) { const row = body.insertRow(); cell(row, item.createdAt); cell(row, item.actorEmail ?? item.actorId); cell(row, item.action); cell(row, item.email ?? "—"); cell(row, item.result); cell(row, item.errorCode ?? "—"); cell(row, item.requestId); } byId<HTMLButtonElement>("audit-next").disabled = !auditCursor;
}

async function loadRecovery(): Promise<void> {
  const states: readonly MailboxStatus[] = ["pending", "resetting", "reset_unknown", "deleting", "delete_failed", "failed"]; const body = byId<HTMLTableSectionElement>("recovery-rows"); body.replaceChildren();
  for (const state of states) { const page = await api.get<MailboxPage>(`/api/mailboxes?limit=100&status=${state}`); for (const item of page.items) { const row = body.insertRow(); cell(row, item.email); cell(row, item.status); cell(row, item.failureCode ?? "—"); cell(row, item.createdAt); } }
}

function bind(): void {
  byId("mailbox-filter").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); void loadMailboxes().catch(fail); }); byId("mailbox-next").addEventListener("click", () => { if (mailboxCursor) void loadMailboxes(mailboxCursor).catch(fail); });
  byId("sync-domains").addEventListener("click", () => void api.mutate<readonly Domain[]>("/api/domains/sync", "POST").then(async () => { await loadDomains(); await loadSettings(); }).catch(fail));
  byId("default-domain-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const domain = byId<HTMLSelectElement>("default-domain").value; if (!domains.some((item) => item.active && item.domain === domain)) return status("Choose an active domain."); void api.mutate("/api/domains/default", "PUT", { domain }).then(() => status("Default domain saved.")).catch(fail); });
  byId("settings-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const value = { mailboxQuotaMb: Number(byId<HTMLInputElement>("quota").value), dailyCreationLimit: Number(byId<HTMLInputElement>("daily-limit").value), totalManagedLimit: Number(byId<HTMLInputElement>("total-limit").value) }; const errors = validateSettingsInput(value); if (errors.length) return status(errors.join(" ")); void api.mutate("/api/settings", "PUT", { ...value, generationEnabled: byId<HTMLInputElement>("generation-enabled").checked }).then(() => status("Settings saved.")).catch(fail); });
  byId("token-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const name = byId<HTMLInputElement>("token-name").value.trim(); if (!name) return; void api.mutate<{ rawToken: string }>("/api/tokens", "POST", { name }).then((result) => { const dialog = byId<HTMLDialogElement>("token-dialog"); text(byId("raw-token"), result.rawToken); dialog.dataset.token = result.rawToken; dialog.showModal(); return loadTokens(); }).catch(fail); });
  byId("copy-token").addEventListener("click", () => { const token = byId<HTMLDialogElement>("token-dialog").dataset.token; if (token) void navigator.clipboard.writeText(token).then(() => status("Token copied.")).catch(fail); });
  const clearToken = () => { const dialog = byId<HTMLDialogElement>("token-dialog"); dialog.dataset.token = ""; text(byId("raw-token"), ""); };
  byId("token-dialog").addEventListener("close", clearToken);
  byId("dismiss-token").addEventListener("click", () => { const dialog = byId<HTMLDialogElement>("token-dialog"); clearToken(); dialog.close(); });
  byId("delete-form").addEventListener("submit", (event: { preventDefault(): void }) => { event.preventDefault(); const input = byId<HTMLInputElement>("delete-confirmation"); if (!validateDeleteConfirmation(input.dataset.email ?? "", input.value)) return status("Type the complete email address exactly."); void api.mutate(`/api/mailboxes/${encodeURIComponent(input.dataset.id ?? "")}`, "DELETE", { confirmationEmail: input.value }).then(async () => { byId<HTMLDialogElement>("delete-dialog").close(); await loadMailboxes(); await loadRecovery(); status("Mailbox permanently deleted."); }).catch(fail); });
  byId("cancel-delete").addEventListener("click", () => byId<HTMLDialogElement>("delete-dialog").close()); byId("audit-next").addEventListener("click", () => { if (auditCursor) void loadAudit(auditCursor).catch(fail); }); byId("refresh-recovery").addEventListener("click", () => void loadRecovery().catch(fail));
  document.addEventListener("visibilitychange", () => { if (document.hidden) for (const clear of clearMailboxSecrets) clear(); });
  document.addEventListener("pagehide", () => { for (const clear of clearMailboxSecrets) clear(); clearToken(); });
}

async function start(): Promise<void> { bind(); await api.initialize(); await loadDomains(); await Promise.all([loadMailboxes(), loadSettings(), loadTokens(), loadAudit(), loadRecovery()]); status("Management data loaded."); }
if (typeof document !== "undefined") void start().catch(fail);
