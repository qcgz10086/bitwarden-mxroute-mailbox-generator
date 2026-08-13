import { WorkerEntrypoint } from "cloudflare:workers";

type Mode = "ok" | "conflict" | "rate" | "create-timeout" | "reset-timeout" | "delete-timeout";
interface Stored { password: string; quota: number; limit: number; }
interface Recorded { method: string; path: string; body: Record<string, unknown>; }

let mode: Mode = "ok";
const mailboxes = new Map<string, Stored>();
const writes: Recorded[] = [];

export default class TestMxroute extends WorkerEntrypoint {
  async setMode(value: Mode): Promise<void> { mode = value; }
  async getWrites(): Promise<Recorded[]> { return structuredClone(writes); }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const body = request.body === null ? {} : await request.clone().json() as Record<string, unknown>;
    writes.push({ method: request.method, path: url.pathname, body });
    if (url.pathname === "/domains" && request.method === "GET") return ok(["example.com", "second.example"]);
    const match = url.pathname.match(/^\/domains\/([^/]+)\/email-accounts(?:\/([^/]+))?$/);
    if (!match) return new Response(null, { status: 404 });
    const domain = decodeURIComponent(match[1]!);
    const user = match[2] === undefined ? undefined : decodeURIComponent(match[2]);
    if (request.method === "POST") {
      if (mode === "conflict") return new Response(null, { status: 409 });
      if (mode === "rate") return new Response(null, { status: 429 });
      const username = String(body.username);
      const record = { password: String(body.password), quota: Number(body.quota), limit: Number(body.limit) };
      mailboxes.set(`${username}@${domain}`, record);
      if (mode === "create-timeout") return new Response(null, { status: 504 });
      return mailbox(username, domain, record);
    }
    if (user === undefined) return new Response(null, { status: 404 });
    const key = `${user}@${domain}`;
    const record = mailboxes.get(key);
    if (request.method === "GET") return record === undefined ? new Response(null, { status: 404 }) : mailbox(user, domain, record);
    if (request.method === "PATCH") {
      if (record === undefined) return new Response(null, { status: 404 });
      if (typeof body.password === "string") record.password = body.password;
      if (mode === "reset-timeout") return new Response(null, { status: 504 });
      return mailbox(user, domain, record);
    }
    if (request.method === "DELETE") {
      mailboxes.delete(key);
      if (mode === "delete-timeout") return new Response(null, { status: 504 });
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 405 });
  }
}

function ok(data: unknown): Response { return Response.json({ success: true, data }); }
function mailbox(user: string, domain: string, record: Stored): Response {
  return ok({ username: user, email: `${user}@${domain}`, quota: record.quota, limit: record.limit });
}
