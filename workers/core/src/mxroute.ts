import { ServiceError, type ServiceErrorCode } from "./errors";

const MXROUTE_ORIGIN = "https://api.mxroute.com";
const TIMEOUT_MS = 10_000;

export interface MxrouteCredentials {
  readonly server: string;
  readonly username: string;
  readonly apiKey: string;
}

export interface MxrouteMailbox {
  readonly username: string;
  readonly email: string;
  readonly quotaMb: number;
  readonly limit: number;
}

export interface MxrouteMailboxPatch {
  readonly password?: string;
  readonly quotaMb?: number;
  readonly limit?: number;
}

export type MxrouteFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type ScheduleTimeout = (callback: () => void, delayMs: number) => unknown;
type CancelTimeout = (handle: unknown) => void;
type MxrouteRequest = {
  readonly method: string;
  readonly body?: BodyInit | null;
};

export interface MxrouteClientDependencies {
  readonly fetch?: MxrouteFetch;
  readonly scheduleTimeout?: ScheduleTimeout;
  readonly cancelTimeout?: CancelTimeout;
}

type UpstreamMailbox = {
  readonly username: string;
  readonly email: string;
  readonly quota: number;
  readonly limit: number;
};

export class MxrouteClient {
  private readonly fetch: MxrouteFetch;
  private readonly scheduleTimeout: ScheduleTimeout;
  private readonly cancelTimeout: CancelTimeout;

  constructor(
    private readonly credentials: MxrouteCredentials,
    dependencies: MxrouteClientDependencies = {},
  ) {
    this.fetch = dependencies.fetch ?? fetch;
    this.scheduleTimeout = dependencies.scheduleTimeout
      ?? ((callback, delayMs) => setTimeout(callback, delayMs));
    this.cancelTimeout = dependencies.cancelTimeout
      ?? ((handle) => clearTimeout(handle as number));
  }

  async listDomains(): Promise<readonly string[]> {
    return this.requestJson("/domains", { method: "GET" }, isDomains);
  }

  async getMailbox(domain: string, user: string): Promise<MxrouteMailbox> {
    return mapMailbox(await this.requestJson(
      this.mailboxPath(domain, user),
      { method: "GET" },
      isUpstreamMailbox,
    ));
  }

  async createMailbox(
    domain: string,
    user: string,
    password: string,
    quotaMb: number,
  ): Promise<MxrouteMailbox> {
    return mapMailbox(await this.requestJson(
      this.mailboxesPath(domain),
      {
        method: "POST",
        body: JSON.stringify({ username: user, password, quota: quotaMb, limit: 9600 }),
      },
      isUpstreamMailbox,
    ));
  }

  async updateMailbox(
    domain: string,
    user: string,
    patch: MxrouteMailboxPatch,
  ): Promise<MxrouteMailbox> {
    const body: Record<string, string | number> = {};
    if (patch.password !== undefined) {
      body.password = patch.password;
    }
    if (patch.quotaMb !== undefined) {
      body.quota = patch.quotaMb;
    }
    if (patch.limit !== undefined) {
      body.limit = patch.limit;
    }
    return mapMailbox(await this.requestJson(
      this.mailboxPath(domain, user),
      { method: "PATCH", body: JSON.stringify(body) },
      isUpstreamMailbox,
    ));
  }

  async deleteMailbox(domain: string, user: string): Promise<void> {
    const response = await this.send(this.mailboxPath(domain, user), { method: "DELETE" });
    if (response.status === 404 || response.ok) {
      return;
    }
    throw serviceErrorForStatus(response.status);
  }

  private async requestJson<T>(
    path: string,
    request: MxrouteRequest,
    isData: (data: unknown) => data is T,
  ): Promise<T> {
    const response = await this.send(path, request);
    if (!response.ok) {
      throw serviceErrorForStatus(response.status);
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new ServiceError("MX_INVALID_RESPONSE");
    }
    if (!isSuccessPayload(payload) || !isData(payload.data)) {
      throw new ServiceError("MX_INVALID_RESPONSE");
    }
    return payload.data;
  }

  private async send(
    path: string,
    request: MxrouteRequest,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeout = this.scheduleTimeout(() => controller.abort(), TIMEOUT_MS);
    const headers: Record<string, string> = {
      "X-Server": this.credentials.server,
      "X-Username": this.credentials.username,
      "X-API-Key": this.credentials.apiKey,
    };
    if (request.body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const init: RequestInit = {
      method: request.method,
      headers,
      signal: controller.signal,
    };
    if (request.body !== undefined) {
      init.body = request.body;
    }

    try {
      return await this.fetch(`${MXROUTE_ORIGIN}${path}`, init);
    } catch {
      throw new ServiceError(controller.signal.aborted ? "MX_TIMEOUT" : "MX_SERVER");
    } finally {
      this.cancelTimeout(timeout);
    }
  }

  private mailboxesPath(domain: string): string {
    return `/domains/${encodeURIComponent(domain)}/email-accounts`;
  }

  private mailboxPath(domain: string, user: string): string {
    return `${this.mailboxesPath(domain)}/${encodeURIComponent(user)}`;
  }
}

function serviceErrorForStatus(status: number): ServiceError {
  const code: ServiceErrorCode = status === 401
    ? "MX_UNAUTHORIZED"
    : status === 404
      ? "MX_NOT_FOUND"
      : status === 409
        ? "MX_CONFLICT"
        : status === 429
          ? "MX_RATE_LIMITED"
          : "MX_SERVER";
  return new ServiceError(code);
}

function isSuccessPayload(value: unknown): value is { readonly success: true; readonly data: unknown } {
  return isRecord(value) && value.success === true && "data" in value;
}

function isDomains(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((domain) => typeof domain === "string");
}

function isUpstreamMailbox(value: unknown): value is UpstreamMailbox {
  return isRecord(value)
    && typeof value.username === "string"
    && typeof value.email === "string"
    && typeof value.quota === "number"
    && typeof value.limit === "number";
}

function mapMailbox(value: UpstreamMailbox): MxrouteMailbox {
  return {
    username: value.username,
    email: value.email,
    quotaMb: value.quota,
    limit: value.limit,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
