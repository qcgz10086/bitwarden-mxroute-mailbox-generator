import { WorkerEntrypoint } from "cloudflare:workers";
import type { AdminIdentity, GenerateResult, MailboxPage } from "../../../packages/contracts/src/index";
import { MxrouteClient } from "./mxroute";
import { Repository, type AuditPage, type DomainRecord, type PageAuditOptions, type PageMailboxesOptions, type RepositorySettings } from "./repository";
import { AdministrationService, type AdminSettingsPatch, MailboxService } from "./service";

export interface CoreEnv {
  readonly DB: D1Database; readonly MXROUTE_SERVER: string; readonly MXROUTE_USERNAME: string;
  readonly MXROUTE_API_KEY: string; readonly TOKEN_PEPPER: string; readonly ENC_KEY_V1: string;
  readonly MXROUTE_FETCH?: Fetcher;
}

function mxroute(env: CoreEnv): MxrouteClient {
  return new MxrouteClient({ server: env.MXROUTE_SERVER, username: env.MXROUTE_USERNAME, apiKey: env.MXROUTE_API_KEY },
      env.MXROUTE_FETCH === undefined ? {} : { fetch: async (input, init) => {
        const response = await env.MXROUTE_FETCH!.fetch(input, init);
        if (response.headers.get("X-Integration-Fault") === "timeout") throw new DOMException("injected timeout", "AbortError");
        return response;
      }});
}
function administration(env: CoreEnv): AdministrationService {
  return new AdministrationService({ repository: new Repository(env.DB), mxroute: mxroute(env), tokenPepper: env.TOKEN_PEPPER,
    encryptionKeys: { 1: env.ENC_KEY_V1 }, encryptionKeyVersion: 1 });
}

export class GeneratorEntrypoint extends WorkerEntrypoint<CoreEnv> {
  generateMailbox(rawToken: string): Promise<GenerateResult> {
    return new MailboxService({ repository: new Repository(this.env.DB), mxroute: mxroute(this.env), tokenPepper: this.env.TOKEN_PEPPER,
      encryptionKey: this.env.ENC_KEY_V1, encryptionKeyVersion: 1 }).generateMailbox(rawToken);
  }
}

export class AdminEntrypoint extends WorkerEntrypoint<CoreEnv> {
  pageMailboxes(identity: AdminIdentity, options: PageMailboxesOptions = {}): Promise<MailboxPage> { return administration(this.env).pageMailboxes(identity, options); }
  listDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]> { return administration(this.env).listDomains(identity); }
  getSettings(identity: AdminIdentity): Promise<RepositorySettings> { return administration(this.env).getSettings(identity); }
  listApiTokens(identity: AdminIdentity): Promise<readonly import("./repository").ApiTokenRecord[]> { return administration(this.env).listApiTokens(identity); }
  revealPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }> { return administration(this.env).revealPassword(identity, publicId); }
  resetPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }> { return administration(this.env).resetPassword(identity, publicId); }
  deleteMailbox(identity: AdminIdentity, publicId: string, confirmationEmail: string): Promise<{ requestId: string }> { return administration(this.env).deleteMailbox(identity, publicId, confirmationEmail); }
  setMailboxNote(identity: AdminIdentity, publicId: string, note: string | null): Promise<{ requestId: string }> { return administration(this.env).setMailboxNote(identity, publicId, note); }
  confirmMailbox(identity: AdminIdentity, publicId: string): Promise<{ requestId: string }> { return administration(this.env).confirmMailbox(identity, publicId); }
  syncDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]> { return administration(this.env).syncDomains(identity); }
  setDefaultDomain(identity: AdminIdentity, domain: string): Promise<{ requestId: string }> { return administration(this.env).setDefaultDomain(identity, domain); }
  createApiToken(identity: AdminIdentity, name: string, operationId: string): Promise<{ id: string; rawToken: string; requestId: string; expiresAt: string }> { return administration(this.env).createApiToken(identity, name, operationId); }
  acknowledgeApiToken(identity: AdminIdentity, id: string, operationId: string): Promise<{ requestId: string }> { return administration(this.env).acknowledgeApiToken(identity, id, operationId); }
  revokeApiToken(identity: AdminIdentity, id: string): Promise<{ requestId: string }> { return administration(this.env).revokeApiToken(identity, id); }
  async updateSettings(identity: AdminIdentity, patch: AdminSettingsPatch): Promise<RepositorySettings & { requestId: string }> {
    const result = await administration(this.env).updateSettings(identity, patch);
    return { ...await new Repository(this.env.DB).getSettings(), requestId: result.requestId };
  }
  pageAudit(identity: AdminIdentity, options: PageAuditOptions = {}): Promise<AuditPage> { return administration(this.env).pageAudit(identity, options); }
}

export default class ScheduledEntrypoint extends WorkerEntrypoint<CoreEnv> {
  async scheduled(_controller: ScheduledController): Promise<void> { await administration(this.env).reconcileAll(); }
}
