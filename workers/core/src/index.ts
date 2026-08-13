import { WorkerEntrypoint } from "cloudflare:workers";

import type {
  AdminIdentity,
  GenerateResult,
  MailboxPage,
} from "../../../packages/contracts/src/index";
import { MxrouteClient } from "./mxroute";
import {
  Repository,
  type AuditPage,
  type DomainRecord,
  type PageAuditOptions,
  type PageMailboxesOptions,
  type RepositorySettings,
} from "./repository";
import {
  AdministrationService,
  type AdminSettingsPatch,
  MailboxService,
} from "./service";

export interface CoreEnv {
  readonly DB: D1Database;
  readonly MXROUTE_SERVER: string;
  readonly MXROUTE_USERNAME: string;
  readonly MXROUTE_API_KEY: string;
  readonly TOKEN_PEPPER: string;
  readonly ENC_KEY_V1: string;
}

export class CoreService extends WorkerEntrypoint<CoreEnv> {
  generateMailbox(rawToken: string): Promise<GenerateResult> {
    const repository = new Repository(this.env.DB);
    const mxroute = new MxrouteClient({
      server: this.env.MXROUTE_SERVER,
      username: this.env.MXROUTE_USERNAME,
      apiKey: this.env.MXROUTE_API_KEY,
    });
    return new MailboxService({
      repository,
      mxroute,
      tokenPepper: this.env.TOKEN_PEPPER,
      encryptionKey: this.env.ENC_KEY_V1,
      encryptionKeyVersion: 1,
    }).generateMailbox(rawToken);
  }

  pageMailboxes(identity: AdminIdentity, options: PageMailboxesOptions = {}): Promise<MailboxPage> {
    return this.administration().pageMailboxes(identity, options);
  }

  listDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]> { return this.administration().listDomains(identity); }
  getSettings(identity: AdminIdentity): Promise<RepositorySettings> { return this.administration().getSettings(identity); }
  listApiTokens(identity: AdminIdentity): Promise<readonly import("./repository").ApiTokenRecord[]> { return this.administration().listApiTokens(identity); }

  revealPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }> {
    return this.administration().revealPassword(identity, publicId);
  }

  resetPassword(identity: AdminIdentity, publicId: string): Promise<{ password: string; requestId: string }> {
    return this.administration().resetPassword(identity, publicId);
  }

  deleteMailbox(identity: AdminIdentity, publicId: string, confirmationEmail: string): Promise<{ requestId: string }> {
    return this.administration().deleteMailbox(identity, publicId, confirmationEmail);
  }

  syncDomains(identity: AdminIdentity): Promise<readonly DomainRecord[]> {
    return this.administration().syncDomains(identity);
  }

  setDefaultDomain(identity: AdminIdentity, domain: string): Promise<{ requestId: string }> {
    return this.administration().setDefaultDomain(identity, domain);
  }

  createApiToken(identity: AdminIdentity, name: string): Promise<{ id: string; rawToken: string; requestId: string }> {
    return this.administration().createApiToken(identity, name);
  }

  revokeApiToken(identity: AdminIdentity, id: string): Promise<{ requestId: string }> {
    return this.administration().revokeApiToken(identity, id);
  }

  async updateSettings(identity: AdminIdentity, patch: AdminSettingsPatch): Promise<RepositorySettings & { requestId: string }> {
    const result = await this.administration().updateSettings(identity, patch);
    return { ...await new Repository(this.env.DB).getSettings(), requestId: result.requestId };
  }

  pageAudit(identity: AdminIdentity, options: PageAuditOptions = {}): Promise<AuditPage> {
    return this.administration().pageAudit(identity, options);
  }

  async scheduled(_controller: ScheduledController): Promise<void> {
    await this.administration().reconcileAll();
  }

  private administration(): AdministrationService {
    return new AdministrationService({
      repository: new Repository(this.env.DB),
      mxroute: new MxrouteClient({
        server: this.env.MXROUTE_SERVER,
        username: this.env.MXROUTE_USERNAME,
        apiKey: this.env.MXROUTE_API_KEY,
      }),
      tokenPepper: this.env.TOKEN_PEPPER,
      encryptionKeys: { 1: this.env.ENC_KEY_V1 },
      encryptionKeyVersion: 1,
    });
  }
}

export default CoreService;
