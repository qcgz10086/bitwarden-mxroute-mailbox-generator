import { WorkerEntrypoint } from "cloudflare:workers";

import type { GenerateResult } from "../../../packages/contracts/src/index";
import { MxrouteClient } from "./mxroute";
import { Repository } from "./repository";
import { MailboxService } from "./service";

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
}

export default CoreService;
