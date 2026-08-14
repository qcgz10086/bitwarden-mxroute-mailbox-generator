export type MailboxStatus =
  | "registered"
  | "pending"
  | "activating"
  | "active"
  | "failed"
  | "resetting"
  | "reset_unknown"
  | "deleting"
  | "delete_failed";

export interface AdminIdentity {
  readonly subject: string;
  readonly email: string;
}

export interface AliasResult {
  readonly id: number;
  readonly email: string;
  readonly enabled: true;
  readonly creation_timestamp: number;
  readonly name: null;
  readonly note: null;
}

export interface MailboxSummary {
  readonly publicId: string;
  readonly email: string;
  readonly domain: string;
  readonly quotaMb: number;
  readonly status: MailboxStatus;
  readonly createdAt: string;
  readonly failureCode: string | null;
  readonly note: string | null;
}

export interface MailboxPage {
  readonly items: readonly MailboxSummary[];
  readonly nextCursor: string | null;
}

export interface GenerateResult {
  readonly alias: AliasResult;
  readonly requestId: string;
}

export interface CoreErrorEnvelope {
  readonly code: string;
  readonly message: string;
  readonly retryable: boolean;
  readonly requestId: string;
}
