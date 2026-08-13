import type {
  MailboxPage,
  MailboxStatus,
  MailboxSummary,
} from "../../../packages/contracts/src/index";

export class RepositoryError extends Error {
  constructor(readonly code: RepositoryErrorCode) {
    super(code);
    this.name = "RepositoryError";
  }
}

export type RepositoryErrorCode =
  | "DAILY_LIMIT"
  | "TOTAL_LIMIT"
  | "RESERVATION_RELEASE"
  | "EMAIL_EXISTS"
  | "PUBLIC_ID_EXISTS"
  | "TOKEN_EXISTS"
  | "TOKEN_LIMIT"
  | "INACTIVE_DOMAIN"
  | "INVALID_STATE"
  | "INVALID_TRANSITION"
  | "INVALID_CURSOR"
  | "INVALID_INPUT"
  | "INVALID_SETTINGS";

export interface EncryptedValue {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly keyVersion: number;
}

export interface ReservePendingMailboxInput {
  readonly tokenId: string;
  readonly date: string;
  readonly publicId: string;
  readonly email: string;
  readonly localPart: string;
  readonly domain: string;
  readonly password: EncryptedValue;
  readonly quotaMb: number;
  readonly now: string;
}

export interface MailboxRecord {
  readonly publicId: string;
  readonly email: string;
  readonly localPart: string;
  readonly domain: string;
  readonly passwordCiphertext: Uint8Array;
  readonly passwordNonce: Uint8Array;
  readonly encryptionKeyVersion: number;
  readonly nextPasswordCiphertext: Uint8Array | null;
  readonly nextPasswordNonce: Uint8Array | null;
  readonly nextPasswordKeyVersion: number | null;
  readonly quotaMb: number;
  readonly status: MailboxStatus;
  readonly failureCode: string | null;
  readonly recoveryAttemptCount: number;
  readonly recoveryNextAt: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface MailboxTransitionPatch {
  readonly updatedAt: string;
  readonly failureCode?: string | null;
  readonly quotaMb?: number;
}

export interface NextPasswordPatch {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly keyVersion: number;
  readonly updatedAt: string;
}

export type MailboxSort = "createdAt" | "email" | "status";
export type SortDirection = "asc" | "desc";

export interface PageMailboxesOptions {
  readonly limit?: number;
  readonly cursor?: string;
  readonly sort?: MailboxSort;
  readonly direction?: SortDirection;
  readonly domain?: string;
  readonly status?: MailboxStatus;
  readonly search?: string;
}

export interface RepositorySettings {
  readonly defaultDomain: string | null;
  readonly mailboxQuotaMb: number;
  readonly prefixLength: number;
  readonly dailyCreationLimit: number;
  readonly totalManagedLimit: number;
  readonly generationEnabled: boolean;
}

export interface CreateTokenDigestInput {
  readonly id: string;
  readonly name: string;
  readonly digest: Uint8Array;
  readonly createdAt: string;
}

export interface ApiTokenRecord {
  readonly id: string;
  readonly name: string;
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
}

export interface AuditEventInput {
  readonly id: string;
  readonly actorType: string;
  readonly actorId: string;
  readonly actorEmail?: string | null;
  readonly action: string;
  readonly email: string | null;
  readonly result: string;
  readonly errorCode: string | null;
  readonly requestId: string;
  readonly createdAt: string;
}

export interface DomainRecord {
  readonly domain: string;
  readonly active: boolean;
  readonly syncedAt: string;
}

export interface AuditRecord extends AuditEventInput {
  readonly actorEmail: string | null;
}

export interface AuditPage {
  readonly items: readonly AuditRecord[];
  readonly nextCursor: string | null;
}

export interface PageAuditOptions {
  readonly limit?: number;
  readonly cursor?: string;
}

export interface SettingsPatch {
  readonly mailboxQuotaMb?: number;
  readonly prefixLength?: number;
  readonly dailyCreationLimit?: number;
  readonly totalManagedLimit?: number;
  readonly generationEnabled?: boolean;
}

type MailboxRow = {
  public_id: string;
  email: string;
  local_part: string;
  domain: string;
  password_ciphertext: unknown;
  password_nonce: unknown;
  encryption_key_version: number;
  next_password_ciphertext: unknown | null;
  next_password_nonce: unknown | null;
  next_password_key_version: number | null;
  quota_mb: number;
  status: MailboxStatus;
  failure_code: string | null;
  recovery_attempt_count: number;
  recovery_next_at: string | null;
  created_at: string;
  updated_at: string;
};

type MailboxSummaryRow = {
  public_id: string;
  email: string;
  domain: string;
  quota_mb: number;
  status: MailboxStatus;
  created_at: string;
  failure_code: string | null;
  sort_value: string;
};

type TokenRow = {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
};

type PageCursor = {
  sort: MailboxSort;
  direction: SortDirection;
  value: string;
  publicId: string;
};

const MAILBOX_SORT_COLUMNS: Readonly<Record<MailboxSort, string>> = {
  createdAt: "created_at",
  email: "email",
  status: "status",
};

const ALLOWED_TRANSITIONS: Readonly<Record<MailboxStatus, readonly MailboxStatus[]>> = {
  pending: ["active", "deleting"],
  active: ["resetting", "deleting"],
  failed: ["deleting"],
  resetting: ["active", "reset_unknown", "deleting"],
  reset_unknown: ["resetting", "active", "deleting"],
  deleting: ["delete_failed"],
  delete_failed: ["deleting"],
};

const MAILBOX_COLUMNS = `
  public_id,
  email,
  local_part,
  domain,
  password_ciphertext,
  password_nonce,
  encryption_key_version,
  next_password_ciphertext,
  next_password_nonce,
  next_password_key_version,
  quota_mb,
  status,
  failure_code,
  recovery_attempt_count,
  recovery_next_at,
  created_at,
  updated_at`;

export class Repository {
  constructor(private readonly db: D1Database) {}

  async reservePendingMailbox(input: ReservePendingMailboxInput): Promise<void> {
    try {
      await this.db.batch([
        this.db.prepare(`INSERT INTO creation_counters(date, token_id, count) VALUES(?, ?, 1)
          ON CONFLICT(date, token_id) DO UPDATE SET count = count + 1`)
          .bind(input.date, input.tokenId),
        this.db.prepare(`INSERT INTO mailboxes(
            public_id,
            email,
            local_part,
            domain,
            reservation_date,
            reservation_token_id,
            password_ciphertext,
            password_nonce,
            encryption_key_version,
            quota_mb,
            status,
            created_at,
            updated_at
          ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`)
          .bind(
            input.publicId,
            input.email,
            input.localPart,
            input.domain,
            input.date,
            input.tokenId,
            toArrayBuffer(input.password.ciphertext),
            toArrayBuffer(input.password.nonce),
            input.password.keyVersion,
            input.quotaMb,
            input.now,
            input.now,
          ),
      ]);
    } catch (error) {
      throw normalizeDatabaseError(error);
    }
  }

  async transitionMailbox(
    publicId: string,
    from: MailboxStatus | readonly MailboxStatus[],
    to: MailboxStatus,
    patch: MailboxTransitionPatch,
  ): Promise<void> {
    const fromStates = typeof from === "string" ? [from] : [...from];
    if (
      fromStates.length === 0
      || fromStates.some((state) => !ALLOWED_TRANSITIONS[state]?.includes(to))
    ) {
      throw new RepositoryError("INVALID_TRANSITION");
    }

    const assignments = ["status = ?", "updated_at = ?"];
    const bindings: unknown[] = [to, patch.updatedAt];
    if ("failureCode" in patch) {
      assignments.push("failure_code = ?");
      bindings.push(patch.failureCode ?? null);
    }
    if ("quotaMb" in patch) {
      assignments.push("quota_mb = ?");
      bindings.push(patch.quotaMb);
    }
    if (fromStates.includes("pending")) {
      assignments.push("reservation_date = NULL", "reservation_token_id = NULL");
    }
    const placeholders = fromStates.map(() => "?").join(", ");
    const result = await this.db.prepare(`UPDATE mailboxes
      SET ${assignments.join(", ")}
      WHERE public_id = ? AND status IN (${placeholders})`)
      .bind(...bindings, publicId, ...fromStates)
      .run();
    requireSingleChange(result);
  }

  async activateMailboxWithAudit(
    publicId: string,
    updatedAt: string,
    event: AuditEventInput,
  ): Promise<void> {
    const [activation, audit] = await this.db.batch([
      this.db.prepare(`UPDATE mailboxes
        SET status = 'active',
            failure_code = NULL,
            updated_at = ?,
            reservation_date = NULL,
            reservation_token_id = NULL
        WHERE public_id = ? AND status = 'pending'`)
        .bind(updatedAt, publicId),
      auditStatement(this.db, event, true),
    ]);
    requireSingleChange(activation);
    requireSingleChange(audit);
  }

  async failPendingMailbox(
    publicId: string,
    failureCode: string,
    updatedAt: string,
  ): Promise<void> {
    try {
      const row = await this.db.prepare(`UPDATE mailboxes
        SET status = 'failed',
            failure_code = ?,
            updated_at = ?,
            reservation_date = NULL,
            reservation_token_id = NULL
        WHERE public_id = ? AND status = 'pending'
        RETURNING public_id`)
        .bind(failureCode, updatedAt, publicId)
        .first<{ public_id: string }>();
      if (row === null) {
        throw new RepositoryError("INVALID_STATE");
      }
    } catch (error) {
      throw normalizeDatabaseError(error);
    }
  }

  async failPendingMailboxWithAudit(publicId: string, failureCode: string, updatedAt: string, event: AuditEventInput): Promise<void> {
    await this.mutateWithAudit(this.db.prepare(`UPDATE mailboxes
      SET status = 'failed', failure_code = ?, updated_at = ?,
          reservation_date = NULL, reservation_token_id = NULL
      WHERE public_id = ? AND status = 'pending'`).bind(failureCode, updatedAt, publicId), event);
  }

  async findRevealableMailbox(publicId: string): Promise<MailboxRecord | null> {
    const row = await this.db.prepare(`SELECT ${MAILBOX_COLUMNS} FROM mailboxes
      WHERE public_id = ? AND status IN ('active', 'reset_unknown', 'delete_failed')`)
      .bind(publicId).first<MailboxRow>();
    return row === null ? null : mapMailbox(row);
  }

  async recordPasswordRevealSuccessWithAudit(publicId: string, event: AuditEventInput): Promise<void> {
    const result = await this.db.prepare(`INSERT INTO audit_events(
        id,actor_type,actor_id,actor_email,action,email,result,error_code,request_id,created_at)
      SELECT ?,?,?,?,?,email,?,?,?,? FROM mailboxes
      WHERE public_id = ? AND status IN ('active', 'reset_unknown', 'delete_failed')`)
      .bind(event.id,event.actorType,event.actorId,event.actorEmail ?? null,event.action,
        event.result,event.errorCode,event.requestId,event.createdAt,publicId).run();
    requireSingleChange(result);
  }

  async findMailbox(publicId: string): Promise<MailboxRecord | null> {
    const row = await this.db.prepare(`SELECT ${MAILBOX_COLUMNS}
      FROM mailboxes WHERE public_id = ?`)
      .bind(publicId)
      .first<MailboxRow>();
    return row === null ? null : mapMailbox(row);
  }

  async pageMailboxes(options: PageMailboxesOptions = {}): Promise<MailboxPage> {
    const sort = options.sort ?? "createdAt";
    const direction = options.direction ?? "desc";
    const sortColumn = MAILBOX_SORT_COLUMNS[sort];
    if (sortColumn === undefined || (direction !== "asc" && direction !== "desc")) {
      throw new RepositoryError("INVALID_CURSOR");
    }
    const limit = validPageLimit(options.limit);
    const clauses: string[] = [];
    const bindings: unknown[] = [];

    if (options.domain !== undefined) {
      clauses.push("domain = ?");
      bindings.push(options.domain);
    }
    if (options.status !== undefined) {
      clauses.push("status = ?");
      bindings.push(options.status);
    }
    if (options.search !== undefined) {
      clauses.push("email LIKE ? ESCAPE '\\'");
      bindings.push(`%${escapeLike(options.search)}%`);
    }
    if (options.cursor !== undefined) {
      const cursor = decodeCursor(options.cursor);
      if (cursor.sort !== sort || cursor.direction !== direction) {
        throw new RepositoryError("INVALID_CURSOR");
      }
      const comparison = direction === "asc" ? ">" : "<";
      clauses.push(`(${sortColumn} ${comparison} ? OR (${sortColumn} = ? AND public_id ${comparison} ?))`);
      bindings.push(cursor.value, cursor.value, cursor.publicId);
    }

    const where = clauses.length === 0 ? "" : `WHERE ${clauses.join(" AND ")}`;
    const order = direction === "asc" ? "ASC" : "DESC";
    const result = await this.db.prepare(`SELECT
        public_id,
        email,
        domain,
        quota_mb,
        status,
        created_at,
        failure_code,
        ${sortColumn} AS sort_value
      FROM mailboxes
      ${where}
      ORDER BY ${sortColumn} ${order}, public_id ${order}
      LIMIT ?`)
      .bind(...bindings, limit + 1)
      .all<MailboxSummaryRow>();
    const hasMore = result.results.length > limit;
    const pageRows = result.results.slice(0, limit);
    const items: MailboxSummary[] = pageRows.map(mapMailboxSummary);
    const last = pageRows.at(-1);
    const nextCursor = hasMore && last !== undefined
      ? encodeCursor({ sort, direction, value: last.sort_value, publicId: last.public_id })
      : null;
    return { items, nextCursor };
  }

  async saveNextPassword(publicId: string, patch: NextPasswordPatch): Promise<void> {
    const result = await this.db.prepare(`UPDATE mailboxes
      SET next_password_ciphertext = ?,
          next_password_nonce = ?,
          next_password_key_version = ?,
          status = 'resetting',
          failure_code = NULL,
          recovery_attempt_count = 0,
          recovery_next_at = NULL,
          updated_at = ?
      WHERE public_id = ? AND status IN ('active')`)
      .bind(
        toArrayBuffer(patch.ciphertext),
        toArrayBuffer(patch.nonce),
        patch.keyVersion,
        patch.updatedAt,
        publicId,
      )
      .run();
    requireSingleChange(result);
  }

  async completePasswordReset(publicId: string, updatedAt: string): Promise<void> {
    const result = await this.db.prepare(`UPDATE mailboxes
      SET password_ciphertext = next_password_ciphertext,
          password_nonce = next_password_nonce,
          encryption_key_version = next_password_key_version,
          next_password_ciphertext = NULL,
          next_password_nonce = NULL,
          next_password_key_version = NULL,
          status = 'active',
          failure_code = NULL,
          recovery_attempt_count = 0,
          recovery_next_at = NULL,
          updated_at = ?
      WHERE public_id = ?
        AND status IN ('resetting', 'reset_unknown')
        AND next_password_ciphertext IS NOT NULL
        AND next_password_nonce IS NOT NULL
        AND next_password_key_version IS NOT NULL`)
      .bind(updatedAt, publicId)
      .run();
    requireSingleChange(result);
  }

  async completePasswordResetWithAudit(
    publicId: string,
    updatedAt: string,
    event: AuditEventInput,
  ): Promise<void> {
    const [completion, audit] = await this.db.batch([
      this.db.prepare(`UPDATE mailboxes
        SET password_ciphertext = next_password_ciphertext,
            password_nonce = next_password_nonce,
            encryption_key_version = next_password_key_version,
            next_password_ciphertext = NULL,
            next_password_nonce = NULL,
            next_password_key_version = NULL,
            status = 'active',
            failure_code = NULL,
            recovery_attempt_count = 0,
            recovery_next_at = NULL,
            updated_at = ?
        WHERE public_id = ?
          AND status IN ('resetting', 'reset_unknown')
          AND next_password_ciphertext IS NOT NULL
          AND next_password_nonce IS NOT NULL
          AND next_password_key_version IS NOT NULL`)
        .bind(updatedAt, publicId),
      auditStatement(this.db, event, true),
    ]);
    requireSingleChange(completion);
    requireSingleChange(audit);
  }

  async rollbackPasswordReset(publicId: string, failureCode: string, updatedAt: string): Promise<void> {
    const result = await this.db.prepare(`UPDATE mailboxes
      SET next_password_ciphertext = NULL,
          next_password_nonce = NULL,
          next_password_key_version = NULL,
          status = 'active',
          failure_code = ?,
          recovery_attempt_count = 0,
          recovery_next_at = NULL,
          updated_at = ?
      WHERE public_id = ? AND status = 'resetting'`)
      .bind(failureCode, updatedAt, publicId).run();
    requireSingleChange(result);
  }

  async rollbackPasswordResetWithAudit(publicId: string, failureCode: string, updatedAt: string, event: AuditEventInput): Promise<void> {
    await this.mutateWithAudit(this.db.prepare(`UPDATE mailboxes SET
      next_password_ciphertext=NULL,next_password_nonce=NULL,next_password_key_version=NULL,
      status='active',failure_code=?,recovery_attempt_count=0,recovery_next_at=NULL,updated_at=?
      WHERE public_id=? AND status='resetting'`).bind(failureCode,updatedAt,publicId), event);
  }

  async markResetUnknown(publicId: string, failureCode: string, updatedAt: string): Promise<void> {
    const result = await this.db.prepare(`UPDATE mailboxes
      SET status = 'reset_unknown', failure_code = ?, updated_at = ?
      WHERE public_id = ? AND status = 'resetting'
        AND next_password_ciphertext IS NOT NULL AND next_password_nonce IS NOT NULL
        AND next_password_key_version IS NOT NULL`)
      .bind(failureCode, updatedAt, publicId).run();
    requireSingleChange(result);
  }

  async markResetUnknownWithAudit(publicId: string, failureCode: string, updatedAt: string, event: AuditEventInput): Promise<void> {
    await this.mutateWithAudit(this.db.prepare(`UPDATE mailboxes SET status='reset_unknown',failure_code=?,updated_at=?
      WHERE public_id=? AND status='resetting' AND next_password_ciphertext IS NOT NULL
      AND next_password_nonce IS NOT NULL AND next_password_key_version IS NOT NULL`)
      .bind(failureCode,updatedAt,publicId), event);
  }

  async markDeleteFailed(publicId: string, failureCode: string, updatedAt: string): Promise<void> {
    const result = await this.db.prepare(`UPDATE mailboxes
      SET status = 'delete_failed', failure_code = ?, recovery_attempt_count = 0,
          recovery_next_at = NULL, updated_at = ?
      WHERE public_id = ? AND status = 'deleting'`)
      .bind(failureCode, updatedAt, publicId).run();
    requireSingleChange(result);
  }

  async markDeleteFailedWithAudit(publicId: string, failureCode: string, updatedAt: string, event: AuditEventInput): Promise<void> {
    await this.mutateWithAudit(this.db.prepare(`UPDATE mailboxes SET status='delete_failed',failure_code=?,
      recovery_attempt_count=0,recovery_next_at=NULL,updated_at=? WHERE public_id=? AND status='deleting'`)
      .bind(failureCode,updatedAt,publicId), event);
  }

  async removeMailbox(publicId: string): Promise<void> {
    const result = await this.db.prepare(
      "DELETE FROM mailboxes WHERE public_id = ? AND status IN ('deleting')",
    ).bind(publicId).run();
    requireSingleChange(result);
  }

  async removeMailboxWithAudit(publicId: string, event: AuditEventInput): Promise<void> {
    const [removal, audit] = await this.db.batch([
      this.db.prepare("DELETE FROM mailboxes WHERE public_id = ? AND status = 'deleting'")
        .bind(publicId),
      auditStatement(this.db, event, true),
    ]);
    requireSingleChange(removal);
    requireSingleChange(audit);
  }

  async syncDomains(domains: readonly string[], syncedAt: string): Promise<void> {
    const statements = [
      this.db.prepare("UPDATE domains SET is_active = 0, synced_at = ?")
        .bind(syncedAt),
      ...domains.map((domain) => this.db.prepare(`INSERT INTO domains(domain, is_active, synced_at)
        VALUES(?, 1, ?)
        ON CONFLICT(domain) DO UPDATE SET is_active = 1, synced_at = excluded.synced_at`)
        .bind(domain, syncedAt)),
    ];
    await this.db.batch(statements);
  }

  async syncDomainsWithAudit(domains: readonly string[], syncedAt: string, event: AuditEventInput): Promise<void> {
    const statements = [this.db.prepare("UPDATE domains SET is_active=0,synced_at=?").bind(syncedAt),
      ...domains.map((domain) => this.db.prepare(`INSERT INTO domains(domain,is_active,synced_at) VALUES(?,1,?)
        ON CONFLICT(domain) DO UPDATE SET is_active=1,synced_at=excluded.synced_at`).bind(domain,syncedAt)),
      auditStatement(this.db,event)];
    const results = await this.db.batch(statements);
    requireSingleChange(results.at(-1));
  }

  async listDomains(): Promise<readonly DomainRecord[]> {
    const result = await this.db.prepare(`SELECT domain, is_active, synced_at
      FROM domains ORDER BY domain ASC`).all<{ domain: string; is_active: number; synced_at: string }>();
    return result.results.map((row) => ({
      domain: row.domain,
      active: row.is_active === 1,
      syncedAt: row.synced_at,
    }));
  }

  async setDefaultDomain(domain: string): Promise<void> {
    const result = await this.db.prepare(`INSERT INTO settings(key, value)
      SELECT 'default_domain', domain
      FROM domains
      WHERE domain = ? AND is_active = 1
      ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
      .bind(domain)
      .run();
    if (Number(result.meta.changes ?? 0) !== 1) {
      throw new RepositoryError("INACTIVE_DOMAIN");
    }
  }

  async setDefaultDomainWithAudit(domain: string, event: AuditEventInput): Promise<void> {
    try {
      await this.mutateWithAudit(this.db.prepare(`INSERT INTO settings(key,value) SELECT 'default_domain',domain
        FROM domains WHERE domain=? AND is_active=1 ON CONFLICT(key) DO UPDATE SET value=excluded.value`).bind(domain), event);
    } catch (error) {
      if (error instanceof RepositoryError && error.code === "INVALID_STATE") throw new RepositoryError("INACTIVE_DOMAIN");
      throw error;
    }
  }

  async getSettings(): Promise<RepositorySettings> {
    const result = await this.db.prepare("SELECT key, value FROM settings")
      .all<{ key: string; value: string }>();
    const settings = new Map(result.results.map((row) => [row.key, row.value]));
    const mailboxQuotaMb = integerSetting(settings, "mailbox_quota_mb");
    const prefixLength = integerSetting(settings, "prefix_length");
    const dailyCreationLimit = integerSetting(settings, "daily_creation_limit");
    const totalManagedLimit = integerSetting(settings, "total_managed_limit");
    const generation = settings.get("generation_enabled");
    if (generation !== "true" && generation !== "false") {
      throw new RepositoryError("INVALID_SETTINGS");
    }
    const configuredDefault = settings.get("default_domain");
    const activeDefault = configuredDefault === undefined
      ? null
      : await this.db.prepare(`SELECT domain FROM domains
          WHERE domain = ? AND is_active = 1`)
        .bind(configuredDefault)
        .first<{ domain: string }>();
    return {
      defaultDomain: activeDefault?.domain ?? null,
      mailboxQuotaMb,
      prefixLength,
      dailyCreationLimit,
      totalManagedLimit,
      generationEnabled: generation === "true",
    };
  }

  async updateSettings(patch: SettingsPatch): Promise<void> {
    const values: readonly [keyof SettingsPatch, string, string][] = [
      ["mailboxQuotaMb", "mailbox_quota_mb", String(patch.mailboxQuotaMb)],
      ["prefixLength", "prefix_length", String(patch.prefixLength)],
      ["dailyCreationLimit", "daily_creation_limit", String(patch.dailyCreationLimit)],
      ["totalManagedLimit", "total_managed_limit", String(patch.totalManagedLimit)],
      ["generationEnabled", "generation_enabled", String(patch.generationEnabled)],
    ];
    const statements = values
      .filter(([property]) => patch[property] !== undefined)
      .map(([, key, value]) => this.db.prepare("UPDATE settings SET value = ? WHERE key = ?")
        .bind(value, key));
    if (statements.length > 0) await this.db.batch(statements);
  }

  async updateSettingsWithAudit(patch: SettingsPatch, event: AuditEventInput): Promise<void> {
    const statements = settingsStatements(this.db, patch);
    const results = await this.db.batch([...statements, auditStatement(this.db,event)]);
    requireSingleChange(results.at(-1));
  }

  async createTokenDigest(input: CreateTokenDigestInput): Promise<void> {
    try {
      await this.db.prepare(`INSERT INTO api_tokens(
        id, name, token_hmac, created_at
      ) VALUES(?, ?, ?, ?)`)
        .bind(input.id, input.name, toArrayBuffer(input.digest), input.createdAt)
        .run();
    } catch (error) {
      throw normalizeDatabaseError(error);
    }
  }

  async createTokenDigestWithAudit(input: CreateTokenDigestInput, event: AuditEventInput): Promise<void> {
    try {
      await this.mutateWithAudit(this.db.prepare(`INSERT INTO api_tokens(id,name,token_hmac,created_at)
        VALUES(?,?,?,?)`).bind(input.id,input.name,toArrayBuffer(input.digest),input.createdAt), event);
    } catch (error) { throw normalizeDatabaseError(error); }
  }

  async countActiveTokens(): Promise<number> {
    const row = await this.db.prepare("SELECT COUNT(*) AS count FROM api_tokens WHERE revoked_at IS NULL")
      .first<{ count: number }>();
    return Number(row?.count ?? 0);
  }

  async revokeToken(id: string, revokedAt: string): Promise<void> {
    const result = await this.db.prepare(`UPDATE api_tokens SET revoked_at = ?
      WHERE id = ? AND revoked_at IS NULL`).bind(revokedAt, id).run();
    requireSingleChange(result);
  }

  async revokeTokenWithAudit(id: string, revokedAt: string, event: AuditEventInput): Promise<void> {
    await this.mutateWithAudit(this.db.prepare("UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL")
      .bind(revokedAt,id), event);
  }

  async verifyTokenDigest(digest: Uint8Array, lastUsedAt: string): Promise<ApiTokenRecord | null> {
    const blob = toArrayBuffer(digest);
    const [updateResult, selectResult] = await this.db.batch([
      this.db.prepare(`UPDATE api_tokens
        SET last_used_at = ?
        WHERE token_hmac = ? AND revoked_at IS NULL`)
        .bind(lastUsedAt, blob),
      this.db.prepare(`SELECT id, name, created_at, last_used_at, revoked_at
        FROM api_tokens
        WHERE token_hmac = ? AND revoked_at IS NULL`)
        .bind(blob),
    ]);
    if (Number(updateResult?.meta.changes ?? 0) !== 1) {
      return null;
    }
    const row = selectResult?.results[0] as TokenRow | undefined;
    return row === undefined ? null : {
      id: row.id,
      name: row.name,
      createdAt: row.created_at,
      lastUsedAt: row.last_used_at,
      revokedAt: row.revoked_at,
    };
  }

  async appendAudit(event: AuditEventInput): Promise<void> {
    await auditStatement(this.db, event).run();
  }

  async pageAudit(options: PageAuditOptions = {}): Promise<AuditPage> {
    const limit = validPageLimit(options.limit);
    let cursorClause = "";
    const bindings: unknown[] = [];
    if (options.cursor !== undefined) {
      const cursor = decodeAuditCursor(options.cursor);
      cursorClause = "WHERE (created_at < ? OR (created_at = ? AND id < ?))";
      bindings.push(cursor.createdAt, cursor.createdAt, cursor.id);
    }
    const result = await this.db.prepare(`SELECT id, actor_type, actor_id, actor_email,
        action, email, result, error_code, request_id, created_at
      FROM audit_events ${cursorClause}
      ORDER BY created_at DESC, id DESC LIMIT ?`)
      .bind(...bindings, limit + 1).all<{
        id: string; actor_type: string; actor_id: string; actor_email: string | null;
        action: string; email: string | null; result: string; error_code: string | null;
        request_id: string; created_at: string;
      }>();
    const pageRows = result.results.slice(0, limit);
    const last = pageRows.at(-1);
    return {
      items: pageRows.map((row) => ({
        id: row.id, actorType: row.actor_type, actorId: row.actor_id,
        actorEmail: row.actor_email, action: row.action, email: row.email,
        result: row.result, errorCode: row.error_code, requestId: row.request_id,
        createdAt: row.created_at,
      })),
      nextCursor: result.results.length > limit && last !== undefined
        ? btoa(JSON.stringify({ createdAt: last.created_at, id: last.id }))
        : null,
    };
  }

  async listRecoveryCandidates(
    statuses: readonly MailboxStatus[],
    staleBefore: string,
    now: string,
    limit = 25,
  ): Promise<readonly MailboxRecord[]> {
    if (statuses.length === 0) return [];
    const placeholders = statuses.map(() => "?").join(", ");
    const result = await this.db.prepare(`SELECT ${MAILBOX_COLUMNS}
      FROM mailboxes
      WHERE status IN (${placeholders})
        AND updated_at <= ?
        AND recovery_attempt_count < 8
        AND (recovery_next_at IS NULL OR recovery_next_at <= ?)
      ORDER BY updated_at ASC, public_id ASC LIMIT ?`)
      .bind(...statuses, staleBefore, now, Math.min(limit, 25)).all<MailboxRow>();
    return result.results.map(mapMailbox);
  }

  async recordRecoveryAttempt(publicId: string, status: MailboxStatus, now: string): Promise<void> {
    const row = await this.db.prepare(`UPDATE mailboxes
      SET recovery_attempt_count = recovery_attempt_count + 1,
          recovery_next_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?, '+' || MIN(1800, 30 * (1 << recovery_attempt_count)) || ' seconds'),
          updated_at = ?
      WHERE public_id = ? AND status = ? AND recovery_attempt_count < 8
      RETURNING public_id`)
      .bind(now, now, publicId, status).first<{ public_id: string }>();
    if (row === null) throw new RepositoryError("INVALID_STATE");
  }

  private async mutateWithAudit(mutation: D1PreparedStatement, event: AuditEventInput): Promise<void> {
    const [changed, audit] = await this.db.batch([mutation, auditStatement(this.db,event,true)]);
    requireSingleChange(changed);
    requireSingleChange(audit);
  }
}

function auditStatement(
  db: D1Database,
  event: AuditEventInput,
  requirePreviousChange = false,
): D1PreparedStatement {
  return db.prepare(`INSERT INTO audit_events(
      id,
      actor_type,
      actor_id,
      actor_email,
      action,
      email,
      result,
      error_code,
      request_id,
      created_at
    ) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      WHERE ${requirePreviousChange ? "changes() = 1" : "1 = 1"}`)
    .bind(
      event.id,
      event.actorType,
      event.actorId,
      event.actorEmail ?? null,
      event.action,
      event.email,
      event.result,
      event.errorCode,
      event.requestId,
      event.createdAt,
    );
}

function settingsStatements(db: D1Database, patch: SettingsPatch): D1PreparedStatement[] {
  const values: readonly [keyof SettingsPatch, string, string][] = [
    ["mailboxQuotaMb", "mailbox_quota_mb", String(patch.mailboxQuotaMb)],
    ["prefixLength", "prefix_length", String(patch.prefixLength)],
    ["dailyCreationLimit", "daily_creation_limit", String(patch.dailyCreationLimit)],
    ["totalManagedLimit", "total_managed_limit", String(patch.totalManagedLimit)],
    ["generationEnabled", "generation_enabled", String(patch.generationEnabled)],
  ];
  return values.filter(([property]) => patch[property] !== undefined)
    .map(([,key,value]) => db.prepare("UPDATE settings SET value=? WHERE key=?").bind(value,key));
}

function validPageLimit(value: number | undefined): number {
  const limit = value ?? 50;
  if (!Number.isFinite(limit) || !Number.isInteger(limit) || limit <= 0) {
    throw new RepositoryError("INVALID_INPUT");
  }
  return Math.min(limit, 100);
}

function mapMailbox(row: MailboxRow): MailboxRecord {
  return {
    publicId: row.public_id,
    email: row.email,
    localPart: row.local_part,
    domain: row.domain,
    passwordCiphertext: fromBlob(row.password_ciphertext),
    passwordNonce: fromBlob(row.password_nonce),
    encryptionKeyVersion: row.encryption_key_version,
    nextPasswordCiphertext: row.next_password_ciphertext === null
      ? null
      : fromBlob(row.next_password_ciphertext),
    nextPasswordNonce: row.next_password_nonce === null
      ? null
      : fromBlob(row.next_password_nonce),
    nextPasswordKeyVersion: row.next_password_key_version,
    quotaMb: row.quota_mb,
    status: row.status,
    failureCode: row.failure_code,
    recoveryAttemptCount: row.recovery_attempt_count,
    recoveryNextAt: row.recovery_next_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function decodeAuditCursor(value: string): { createdAt: string; id: string } {
  try {
    const parsed = JSON.parse(atob(value)) as { createdAt?: unknown; id?: unknown };
    if (typeof parsed.createdAt !== "string" || typeof parsed.id !== "string") throw new Error();
    return { createdAt: parsed.createdAt, id: parsed.id };
  } catch {
    throw new RepositoryError("INVALID_CURSOR");
  }
}

function mapMailboxSummary(row: MailboxSummaryRow): MailboxSummary {
  return {
    publicId: row.public_id,
    email: row.email,
    domain: row.domain,
    quotaMb: row.quota_mb,
    status: row.status,
    createdAt: row.created_at,
    failureCode: row.failure_code,
  };
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function fromBlob(value: unknown): Uint8Array {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return Uint8Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value as number[]);
  }
  throw new RepositoryError("INVALID_STATE");
}

function requireSingleChange(result: D1Result<unknown> | undefined): void {
  if (Number(result?.meta.changes ?? 0) !== 1) {
    throw new RepositoryError("INVALID_STATE");
  }
}

function integerSetting(settings: ReadonlyMap<string, string>, key: string): number {
  const raw = settings.get(key);
  const parsed = raw === undefined ? Number.NaN : Number(raw);
  if (!Number.isInteger(parsed)) {
    throw new RepositoryError("INVALID_SETTINGS");
  }
  return parsed;
}

function normalizeDatabaseError(error: unknown): RepositoryError | unknown {
  const message = error instanceof Error ? error.message : String(error);
  if (message.includes("DAILY_LIMIT")) {
    return new RepositoryError("DAILY_LIMIT");
  }
  if (message.includes("TOTAL_LIMIT")) {
    return new RepositoryError("TOTAL_LIMIT");
  }
  if (message.includes("RESERVATION_RELEASE")) {
    return new RepositoryError("RESERVATION_RELEASE");
  }
  if (message.includes("mailboxes.email")) {
    return new RepositoryError("EMAIL_EXISTS");
  }
  if (message.includes("mailboxes.public_id")) {
    return new RepositoryError("PUBLIC_ID_EXISTS");
  }
  if (message.includes("api_tokens.token_hmac") || message.includes("api_tokens.id")) {
    return new RepositoryError("TOKEN_EXISTS");
  }
  if (message.includes("TOKEN_LIMIT")) {
    return new RepositoryError("TOKEN_LIMIT");
  }
  return error;
}

function escapeLike(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("%", "\\%").replaceAll("_", "\\_");
}

function encodeCursor(cursor: PageCursor): string {
  return btoa(JSON.stringify(cursor));
}

function decodeCursor(value: string): PageCursor {
  try {
    const parsed = JSON.parse(atob(value)) as Partial<PageCursor>;
    if (
      (parsed.sort !== "createdAt" && parsed.sort !== "email" && parsed.sort !== "status")
      || (parsed.direction !== "asc" && parsed.direction !== "desc")
      || typeof parsed.value !== "string"
      || typeof parsed.publicId !== "string"
    ) {
      throw new Error("invalid cursor");
    }
    return parsed as PageCursor;
  } catch {
    throw new RepositoryError("INVALID_CURSOR");
  }
}
