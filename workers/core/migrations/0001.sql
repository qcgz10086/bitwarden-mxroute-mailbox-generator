PRAGMA foreign_keys = ON;

CREATE TABLE domains (
  domain TEXT PRIMARY KEY,
  is_active INTEGER NOT NULL CHECK (is_active IN (0, 1)),
  synced_at TEXT NOT NULL
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  local_part TEXT NOT NULL,
  domain TEXT NOT NULL,
  reservation_date TEXT,
  reservation_token_id TEXT,
  password_ciphertext BLOB NOT NULL,
  password_nonce BLOB NOT NULL,
  encryption_key_version INTEGER NOT NULL,
  next_password_ciphertext BLOB,
  next_password_nonce BLOB,
  quota_mb INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'pending',
    'active',
    'failed',
    'resetting',
    'reset_unknown',
    'deleting',
    'delete_failed'
  )),
  failure_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (
    (status = 'pending' AND reservation_date IS NOT NULL AND reservation_token_id IS NOT NULL)
    OR
    (status != 'pending' AND reservation_date IS NULL AND reservation_token_id IS NULL)
  ),
  FOREIGN KEY (domain) REFERENCES domains(domain)
);

CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hmac BLOB NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE creation_counters (
  date TEXT NOT NULL,
  token_id TEXT NOT NULL,
  count INTEGER NOT NULL CHECK (count >= 0),
  PRIMARY KEY (date, token_id),
  FOREIGN KEY (token_id) REFERENCES api_tokens(id)
);

CREATE TABLE audit_events (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  email TEXT,
  result TEXT NOT NULL,
  error_code TEXT,
  request_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX mailboxes_email_idx ON mailboxes(email);
CREATE INDEX mailboxes_status_updated_at_idx ON mailboxes(status, updated_at);
CREATE INDEX audit_events_created_at_idx ON audit_events(created_at);

INSERT INTO settings(key, value) VALUES
  ('mailbox_quota_mb', '100'),
  ('prefix_length', '12'),
  ('daily_creation_limit', '30'),
  ('total_managed_limit', '500'),
  ('generation_enabled', 'true');

CREATE TRIGGER enforce_daily_limit_insert
BEFORE INSERT ON creation_counters
WHEN NEW.count > CAST((SELECT value FROM settings WHERE key = 'daily_creation_limit') AS INTEGER)
BEGIN SELECT RAISE(ABORT, 'DAILY_LIMIT'); END;

CREATE TRIGGER enforce_daily_limit_update
BEFORE UPDATE OF count ON creation_counters
WHEN NEW.count > CAST((SELECT value FROM settings WHERE key = 'daily_creation_limit') AS INTEGER)
BEGIN SELECT RAISE(ABORT, 'DAILY_LIMIT'); END;

CREATE TRIGGER enforce_total_managed_limit
BEFORE INSERT ON mailboxes
WHEN (SELECT COUNT(*) FROM mailboxes) >= CAST((SELECT value FROM settings WHERE key = 'total_managed_limit') AS INTEGER)
BEGIN SELECT RAISE(ABORT, 'TOTAL_LIMIT'); END;

CREATE TRIGGER enforce_pending_reservation
BEFORE INSERT ON mailboxes
WHEN NEW.status = 'pending' AND NOT EXISTS (
  SELECT 1
  FROM creation_counters
  WHERE date = NEW.reservation_date
    AND token_id = NEW.reservation_token_id
    AND count > 0
)
BEGIN SELECT RAISE(ABORT, 'RESERVATION_RELEASE'); END;

CREATE TRIGGER prevent_pending_reservation_retarget
BEFORE UPDATE OF reservation_date, reservation_token_id ON mailboxes
WHEN OLD.status = 'pending'
  AND NEW.status = 'pending'
  AND (
    NEW.reservation_date IS NOT OLD.reservation_date
    OR NEW.reservation_token_id IS NOT OLD.reservation_token_id
  )
BEGIN SELECT RAISE(ABORT, 'RESERVATION_OWNERSHIP'); END;

CREATE TRIGGER release_pending_reservation
BEFORE UPDATE OF status ON mailboxes
WHEN OLD.status = 'pending' AND NEW.status = 'failed'
BEGIN
  UPDATE creation_counters
  SET count = count - 1
  WHERE date = OLD.reservation_date
    AND token_id = OLD.reservation_token_id
    AND count > 0;
  SELECT CASE
    WHEN changes() != 1 THEN RAISE(ABORT, 'RESERVATION_RELEASE')
  END;
END;
