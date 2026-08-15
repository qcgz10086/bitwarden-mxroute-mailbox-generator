-- Allow unmanaged mailbox states to retain reservation ownership so local
-- deletion can release the daily creation quota, and track admin password
-- versions plus login throttling.
DROP TRIGGER IF EXISTS enforce_total_managed_limit;
DROP TRIGGER IF EXISTS enforce_pending_reservation;
DROP TRIGGER IF EXISTS prevent_pending_reservation_retarget;
DROP TRIGGER IF EXISTS release_pending_reservation;

ALTER TABLE mailboxes RENAME TO mailboxes_old;

CREATE TABLE mailboxes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  local_part TEXT NOT NULL,
  domain TEXT NOT NULL,
  reservation_date TEXT,
  reservation_token_id TEXT,
  password_ciphertext BLOB,
  password_nonce BLOB,
  encryption_key_version INTEGER,
  next_password_ciphertext BLOB,
  next_password_nonce BLOB,
  next_password_key_version INTEGER,
  quota_mb INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'registered',
    'pending',
    'activating',
    'active',
    'failed',
    'resetting',
    'reset_unknown',
    'deleting',
    'delete_failed'
  )),
  failure_code TEXT,
  recovery_attempt_count INTEGER NOT NULL DEFAULT 0
    CHECK (recovery_attempt_count BETWEEN 0 AND 8),
  recovery_next_at TEXT,
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (
    (status = 'pending' AND reservation_date IS NOT NULL AND reservation_token_id IS NOT NULL)
    OR
    (
      status IN ('registered', 'activating', 'failed', 'deleting', 'delete_failed')
      AND (
        (reservation_date IS NULL AND reservation_token_id IS NULL)
        OR
        (reservation_date IS NOT NULL AND reservation_token_id IS NOT NULL)
      )
    )
    OR
    (
      status IN ('active', 'resetting', 'reset_unknown')
      AND reservation_date IS NULL
      AND reservation_token_id IS NULL
    )
  ),
  FOREIGN KEY (domain) REFERENCES domains(domain)
);

INSERT INTO mailboxes(
  id, public_id, email, local_part, domain, reservation_date, reservation_token_id,
  password_ciphertext, password_nonce, encryption_key_version,
  next_password_ciphertext, next_password_nonce, next_password_key_version,
  quota_mb, status, failure_code, recovery_attempt_count, recovery_next_at, note,
  created_at, updated_at
)
SELECT
  id, public_id, email, local_part, domain, reservation_date, reservation_token_id,
  password_ciphertext, password_nonce, encryption_key_version,
  next_password_ciphertext, next_password_nonce, next_password_key_version,
  quota_mb, status, failure_code, recovery_attempt_count, recovery_next_at, note,
  created_at, updated_at
FROM mailboxes_old;

DROP TABLE mailboxes_old;

CREATE INDEX mailboxes_email_idx ON mailboxes(email);
CREATE INDEX mailboxes_status_updated_at_idx ON mailboxes(status, updated_at);

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
  SELECT RAISE(ABORT, 'RESERVATION_RELEASE') WHERE changes() = 0;
END;

CREATE TRIGGER release_reserved_mailbox_delete
BEFORE DELETE ON mailboxes
WHEN OLD.reservation_date IS NOT NULL AND OLD.reservation_token_id IS NOT NULL
BEGIN
  UPDATE creation_counters
  SET count = count - 1
  WHERE date = OLD.reservation_date
    AND token_id = OLD.reservation_token_id
    AND count > 0;
  SELECT RAISE(ABORT, 'RESERVATION_RELEASE') WHERE changes() = 0;
END;

INSERT INTO settings(key, value)
SELECT 'admin_password_version', '0'
WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key = 'admin_password_version');

CREATE TABLE login_attempts (
  key TEXT PRIMARY KEY,
  failures INTEGER NOT NULL CHECK (failures >= 0),
  blocked_until TEXT
);
