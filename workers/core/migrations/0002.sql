ALTER TABLE mailboxes ADD COLUMN next_password_key_version INTEGER;
ALTER TABLE mailboxes ADD COLUMN recovery_attempt_count INTEGER NOT NULL DEFAULT 0
  CHECK (recovery_attempt_count BETWEEN 0 AND 8);
ALTER TABLE mailboxes ADD COLUMN recovery_next_at TEXT;
ALTER TABLE audit_events ADD COLUMN actor_email TEXT;

CREATE TRIGGER enforce_active_token_limit
BEFORE INSERT ON api_tokens
WHEN NEW.revoked_at IS NULL AND (
  SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL
) >= 2
BEGIN SELECT RAISE(ABORT, 'TOKEN_LIMIT'); END;
