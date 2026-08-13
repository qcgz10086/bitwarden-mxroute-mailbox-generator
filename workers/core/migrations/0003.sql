ALTER TABLE api_tokens ADD COLUMN operation_id TEXT;
ALTER TABLE api_tokens ADD COLUMN pending_actor_id TEXT;
ALTER TABLE api_tokens ADD COLUMN pending_token_ciphertext BLOB;
ALTER TABLE api_tokens ADD COLUMN pending_token_nonce BLOB;
ALTER TABLE api_tokens ADD COLUMN pending_token_key_version INTEGER;
ALTER TABLE api_tokens ADD COLUMN pending_expires_at TEXT;
ALTER TABLE api_tokens ADD COLUMN acknowledged_at TEXT;

UPDATE api_tokens SET acknowledged_at = created_at WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX api_tokens_operation_id_idx ON api_tokens(operation_id)
  WHERE operation_id IS NOT NULL;
CREATE INDEX api_tokens_pending_expiry_idx ON api_tokens(pending_expires_at)
  WHERE revoked_at IS NULL AND acknowledged_at IS NULL;

DROP TRIGGER enforce_active_token_limit;
CREATE TRIGGER enforce_active_token_limit
BEFORE INSERT ON api_tokens
WHEN NEW.revoked_at IS NULL AND (
  SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL
) >= 2
BEGIN SELECT RAISE(ABORT, 'TOKEN_LIMIT'); END;
