-- M5: push tokens (D60). The table exists since 0001 (unused until now): add ordering columns.
DELETE FROM push_tokens;
ALTER TABLE push_tokens ADD COLUMN created_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE push_tokens ADD COLUMN record_key BLOB;
