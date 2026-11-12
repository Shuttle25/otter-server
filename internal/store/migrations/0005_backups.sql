-- M6: password backups (D50), install identity (D52), restore rate limits (D51).
ALTER TABLE blobs ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0;
DROP TABLE IF EXISTS backups;
CREATE TABLE backups(user_id BLOB PRIMARY KEY, record_key BLOB NOT NULL, version INTEGER NOT NULL,
                     created_ms INTEGER NOT NULL, blob_key BLOB NOT NULL);
CREATE INDEX backups_blob ON backups(blob_key);
ALTER TABLE devices ADD COLUMN installed_ms INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS auth_failures_name ON auth_failures(username, at_ms);
CREATE INDEX IF NOT EXISTS auth_failures_at ON auth_failures(at_ms);
