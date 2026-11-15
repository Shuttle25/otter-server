-- M9.2 (C8, D107): invites are ranked per author by (created_ms, record_key); legacy rows rank first and are never
-- evicted. PUSH_TOKEN: only the newest record per author is kept from now on; superseded legacy records go now.
ALTER TABLE invites ADD COLUMN created_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE invites ADD COLUMN record_key BLOB;
CREATE INDEX IF NOT EXISTS invites_inviter ON invites(inviter, expires_ms);
DELETE FROM records WHERE type = 8 AND EXISTS (SELECT 1 FROM records n WHERE n.type = 8 AND n.author = records.author
  AND (n.created_ms > records.created_ms OR (n.created_ms = records.created_ms AND n.record_key > records.record_key)));
