ALTER TABLE users ADD COLUMN entry_created_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN username_conflict INTEGER NOT NULL DEFAULT 0;
CREATE INDEX oplog_received ON oplog(received_ms);
CREATE INDEX prekeys_owner ON prekeys(user_id, device_id, kind, owner_node, consumed);
