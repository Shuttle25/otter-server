-- M9.2 (C8, D107): per-author budgets. compacted: keys of records deleted as superseded, ignored when re-sent (30 days).
-- prekey_floor: one-time key ids below the floor were consumed and forgotten here; they are never inserted again.
CREATE TABLE compacted(record_key BLOB PRIMARY KEY, until_ms INTEGER NOT NULL);
CREATE TABLE prekey_floor(user_id BLOB NOT NULL, device_id INTEGER NOT NULL, owner_node BLOB NOT NULL,
                          floor_id INTEGER NOT NULL, PRIMARY KEY(user_id, device_id, owner_node));
CREATE INDEX IF NOT EXISTS records_type_author ON records(type, author, created_ms);
