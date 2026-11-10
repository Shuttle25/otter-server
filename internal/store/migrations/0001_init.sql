CREATE TABLE oplog(seq INTEGER PRIMARY KEY AUTOINCREMENT, record_key BLOB UNIQUE NOT NULL,
                   type INTEGER NOT NULL, received_ms INTEGER NOT NULL);
CREATE TABLE records(record_key BLOB PRIMARY KEY, type INTEGER NOT NULL, author BLOB NOT NULL,
                     created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL, raw BLOB NOT NULL);
CREATE INDEX records_type ON records(type);
CREATE TABLE mailbox(user_id BLOB, device_id INTEGER, record_key BLOB, origin_node BLOB,
                     received_ms INTEGER, PRIMARY KEY(user_id, device_id, record_key));
CREATE TABLE tombstones(record_key BLOB PRIMARY KEY, until_ms INTEGER NOT NULL);
CREATE TABLE users(user_id BLOB PRIMARY KEY, username TEXT UNIQUE NOT NULL, account_pub BLOB NOT NULL,
                   entry_key BLOB NOT NULL, version INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
                   can_invite INTEGER NOT NULL DEFAULT 1, created_ms INTEGER NOT NULL);
CREATE TABLE invites(invite_id BLOB PRIMARY KEY, inviter BLOB NOT NULL, expires_ms INTEGER NOT NULL, used_by BLOB);
CREATE TABLE prekeys(user_id BLOB, device_id INTEGER, key_id INTEGER, kind INTEGER,
                     owner_node BLOB, public BLOB, consumed INTEGER NOT NULL DEFAULT 0,
                     PRIMARY KEY(user_id, device_id, kind, key_id));
CREATE TABLE blobs(blob_id BLOB PRIMARY KEY, owner BLOB, size INTEGER, chunks INTEGER, sha256 BLOB,
                   present_chunks BLOB, expires_ms INTEGER, kind INTEGER);
CREATE TABLE blob_readers(blob_id BLOB, user_id BLOB, fetched INTEGER NOT NULL DEFAULT 0,
                          PRIMARY KEY(blob_id, user_id));
CREATE TABLE backups(user_id BLOB PRIMARY KEY, meta_key BLOB, version INTEGER);
CREATE TABLE auth_failures(username TEXT, at_ms INTEGER);
CREATE TABLE push_tokens(user_id BLOB, device_id INTEGER, kind INTEGER, token TEXT,
                         PRIMARY KEY(user_id, device_id));
CREATE TABLE peers(node_id BLOB PRIMARY KEY, cursor INTEGER NOT NULL DEFAULT 0, last_seen_ms INTEGER);
CREATE TABLE manifest(version INTEGER PRIMARY KEY, raw BLOB NOT NULL);
