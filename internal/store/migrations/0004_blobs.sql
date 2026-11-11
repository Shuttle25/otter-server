-- M4: blobs (D44/D45). Replaces the unused M0 tables.
DROP TABLE IF EXISTS blobs;
DROP TABLE IF EXISTS blob_readers;
CREATE TABLE blobs(blob_key BLOB PRIMARY KEY, owner BLOB NOT NULL, size INTEGER NOT NULL, chunks INTEGER NOT NULL,
                   expires_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL);
CREATE INDEX blobs_owner ON blobs(owner);
CREATE INDEX blobs_expires ON blobs(expires_ms);
CREATE TABLE blob_chunks(blob_key BLOB NOT NULL, idx INTEGER NOT NULL, PRIMARY KEY(blob_key, idx));
CREATE TABLE blob_readers(blob_key BLOB NOT NULL, user_id BLOB NOT NULL, PRIMARY KEY(blob_key, user_id));
CREATE TABLE blob_fetched(blob_key BLOB NOT NULL, user_id BLOB NOT NULL, at_ms INTEGER NOT NULL,
                          PRIMARY KEY(blob_key, user_id));
CREATE TABLE blob_tombstones(blob_key BLOB PRIMARY KEY, until_ms INTEGER NOT NULL);
