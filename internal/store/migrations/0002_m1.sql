DROP TABLE tombstones;
CREATE TABLE tombstones(record_key BLOB NOT NULL, user_id BLOB NOT NULL, device_id INTEGER NOT NULL,
                        until_ms INTEGER NOT NULL, PRIMARY KEY(record_key, user_id, device_id));
ALTER TABLE prekeys ADD COLUMN signature BLOB;
CREATE TABLE devices(user_id BLOB NOT NULL, device_id INTEGER NOT NULL, registration_id INTEGER NOT NULL,
                     PRIMARY KEY(user_id, device_id));
CREATE INDEX mailbox_record ON mailbox(record_key);
