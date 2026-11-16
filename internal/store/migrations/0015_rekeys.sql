-- M9.3 (D111): lost-phone re-keys. One row per replaced account; the later REKEY (created_ms, then the lower record
-- key) wins. new_own_rank: the new account's own clash rank while it inherits the old account's (NULL until then).
CREATE TABLE rekeys(old_user_id BLOB PRIMARY KEY, new_user_id BLOB NOT NULL, record_key BLOB NOT NULL,
                    created_ms INTEGER NOT NULL, new_own_rank INTEGER);
CREATE INDEX rekeys_new ON rekeys(new_user_id);
