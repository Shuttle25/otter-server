-- M9.1 (C14): the newest account-signed INSTALL record per user.
CREATE TABLE installs(user_id BLOB PRIMARY KEY, record_key BLOB NOT NULL, installed_ms INTEGER NOT NULL,
                      registration_id INTEGER NOT NULL);
