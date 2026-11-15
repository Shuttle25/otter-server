-- M9.2 (D99-D103): membership state from network-signed records and invite chains.
CREATE TABLE revocations(user_id BLOB PRIMARY KEY, created_ms INTEGER NOT NULL, reason TEXT NOT NULL);
-- one row per (version, value): equal versions with different values resolve to "no" (D99)
CREATE TABLE invite_rights(user_id BLOB NOT NULL, version INTEGER NOT NULL, can_invite INTEGER NOT NULL,
                           created_ms INTEGER NOT NULL, PRIMARY KEY(user_id, version, can_invite));
-- inviter: the INVITE's author (the network's id16 for a bootstrap invite); a duplicate loser never admits anyone
CREATE TABLE redemptions(invite_id BLOB NOT NULL, user_id BLOB NOT NULL, rank BLOB NOT NULL, inviter BLOB NOT NULL,
                         PRIMARY KEY(invite_id, user_id));
CREATE INDEX redemptions_inviter ON redemptions(inviter);
CREATE TABLE username_clashes(username TEXT PRIMARY KEY);
ALTER TABLE users ADD COLUMN revoke_reason TEXT NOT NULL DEFAULT '';
-- D101 (owner, 2026-11-15): every member may invite unless an INVITE_RIGHTS withdrew it; DirectoryEntry.can_invite
-- no longer counts, and no INVITE_RIGHTS was ever issued before this version.
UPDATE users SET can_invite = 1;
INSERT OR IGNORE INTO username_clashes(username)
  SELECT substr(username, 1, instr(username, '#') - 1) FROM users WHERE username_conflict = 1 AND instr(username, '#') > 0;
