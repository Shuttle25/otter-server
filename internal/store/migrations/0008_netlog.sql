-- M7 (D74): connectivity log; repeats of the same outcome update one line. Capped at 200 lines by the store.
CREATE TABLE netlog(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  peer TEXT NOT NULL, endpoint TEXT NOT NULL, direction TEXT NOT NULL,
  result TEXT NOT NULL, class TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  count INTEGER NOT NULL, first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL
);
CREATE INDEX netlog_key ON netlog(peer, endpoint, direction, id);
