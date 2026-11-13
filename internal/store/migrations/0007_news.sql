-- M6.5 (D66): announcement deletions, kept forever so a lagging peer cannot resurrect the target.
CREATE TABLE news_deleted(target BLOB PRIMARY KEY);
