-- M9.2 (C4, C10, D105): restore failures are counted per source; the attempt is reserved before the secret is compared.
ALTER TABLE auth_failures ADD COLUMN source TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS auth_failures_name_source ON auth_failures(username, source, at_ms);
CREATE INDEX IF NOT EXISTS auth_failures_source ON auth_failures(source, at_ms);
