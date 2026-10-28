-- PBA weekly digest: opt-in flag and unsubscribe token on users.
ALTER TABLE users ADD COLUMN digest_opt_in INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN digest_token TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_digest_token ON users(digest_token);
