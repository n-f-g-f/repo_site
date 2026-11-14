-- PBA "Share profile": temporary public links to one player profile.
-- Run BEFORE deploying the new preferences.js and functions/p/[token].js.
CREATE TABLE IF NOT EXISTS shared_profiles (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  league_key TEXT NOT NULL,
  season_key TEXT NOT NULL,
  team_key TEXT NOT NULL,
  hub_path TEXT NOT NULL,
  player_name TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  views INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_shared_profiles_user ON shared_profiles(user_id);
