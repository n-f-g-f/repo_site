-- PBA "Followed players". Run BEFORE deploying the new preferences.js.
CREATE TABLE IF NOT EXISTS followed_players (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  league_key TEXT NOT NULL,
  season_key TEXT,
  team_key TEXT NOT NULL,
  player_key TEXT NOT NULL,
  player_name TEXT,
  hub_path TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (user_id, league_key, team_key, player_key)
);
CREATE INDEX IF NOT EXISTS idx_followed_players_user ON followed_players(user_id);
