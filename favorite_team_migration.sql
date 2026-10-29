-- PBA "My team": favourite team per user. Run BEFORE deploying the new _auth.js.
ALTER TABLE users ADD COLUMN favorite_league_key TEXT;
ALTER TABLE users ADD COLUMN favorite_team_key TEXT;
