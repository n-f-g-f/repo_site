-- PBA — Registo de ações da página de administração (Fase 1)
-- Executar uma vez:
--   npx --yes wrangler d1 execute pba_auth --remote --file=migrations/admin_audit_log.sql

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  admin_user_id INTEGER NOT NULL,
  admin_email TEXT NOT NULL,
  action TEXT NOT NULL,
  target_user_id INTEGER,
  target_email TEXT,
  details TEXT,
  ip_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_log(target_user_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at);
