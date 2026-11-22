// PBA — Admin: client list
// GET /api/admin/users?q=<email ou nome>

import { requireAdmin, jsonResponse, methodNotAllowed, planStatusSql } from "./_admin.js";

export async function onRequestGet(context) {
  const guard = await requireAdmin(context);
  if (guard.response) return guard.response;
  const db = context.env.AUTH_DB;

  const url = new URL(context.request.url);
  const q = String(url.searchParams.get("q") || "").trim().toLowerCase().slice(0, 100);
  const like = `%${q.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;

  const result = await db.prepare(
    `SELECT
       u.id, u.email, u.full_name, u.is_active, u.created_at, u.digest_opt_in,
       (SELECT MAX(s.created_at) FROM sessions s WHERE s.user_id = u.id) AS last_session_at,
       a.plan_code, a.billing_cycle, a.starts_at, a.ends_at,
       (SELECT group_concat(al.league_key, ',') FROM access_leagues al WHERE al.access_right_id = a.id) AS leagues,
       ${planStatusSql("a")} AS plan_status
     FROM users u
     LEFT JOIN access_rights a
       ON a.id = (SELECT x.id FROM access_rights x WHERE x.user_id = u.id AND x.is_active = 1 ORDER BY x.id DESC LIMIT 1)
     WHERE ?1 = ''
        OR lower(u.email) LIKE ?2 ESCAPE '\\'
        OR lower(COALESCE(u.full_name, '')) LIKE ?2 ESCAPE '\\'
     ORDER BY u.created_at DESC, u.id DESC
     LIMIT 500`
  ).bind(q, like).all();

  return jsonResponse({ ok: true, users: result?.results || [] });
}

export const onRequestPost = methodNotAllowed;
