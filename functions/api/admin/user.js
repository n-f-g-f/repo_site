// PBA — Admin: client card
// GET /api/admin/user?id=<user_id>

import { requireAdmin, jsonResponse, errorResponse, methodNotAllowed, parseUserId, planStatusSql } from "./_admin.js";

export async function onRequestGet(context) {
  const guard = await requireAdmin(context);
  if (guard.response) return guard.response;
  const db = context.env.AUTH_DB;

  const userId = parseUserId(new URL(context.request.url).searchParams.get("id"));
  if (!userId) return errorResponse("Cliente inválido.");

  const user = await db.prepare(
    `SELECT
       u.id, u.email, u.full_name, u.is_active, u.created_at, u.digest_opt_in,
       u.favorite_league_key, u.favorite_team_key,
       (SELECT league_name FROM leagues WHERE league_key = u.favorite_league_key) AS favorite_league_name,
       (SELECT team_name FROM teams WHERE team_key = u.favorite_team_key) AS favorite_team_name,
       (SELECT MAX(created_at) FROM sessions WHERE user_id = u.id) AS last_session_at
     FROM users u
     WHERE u.id = ?`
  ).bind(userId).first();
  if (!user) return errorResponse("Cliente não encontrado.", 404);

  const [plans, sessions, followed, shared, resets, audit] = await Promise.all([
    db.prepare(
      `SELECT a.id, a.plan_code, a.billing_cycle, a.starts_at, a.ends_at, a.is_active, a.created_at,
              (SELECT group_concat(league_key, ',') FROM access_leagues WHERE access_right_id = a.id) AS leagues,
              ${planStatusSql("a")} AS plan_status
       FROM access_rights a
       WHERE a.user_id = ?
       ORDER BY a.id DESC`
    ).bind(userId).all(),
    db.prepare(
      `SELECT id, created_at, expires_at
       FROM sessions
       WHERE user_id = ?
         AND (datetime(expires_at) IS NULL OR datetime(expires_at) > datetime('now'))
       ORDER BY created_at DESC`
    ).bind(userId).all(),
    db.prepare(
      `SELECT league_key, season_key, team_key, player_key, player_name, hub_path, created_at
       FROM followed_players
       WHERE user_id = ?
       ORDER BY created_at DESC`
    ).bind(userId).all(),
    db.prepare(
      `SELECT league_key, season_key, team_key, player_name, hub_path, created_at, expires_at, views,
              CASE
                WHEN revoked = 1 THEN 'revoked'
                WHEN datetime(expires_at) IS NOT NULL AND datetime(expires_at) < datetime('now') THEN 'expired'
                ELSE 'active'
              END AS link_status
       FROM shared_profiles
       WHERE user_id = ?
       ORDER BY created_at DESC`
    ).bind(userId).all(),
    db.prepare(
      `SELECT id, requested_at, status, processed_at, processed_by
       FROM password_reset_requests
       WHERE lower(email) = lower(?)
       ORDER BY id DESC
       LIMIT 20`
    ).bind(user.email).all(),
    db.prepare(
      `SELECT id, created_at, admin_email, action, details
       FROM admin_audit_log
       WHERE target_user_id = ?
       ORDER BY id DESC
       LIMIT 50`
    ).bind(userId).all(),
  ]);

  return jsonResponse({
    ok: true,
    user,
    plans: plans?.results || [],
    sessions: sessions?.results || [],
    followed_players: followed?.results || [],
    shared_profiles: shared?.results || [],
    reset_requests: resets?.results || [],
    audit: audit?.results || [],
  });
}

export const onRequestPost = methodNotAllowed;
