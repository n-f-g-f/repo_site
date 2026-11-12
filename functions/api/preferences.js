// functions/api/preferences.js — user preferences: My team, followed players, weekly digest.
// GET  /api/preferences  -> { ok, user, access, favorite, followed[], digest_opt_in }
// POST /api/preferences
//   { league_key, team_key }                       set My team (unchanged)
//   { clear: true }                                remove My team (unchanged)
//   { action: "follow", league_key, season_key, team_key, player_key, player_name, hub_path }
//   { action: "unfollow", league_key, team_key, player_key }
//   { action: "digest", enabled: true|false }      weekly digest consent (users.digest_opt_in)
import { getSessionBundle, json } from "./_auth.js";

const MAX_FOLLOWED = 30;

function leagueAllowed(access, leagueKey) {
  const allowed = Array.isArray(access?.allowed_leagues) ? access.allowed_leagues : [];
  return !!(access?.can_access_all || allowed.includes(leagueKey));
}

async function loadFollowed(env, userId) {
  try {
    const r = await env.AUTH_DB.prepare(
      "SELECT league_key, season_key, team_key, player_key, player_name, hub_path, created_at FROM followed_players WHERE user_id = ? ORDER BY created_at DESC"
    ).bind(userId).all();
    return Array.isArray(r?.results) ? r.results : [];
  } catch (e) {
    return [];
  }
}

export async function onRequestGet({ request, env }) {
  const bundle = await getSessionBundle(env, request);
  if (!bundle) return json({ ok: false, authenticated: false }, 401);
  let digest = 0;
  try {
    const row = await env.AUTH_DB.prepare("SELECT digest_opt_in FROM users WHERE id = ?").bind(bundle.user.id).first();
    digest = Number(row?.digest_opt_in || 0);
  } catch (e) { digest = 0; }
  const followed = (await loadFollowed(env, bundle.user.id)).filter((f) => leagueAllowed(bundle.access, f.league_key));
  return json({
    ok: true,
    user: { email: bundle.user.email, full_name: bundle.user.full_name },
    access: bundle.access,
    favorite: {
      league_key: bundle.user.favorite_league_key || null,
      team_key: bundle.user.favorite_team_key || null,
    },
    followed,
    digest_opt_in: digest === 1,
  });
}

export async function onRequestPost({ request, env }) {
  const bundle = await getSessionBundle(env, request);
  if (!bundle) return json({ ok: false, error: "Not authenticated." }, 401);
  let body = {};
  try { body = await request.json(); } catch (_) { body = {}; }
  const uid = bundle.user.id;

  // ---- weekly digest consent
  if (body.action === "digest") {
    const on = body.enabled ? 1 : 0;
    await env.AUTH_DB.prepare("UPDATE users SET digest_opt_in = ? WHERE id = ?").bind(on, uid).run();
    return json({ ok: true, digest_opt_in: on === 1 });
  }

  // ---- followed players
  if (body.action === "follow" || body.action === "unfollow") {
    const leagueKey = String(body.league_key || "").trim().toLowerCase();
    const teamKey = String(body.team_key || "").trim().toUpperCase();
    const playerKey = String(body.player_key || "").trim();
    if (!/^[a-z0-9_]{2,30}$/.test(leagueKey) || !/^[A-Z0-9]{2,6}$/.test(teamKey) || !/^[A-Za-z0-9._-]{1,80}$/.test(playerKey)) {
      return json({ ok: false, error: "Invalid player." }, 400);
    }
    if (body.action === "unfollow") {
      await env.AUTH_DB.prepare("DELETE FROM followed_players WHERE user_id = ? AND league_key = ? AND team_key = ? AND player_key = ?")
        .bind(uid, leagueKey, teamKey, playerKey).run();
      return json({ ok: true, following: false });
    }
    if (!leagueAllowed(bundle.access, leagueKey)) {
      return json({ ok: false, error: "League not included in your plan." }, 403);
    }
    const seasonKey = String(body.season_key || "").trim();
    const name = String(body.player_name || "").trim().slice(0, 80);
    let hub = String(body.hub_path || "").trim();
    if (!/^\d{4}_\d{4}$/.test(seasonKey)) return json({ ok: false, error: "Invalid season." }, 400);
    if (!hub.startsWith("/leagues/" + leagueKey + "/") || !/^[A-Za-z0-9_./-]{1,200}$/.test(hub)) hub = "";
    const count = await env.AUTH_DB.prepare("SELECT COUNT(*) AS n FROM followed_players WHERE user_id = ?").bind(uid).first();
    if (Number(count?.n || 0) >= MAX_FOLLOWED) {
      return json({ ok: false, error: "You can follow up to " + MAX_FOLLOWED + " players." }, 400);
    }
    await env.AUTH_DB.prepare(
      "INSERT OR IGNORE INTO followed_players (user_id, league_key, season_key, team_key, player_key, player_name, hub_path) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(uid, leagueKey, seasonKey, teamKey, playerKey, name, hub).run();
    return json({ ok: true, following: true });
  }

  // ---- My team (unchanged behaviour)
  if (body && body.clear) {
    await env.AUTH_DB.prepare("UPDATE users SET favorite_league_key = NULL, favorite_team_key = NULL WHERE id = ?")
      .bind(uid).run();
    return json({ ok: true, favorite: null });
  }
  const leagueKey = String(body.league_key || "").trim().toLowerCase();
  const teamKey = String(body.team_key || "").trim().toUpperCase();
  if (!/^[a-z0-9_]{2,30}$/.test(leagueKey) || !/^[A-Z0-9]{2,6}$/.test(teamKey)) {
    return json({ ok: false, error: "Invalid team." }, 400);
  }
  if (!leagueAllowed(bundle.access, leagueKey)) {
    return json({ ok: false, error: "League not included in your plan." }, 403);
  }
  await env.AUTH_DB.prepare("UPDATE users SET favorite_league_key = ?, favorite_team_key = ? WHERE id = ?")
    .bind(leagueKey, teamKey, uid).run();
  return json({ ok: true, favorite: { league_key: leagueKey, team_key: teamKey } });
}
