// functions/api/preferences.js — user preferences ("My team").
// GET  /api/preferences          -> { ok, favorite: { league_key, team_key } }
// POST /api/preferences {league_key, team_key} | {clear:true}
import { getSessionBundle, json } from "./_auth.js";

export async function onRequestGet({ request, env }) {
  const bundle = await getSessionBundle(env, request);
  if (!bundle) return json({ ok: false, authenticated: false }, 401);
  return json({
    ok: true,
    favorite: {
      league_key: bundle.user.favorite_league_key || null,
      team_key: bundle.user.favorite_team_key || null,
    },
  });
}

export async function onRequestPost({ request, env }) {
  const bundle = await getSessionBundle(env, request);
  if (!bundle) return json({ ok: false, error: "Not authenticated." }, 401);
  let body = {};
  try { body = await request.json(); } catch (_) { body = {}; }

  if (body && body.clear) {
    await env.AUTH_DB.prepare("UPDATE users SET favorite_league_key = NULL, favorite_team_key = NULL WHERE id = ?")
      .bind(bundle.user.id).run();
    return json({ ok: true, favorite: null });
  }

  const leagueKey = String(body.league_key || "").trim().toLowerCase();
  const teamKey = String(body.team_key || "").trim().toUpperCase();
  if (!/^[a-z0-9_]{2,30}$/.test(leagueKey) || !/^[A-Z0-9]{2,6}$/.test(teamKey)) {
    return json({ ok: false, error: "Invalid team." }, 400);
  }
  const access = bundle.access || {};
  const allowed = Array.isArray(access.allowed_leagues) ? access.allowed_leagues : [];
  if (!access.can_access_all && !allowed.includes(leagueKey)) {
    return json({ ok: false, error: "League not included in your plan." }, 403);
  }
  await env.AUTH_DB.prepare("UPDATE users SET favorite_league_key = ?, favorite_team_key = ? WHERE id = ?")
    .bind(leagueKey, teamKey, bundle.user.id).run();
  return json({ ok: true, favorite: { league_key: leagueKey, team_key: teamKey } });
}
