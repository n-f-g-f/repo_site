function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

export function getCookie(request, name) {
  const cookieHeader = request.headers.get("cookie") || "";
  const parts = cookieHeader.split(/;\s*/).filter(Boolean);
  for (const part of parts) {
    const eqIndex = part.indexOf("=");
    if (eqIndex === -1) continue;
    const key = part.slice(0, eqIndex).trim();
    if (key !== name) continue;
    return decodeURIComponent(part.slice(eqIndex + 1));
  }
  return null;
}

export function buildSessionCookie(token, maxAgeSeconds = 60 * 60 * 24 * 30) {
  return [
    `pba_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ].join("; ");
}

export function clearSessionCookie() {
  return [
    "pba_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

export async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${salt}${password}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = Array.from(new Uint8Array(digest));
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function computeEntitlements(accessRow, leagueRows = []) {
  if (!accessRow || !accessRow.is_active) {
    return {
      plan_code: null,
      billing_cycle: null,
      allowed_leagues: [],
      can_access_all: false,
    };
  }

  const planCode = String(accessRow.plan_code || "").trim();
  const allowedLeagues = Array.from(
    new Set(
      (leagueRows || [])
        .map((row) => String(row?.league_key || "").trim().toLowerCase())
        .filter(Boolean)
    )
  );

  return {
    plan_code: planCode,
    billing_cycle: accessRow.billing_cycle || null,
    allowed_leagues: allowedLeagues,
    can_access_all: planCode === "all_leagues" || planCode === "full_access_yearly",
  };
}

export async function getSessionBundle(env, request) {
  const token = getCookie(request, "pba_session");
  if (!token) return null;

  const sessionRow = await env.AUTH_DB
    .prepare(
      `SELECT
         s.id,
         s.session_token,
         s.user_id,
         s.expires_at,
         u.email,
         u.full_name,
         u.is_active
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.session_token = ?
       LIMIT 1`
    )
    .bind(token)
    .first();

  if (!sessionRow) return null;
  if (!sessionRow.is_active) return null;

  if (sessionRow.expires_at) {
    const expiresAt = new Date(sessionRow.expires_at);
    if (!Number.isNaN(expiresAt.getTime()) && expiresAt.getTime() < Date.now()) {
      await env.AUTH_DB.prepare("DELETE FROM sessions WHERE session_token = ?").bind(token).run();
      return null;
    }
  }

  const accessRow = await env.AUTH_DB
    .prepare(
      `SELECT
         id,
         user_id,
         plan_code,
         billing_cycle,
         starts_at,
         ends_at,
         is_active
       FROM access_rights
       WHERE user_id = ? AND is_active = 1
       ORDER BY id DESC
       LIMIT 1`
    )
    .bind(sessionRow.user_id)
    .first();

  let leagueRows = [];
  if (accessRow?.id) {
    const result = await env.AUTH_DB
      .prepare(
        `SELECT
           league_key
         FROM access_leagues
         WHERE access_right_id = ?
         ORDER BY id ASC`
      )
      .bind(accessRow.id)
      .all();

    leagueRows = Array.isArray(result?.results) ? result.results : [];
  }

  return {
    session_token: token,
    user: {
      id: sessionRow.user_id,
      email: sessionRow.email,
      full_name: sessionRow.full_name || "",
    },
    access: computeEntitlements(accessRow, leagueRows),
  };
}

export { json };