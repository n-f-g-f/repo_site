import {
  buildSessionCookie,
  clearSessionCookie,
  hashPassword,
  json,
  randomToken,
} from "./_auth.js";

const CURRENT_SEASON_BY_LEAGUE = {
  betclic: "2025_2026",
  betclic_fem: "2025_2026",
  proliga: "2025_2026",
};

function normalizePath(pathname) {
  if (!pathname) return "/";
  return pathname.replace(/\/+/g, "/").replace(/\/index\.html$/, "").replace(/\/$/, "") || "/";
}

function normalizeNextPath(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";

  try {
    if (raw.startsWith("http://") || raw.startsWith("https://")) {
      const url = new URL(raw);
      return normalizePath(url.pathname) + (url.search || "");
    }
  } catch (_) {
    return "";
  }

  if (!raw.startsWith("/")) {
    return "";
  }

  if (raw.startsWith("/api/")) {
    return "";
  }

  return raw;
}

function canAccessLeaguePath(pathname, access) {
  const path = normalizePath(pathname);
  const parts = path.split("/").filter(Boolean);

  if (!parts.length) return true;
  if (parts[0] !== "leagues") return true;
  if (!access) return false;
  if (access.plan_code === "full_platform") return true;

  const leagueKey = String(parts[1] || "").trim().toLowerCase();
  const seasonKey = String(parts[2] || "").trim();
  const allowedLeagueKey = String(access.league_key || "").trim().toLowerCase();

  if (!leagueKey) return false;

  if (access.plan_code === "single_league_history") {
    return leagueKey === allowedLeagueKey;
  }

  if (access.plan_code === "single_league_current") {
    const currentSeasonKey = CURRENT_SEASON_BY_LEAGUE[allowedLeagueKey] || "";
    if (leagueKey !== allowedLeagueKey) return false;
    if (!seasonKey) return true;
    return seasonKey === currentSeasonKey;
  }

  return false;
}

function defaultRedirectForAccess(access) {
  if (!access || !access.plan_code) {
    return "/access.html";
  }

  if (access.plan_code === "full_platform") {
    return "/";
  }

  const leagueKey = String(access.league_key || "").trim().toLowerCase();
  if (!leagueKey) {
    return "/access.html";
  }

  if (access.plan_code === "single_league_history") {
    return `/leagues/${leagueKey}/index.html`;
  }

  if (access.plan_code === "single_league_current") {
    const seasonKey = CURRENT_SEASON_BY_LEAGUE[leagueKey];
    if (!seasonKey) {
      return "/access.html";
    }
    return `/leagues/${leagueKey}/${seasonKey}/index.html`;
  }

  return "/access.html";
}

function resolveRedirect(access, nextPath) {
  const normalizedNext = normalizeNextPath(nextPath);
  if (!normalizedNext) {
    return defaultRedirectForAccess(access);
  }

  const nextOnlyPath = normalizedNext.split("?")[0] || "/";
  if (canAccessLeaguePath(nextOnlyPath, access)) {
    return normalizedNext;
  }

  return "/access.html";
}

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const email = String(body?.email || "").trim().toLowerCase();
    const password = String(body?.password || "");
    const nextPath = String(body?.next || "");

    if (!email || !password) {
      return json({ ok: false, error: "Email and password are required." }, 400);
    }

    const user = await context.env.AUTH_DB
      .prepare(
        `SELECT
           id,
           email,
           password_hash,
           salt,
           full_name,
           is_active
         FROM users
         WHERE email = ?
         LIMIT 1`
      )
      .bind(email)
      .first();

    if (!user || !user.is_active) {
      return json({ ok: false, error: "Invalid email or password." }, 401);
    }

    const expectedHash = await hashPassword(password, user.salt || "");
    if (expectedHash !== user.password_hash) {
      return json({ ok: false, error: "Invalid email or password." }, 401);
    }

    const token = randomToken();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();

    await context.env.AUTH_DB
      .prepare(
        `INSERT INTO sessions (
           session_token,
           user_id,
           expires_at
         ) VALUES (?, ?, ?)`
      )
      .bind(token, user.id, expiresAt)
      .run();

    const accessRow = await context.env.AUTH_DB
      .prepare(
        `SELECT
           plan_code,
           league_key,
           billing_cycle,
           is_active
         FROM access_rights
         WHERE user_id = ? AND is_active = 1
         ORDER BY id DESC
         LIMIT 1`
      )
      .bind(user.id)
      .first();

    const access = {
      plan_code: accessRow?.plan_code || null,
      league_key: accessRow?.league_key || null,
      billing_cycle: accessRow?.billing_cycle || null,
    };

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          email: user.email,
          full_name: user.full_name || "",
        },
        access,
        redirect_to: resolveRedirect(access, nextPath),
      },
      200,
      {
        "set-cookie": buildSessionCookie(token),
      }
    );
  } catch (error) {
    return json(
      { ok: false, error: "Login failed." },
      500,
      { "set-cookie": clearSessionCookie() }
    );
  }
}

export async function onRequestGet() {
  return json({ ok: false, error: "Method not allowed." }, 405);
}