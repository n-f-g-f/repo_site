import { getSessionBundle } from "./api/_auth.js";

const PUBLIC_PATHS = new Set([
  "/",
  "/about.html",
  "/access.html",
  "/login.html",
  "/contact.html",
  "/privacy.html",
  "/terms.html",
  "/cookies.html",
  "/404.html",
]);

const CURRENT_SEASON_BY_LEAGUE = {
  betclic: "2025_2026",
  betclic_fem: "2025_2026",
  proliga: "2025_2026",
};

function normalizePath(pathname) {
  if (!pathname) return "/";
  return pathname.replace(/\/+/g, "/").replace(/\/index\.html$/, "").replace(/\/$/, "") || "/";
}

function isPublicPath(pathname) {
  return PUBLIC_PATHS.has(normalizePath(pathname));
}

function isProtectedLeaguePath(pathname) {
  const path = normalizePath(pathname);
  return path === "/leagues" || path.startsWith("/leagues/");
}

function buildRedirectUrl(requestUrl, targetPath) {
  const url = new URL(requestUrl);
  url.pathname = targetPath;
  url.search = "";
  url.hash = "";
  return url.toString();
}

function buildLoginRedirectUrl(requestUrl) {
  const request = new URL(requestUrl);
  const loginUrl = new URL(requestUrl);
  loginUrl.pathname = "/login.html";
  loginUrl.search = "";
  loginUrl.hash = "";

  const nextValue = request.pathname + (request.search || "");
  loginUrl.searchParams.set("next", nextValue);

  return loginUrl.toString();
}

function canAccessLeaguePath(pathname, access) {
  const path = normalizePath(pathname);
  const parts = path.split("/").filter(Boolean);

  if (!parts.length) return true;
  if (parts[0] !== "leagues") return true;
  if (!access) return false;
  if (access.can_access_all) return true;

  const leagueKey = String(parts[1] || "").trim().toLowerCase();
  const seasonKey = String(parts[2] || "").trim();
  const allowedLeagueKey = String(access.league_key || "").trim().toLowerCase();

  if (!leagueKey) {
    return false;
  }

  if (access.can_access_history) {
    return leagueKey === allowedLeagueKey;
  }

  if (access.can_access_current_only) {
    const currentSeasonKey = CURRENT_SEASON_BY_LEAGUE[allowedLeagueKey] || "";

    if (leagueKey !== allowedLeagueKey) {
      return false;
    }

    if (!seasonKey) {
      return true;
    }

    return seasonKey === currentSeasonKey;
  }

  return false;
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const pathname = normalizePath(url.pathname);

  if (pathname.startsWith("/api/")) {
    return context.next();
  }

  if (isPublicPath(pathname)) {
    return context.next();
  }

  if (!isProtectedLeaguePath(pathname)) {
    return context.next();
  }

  const session = await getSessionBundle(env, request);

  if (!session || !session.access) {
    return Response.redirect(buildLoginRedirectUrl(request.url), 302);
  }

  if (!canAccessLeaguePath(pathname, session.access)) {
    return Response.redirect(buildRedirectUrl(request.url, "/access.html"), 302);
  }

  return context.next();
}