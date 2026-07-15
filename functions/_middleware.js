import { getSessionBundle } from "./api/_auth.js";

const PUBLIC_PATHS = new Set([
  "/",
  "/about.html",
  "/access.html",
  "/login.html",
  "/contact.html",
  "/password_reset.html",
  "/privacy.html",
  "/terms.html",
  "/cookies.html",
  "/404.html",
]);

function logEvent(event, data) {
  try {
    console.log(JSON.stringify({
      event,
      timestamp: new Date().toISOString(),
      ...data,
    }));
  } catch (_) {}
}

function extractIP(request) {
  const cf = request.headers.get("CF-Connecting-IP");
  if (cf) return cf;
  const xff = request.headers.get("X-Forwarded-For");
  if (xff) return xff.split(",")[0].trim();
  return "";
}

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

function buildAccessRedirectUrl(requestUrl, reason, leagueKey) {
  const target = new URL(requestUrl);
  target.pathname = "/access.html";
  target.search = "";
  target.hash = "";
  if (reason) target.searchParams.set("reason", reason);
  if (leagueKey) target.searchParams.set("league", leagueKey);
  return target.toString();
}

function extractLeagueKey(pathname) {
  const path = normalizePath(pathname);
  const parts = path.split("/").filter(Boolean);
  if (parts.length >= 2 && parts[0] === "leagues") {
    return String(parts[1] || "").trim().toLowerCase();
  }
  return "";
}

function canAccessLeaguePath(pathname, access) {
  const path = normalizePath(pathname);
  const parts = path.split("/").filter(Boolean);
  if (!parts.length) return true;
  if (parts[0] !== "leagues") return true;
  if (!access) return false;
  if (access.can_access_all) return true;
  const leagueKey = String(parts[1] || "").trim().toLowerCase();
  if (!leagueKey) {
    return false;
  }
  const allowedLeagues = Array.isArray(access.allowed_leagues) ? access.allowed_leagues : [];
  return allowedLeagues.includes(leagueKey);
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
    logEvent("access_denied", {
      path: pathname,
      ip: extractIP(request),
      reason: "no_session",
    });
    return Response.redirect(buildLoginRedirectUrl(request.url), 302);
  }

  if (!canAccessLeaguePath(pathname, session.access)) {
    const leagueKey = extractLeagueKey(pathname);
    const hasPlan = !!(session.access && session.access.plan_code);
    const reason = hasPlan ? "no_entitlement" : "no_plan";

    logEvent("access_denied", {
      path: pathname,
      ip: extractIP(request),
      reason,
      user_id: session.user && session.user.id,
      league: leagueKey,
    });

    return Response.redirect(
      buildAccessRedirectUrl(request.url, reason, hasPlan ? leagueKey : ""),
      302
    );
  }

  return context.next();
}
