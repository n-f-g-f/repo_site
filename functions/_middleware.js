import { getSessionBundle } from "./api/_auth.js";

function logEvent(event, data = {}) {
    try {
        console.log(JSON.stringify({
            event,
            timestamp: new Date().toISOString(),
            ...data,
        }));
    } catch (_) {
        // silent fail
    }
}

function extractIP(request) {
    const cf = request.headers.get("CF-Connecting-IP");
    if (cf) return cf;
    const xff = request.headers.get("X-Forwarded-For");
    if (xff) return xff.split(",")[0].trim();
    return "";
}

function isProtectedPath(pathname) {
    if (!pathname) return false;
    return pathname.startsWith("/leagues/");
}

function canAccessLeaguePath(pathname, access) {
    if (!pathname.startsWith("/leagues/")) return true;

    const parts = pathname.split("/").filter(Boolean);
    if (parts.length < 2) return false;

    if (!access) return false;
    if (access.can_access_all) return true;

    const leagueKey = String(parts[1] || "").trim().toLowerCase();
    if (!leagueKey) return false;

    const allowedLeagues = Array.isArray(access.allowed_leagues) ? access.allowed_leagues : [];
    return allowedLeagues.includes(leagueKey);
}

export async function onRequest(context) {
    const { request, next, env } = context;
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Skip public paths & API endpoints
    if (!isProtectedPath(pathname)) {
        return next();
    }

    const bundle = await getSessionBundle(env, request);
    const ip = extractIP(request);

    // No session at all → redirect to login with ?next
    if (!bundle) {
        logEvent("access_denied", {
            path: pathname,
            ip,
            reason: "no_session",
        });
        const nextParam = encodeURIComponent(pathname + (url.search || ""));
        return Response.redirect(`${url.origin}/login.html?next=${nextParam}`, 302);
    }

    // Session exists but no entitlement → redirect to access page
    if (!canAccessLeaguePath(pathname, bundle.access)) {
        logEvent("access_denied", {
            path: pathname,
            ip,
            user_id: bundle.user?.id,
            reason: "no_entitlement",
        });
        return Response.redirect(`${url.origin}/access.html`, 302);
    }

    return next();
}
