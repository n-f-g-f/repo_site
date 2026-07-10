import { getCookie, getSessionBundle, json } from "./_auth.js";

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

export async function onRequestGet(context) {
    const bundle = await getSessionBundle(context.env, context.request);

    if (!bundle) {
        // Only log if there was a cookie (invalid session), not for anonymous checks
        const token = getCookie(context.request, "pba_session");
        if (token) {
            const ip = extractIP(context.request);
            const token_preview = String(token).slice(0, 8);
            logEvent("session_invalid", { ip, token_preview });
        }
        return json({ ok: false, authenticated: false }, 401);
    }

    return json({
        ok: true,
        authenticated: true,
        user: bundle.user,
        access: bundle.access,
    });
}
