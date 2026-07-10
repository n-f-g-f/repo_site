import { clearSessionCookie, getCookie, json } from "./_auth.js";

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

export async function onRequestPost(context) {
    const token = getCookie(context.request, "pba_session");
    const ip = extractIP(context.request);

    if (token) {
        try {
            await context.env.AUTH_DB
                .prepare("DELETE FROM sessions WHERE session_token = ?")
                .bind(token)
                .run();
        } catch (_) {
            // silent — best-effort cleanup
        }

        const token_preview = String(token).slice(0, 8);
        logEvent("logout", { ip, token_preview });
    }

    return json(
        { ok: true, redirect_to: "/" },
        200,
        { "set-cookie": clearSessionCookie() }
    );
}

export async function onRequestGet(context) {
    return onRequestPost(context);
}
