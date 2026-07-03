// PBA — Password reset request endpoint
// POST /api/request_reset
// Registers a password reset request in D1. Manual processing by admin.
// Security: never reveals whether the email exists in the database.

const RATE_LIMIT_MINUTES = 15;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const SUCCESS_MESSAGE = "Se o email estiver associado a uma conta, receberá uma nova password por email em breve.";

function jsonResponse(payload, status = 200) {
    return new Response(JSON.stringify(payload), {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

function extractIP(request) {
    const cf = request.headers.get("CF-Connecting-IP");
    if (cf) return cf;
    const xff = request.headers.get("X-Forwarded-For");
    if (xff) return xff.split(",")[0].trim();
    return "";
}

function extractUserAgent(request) {
    const ua = request.headers.get("User-Agent") || "";
    return ua.slice(0, 500);
}

async function isRateLimited(db, email) {
    try {
        const cutoff = new Date(Date.now() - RATE_LIMIT_MINUTES * 60 * 1000).toISOString();
        const row = await db
            .prepare(
                "SELECT id FROM password_reset_requests WHERE lower(email) = lower(?) AND requested_at > ? LIMIT 1"
            )
            .bind(email, cutoff)
            .first();
        return !!row;
    } catch (_e) {
        return false;
    }
}

async function userExists(db, email) {
    try {
        const row = await db
            .prepare("SELECT id FROM users WHERE lower(email) = lower(?) AND is_active = 1 LIMIT 1")
            .bind(email)
            .first();
        return !!row;
    } catch (_e) {
        return false;
    }
}

async function insertRequest(db, email, status, ip, ua) {
    try {
        await db
            .prepare(
                "INSERT INTO password_reset_requests (email, ip_address, user_agent, status) VALUES (?, ?, ?, ?)"
            )
            .bind(email, ip, ua, status)
            .run();
    } catch (_e) {
        // silent — never surface DB errors to the client
    }
}

export async function onRequestPost(context) {
    const { request, env } = context;
    const db = env.AUTH_DB;

    if (!db) {
        return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
    }

    let body = {};
    try {
        body = await request.json();
    } catch (_e) {
        return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
    }

    const email = String(body.email || "").trim().toLowerCase();

    if (!email || !EMAIL_REGEX.test(email) || email.length > 254) {
        return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
    }

    const ip = extractIP(request);
    const ua = extractUserAgent(request);

    if (await isRateLimited(db, email)) {
        return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
    }

    const exists = await userExists(db, email);
    const status = exists ? "pending" : "ignored";

    await insertRequest(db, email, status, ip, ua);

    return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
}

export async function onRequestGet() {
    return jsonResponse({ ok: false, error: "Method not allowed" }, 405);
}

export async function onRequestOptions() {
    return new Response(null, {
        status: 204,
        headers: {
            "access-control-allow-origin": "same-origin",
            "access-control-allow-methods": "POST, OPTIONS",
            "access-control-allow-headers": "content-type",
            "access-control-max-age": "86400",
        },
    });
}
