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
        const row = await db
            .prepare(
                `SELECT id FROM password_reset_requests WHERE lower(email) = lower(?) AND requested_at > datetime('now', '-${RATE_LIMIT_MINUTES} minutes') LIMIT 1`
            )
            .bind(email)
            .first();
        return row !== null && row !== undefined;
    } catch (_) {
        return false;
    }
}

async function emailExists(db, email) {
    try {
        const row = await db
            .prepare("SELECT id FROM users WHERE lower(email) = lower(?) LIMIT 1")
            .bind(email)
            .first();
        return row !== null && row !== undefined;
    } catch (_) {
        return false;
    }
}

async function insertRequest(db, email, status, ipAddress, userAgent) {
    try {
        await db
            .prepare(
                "INSERT INTO password_reset_requests (email, status, ip_address, user_agent) VALUES (?, ?, ?, ?)"
            )
            .bind(email, status, ipAddress, userAgent)
            .run();
    } catch (_) {
        // silent - never crash
    }
}

export async function onRequestPost(context) {
    const db = context.env.AUTH_DB;
    const request = context.request;

    // Always return the same message
    try {
        const body = await request.json().catch(() => ({}));
        const email = String(body?.email || "").trim().toLowerCase();

        if (!email || !EMAIL_REGEX.test(email)) {
            return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
        }

        const ipAddress = extractIP(request);
        const userAgent = extractUserAgent(request);

        // Rate limit check — silent
        if (await isRateLimited(db, email)) {
            return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
        }

        // Check if email exists
        const exists = await emailExists(db, email);
        const status = exists ? "pending" : "ignored";

        // Insert request (always — for audit)
        await insertRequest(db, email, status, ipAddress, userAgent);

        return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
    } catch (_) {
        // Never crash — always same message
        return jsonResponse({ ok: true, message: SUCCESS_MESSAGE });
    }
}

export async function onRequestGet() {
    return jsonResponse({ ok: false, error: "Method not allowed." }, 405);
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
