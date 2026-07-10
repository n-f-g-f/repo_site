// PBA — Password reset request endpoint
// POST /api/request_reset
// Registers a password reset request in D1. Manual processing by admin.
// Security: never reveals whether the email exists in the database.
// Sends admin notification email via Resend when a valid pending request is created.

const RATE_LIMIT_MINUTES = 15;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const SUCCESS_MESSAGE = "Se o email estiver associado a uma conta, receberá uma nova password por email em breve.";
const FROM_EMAIL = "PBA Alerts <noreply@ptbballanalytics.com>";

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

function escapeHtml(text) {
    return String(text || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
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
        const result = await db
            .prepare(
                "INSERT INTO password_reset_requests (email, status, ip_address, user_agent) VALUES (?, ?, ?, ?)"
            )
            .bind(email, status, ipAddress, userAgent)
            .run();
        return result?.meta?.last_row_id || null;
    } catch (_) {
        return null;
    }
}

async function sendAdminNotification(env, requestData) {
    try {
        const apiKey = env.RESEND_API_KEY;
        const toEmail = env.ADMIN_NOTIFICATION_EMAIL;

        if (!apiKey || !toEmail) return;

        const {
            requestId,
            email,
            requestedAt,
            ipAddress,
            userAgent,
        } = requestData;

        const uaShort = String(userAgent || "").slice(0, 100);

        const html = `
<div style="font-family:Inter,Arial,sans-serif;color:#0f172a;max-width:600px;">
  <h2 style="color:#0f172a;margin-bottom:8px;">Novo pedido de reset de password</h2>
  <p style="color:#475569;margin-top:0;">Recebeste um novo pedido de reset de password no PBA.</p>

  <table style="border-collapse:collapse;margin:16px 0;font-size:14px;">
    <tr>
      <td style="padding:6px 12px;color:#64748b;font-weight:600;">ID do pedido</td>
      <td style="padding:6px 12px;color:#0f172a;">${escapeHtml(requestId)}</td>
    </tr>
    <tr>
      <td style="padding:6px 12px;color:#64748b;font-weight:600;">Email do cliente</td>
      <td style="padding:6px 12px;color:#0f172a;"><strong>${escapeHtml(email)}</strong></td>
    </tr>
    <tr>
      <td style="padding:6px 12px;color:#64748b;font-weight:600;">Timestamp</td>
      <td style="padding:6px 12px;color:#0f172a;">${escapeHtml(requestedAt)}</td>
    </tr>
    <tr>
      <td style="padding:6px 12px;color:#64748b;font-weight:600;">IP</td>
      <td style="padding:6px 12px;color:#0f172a;">${escapeHtml(ipAddress)}</td>
    </tr>
    <tr>
      <td style="padding:6px 12px;color:#64748b;font-weight:600;">User Agent</td>
      <td style="padding:6px 12px;color:#475569;font-size:12px;">${escapeHtml(uaShort)}</td>
    </tr>
  </table>

  <div style="background:#f1f5f9;border-left:3px solid #2563eb;padding:12px 16px;margin:16px 0;font-size:14px;color:#334155;">
    Consulta a tabela <code>password_reset_requests</code> no D1 e segue o workflow em <code>ops_admin_workflow.md</code> secção 7.
  </div>

  <p style="color:#94a3b8;font-size:12px;margin-top:24px;">
    PBA Analytics — Notificação automática de sistema
  </p>
</div>`.trim();

        await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
                "authorization": `Bearer ${apiKey}`,
                "content-type": "application/json",
            },
            body: JSON.stringify({
                from: FROM_EMAIL,
                to: [toEmail],
                subject: "[PBA] Novo pedido de reset de password",
                html: html,
            }),
        });
    } catch (_) {
        // silent — never crash
    }
}

export async function onRequestPost(context) {
    const db = context.env.AUTH_DB;
    const env = context.env;
    const request = context.request;

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
        const requestId = await insertRequest(db, email, status, ipAddress, userAgent);

        // Send admin notification ONLY for pending (real) requests
        if (status === "pending" && requestId) {
            await sendAdminNotification(env, {
                requestId,
                email,
                requestedAt: new Date().toISOString(),
                ipAddress,
                userAgent,
            });
        }

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
