// POST /api/change_password  { current_password, new_password }
// Self-service password change for a signed-in user (rule R-AUTH-2).
// - verifies the current password (PBKDF2 or legacy SHA-256)
// - new password: >= 10 characters, <= 200, different from the current one
// - stores PBKDF2 with a fresh salt
// - ends every other session of the user, keeps the current one
// - 5 failed attempts per user per 15 minutes (Cloudflare Cache API,
//   per data centre; no D1 table needed)
import {
  getSessionBundle,
  hashPasswordPbkdf2,
  json,
  verifyPassword,
} from "./_auth.js";

const MIN_LENGTH = 10;
const MAX_LENGTH = 200;
const MAX_FAILURES = 5;
const WINDOW_SECONDS = 15 * 60;

function logEvent(event, data = {}) {
  try {
    console.log(JSON.stringify({ event, timestamp: new Date().toISOString(), ...data }));
  } catch (_) {
    // silent fail
  }
}

function randomSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function failureKey(userId) {
  return new Request(`https://pba-rate-limit.internal/change-password/${encodeURIComponent(String(userId))}`);
}

async function readFailures(userId) {
  try {
    const hit = await caches.default.match(failureKey(userId));
    if (!hit) return 0;
    const n = parseInt(await hit.text(), 10);
    return Number.isFinite(n) ? n : 0;
  } catch (_) {
    return 0;
  }
}

async function writeFailures(userId, count) {
  try {
    await caches.default.put(
      failureKey(userId),
      new Response(String(count), { headers: { "cache-control": `max-age=${WINDOW_SECONDS}` } })
    );
  } catch (_) {
    // silent fail: rate limiting is best effort
  }
}

async function clearFailures(userId) {
  try {
    await caches.default.delete(failureKey(userId));
  } catch (_) {
    // silent fail
  }
}

export async function onRequestPost(context) {
  const { env, request } = context;
  try {
    const bundle = await getSessionBundle(env, request);
    if (!bundle) return json({ ok: false, error: "Please sign in again." }, 401);
    const userId = bundle.user.id;

    let body = {};
    try { body = await request.json(); } catch (_) { body = {}; }
    const current = String(body?.current_password ?? "");
    const next = String(body?.new_password ?? "");

    if (!current || !next) {
      return json({ ok: false, error: "Fill in the current and the new password." }, 400);
    }
    if (next.length < MIN_LENGTH) {
      return json({ ok: false, error: `The new password must have at least ${MIN_LENGTH} characters.` }, 400);
    }
    if (next.length > MAX_LENGTH) {
      return json({ ok: false, error: `The new password must have at most ${MAX_LENGTH} characters.` }, 400);
    }
    if (next === current) {
      return json({ ok: false, error: "The new password must be different from the current one." }, 400);
    }

    const failures = await readFailures(userId);
    if (failures >= MAX_FAILURES) {
      logEvent("password_change_blocked", { user_id: userId });
      return json({ ok: false, error: "Too many attempts. Please wait 15 minutes and try again." }, 429);
    }

    const user = await env.AUTH_DB
      .prepare("SELECT id, password_hash, salt, is_active FROM users WHERE id = ? LIMIT 1")
      .bind(userId)
      .first();
    if (!user || !user.is_active) return json({ ok: false, error: "Please sign in again." }, 401);

    const check = await verifyPassword(current, user.salt || "", user.password_hash);
    if (!check.ok) {
      await writeFailures(userId, failures + 1);
      logEvent("password_change_failed", { user_id: userId, reason: "wrong_current_password" });
      return json({ ok: false, error: "The current password is not correct." }, 403);
    }

    const salt = randomSalt();
    const hash = await hashPasswordPbkdf2(next, salt);
    await env.AUTH_DB
      .prepare("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?")
      .bind(hash, salt, userId)
      .run();
    const ended = await env.AUTH_DB
      .prepare("DELETE FROM sessions WHERE user_id = ? AND session_token <> ?")
      .bind(userId, bundle.session_token)
      .run();
    await clearFailures(userId);

    const otherSessions = Number(ended?.meta?.changes ?? 0);
    logEvent("password_changed", { user_id: userId, other_sessions_ended: otherSessions });
    return json({ ok: true, other_sessions_ended: otherSessions });
  } catch (error) {
    logEvent("password_change_error", { error: String(error?.message || error || "unknown") });
    return json({ ok: false, error: "Could not change the password. Please try again." }, 500);
  }
}

export async function onRequestGet() {
  return json({ ok: false, error: "Method not allowed." }, 405);
}
