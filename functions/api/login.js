import { buildSessionCookie, clearSessionCookie, hashPassword, json, randomToken } from "./_auth.js";

export async function onRequestPost(context) {
  try {
    const body = await context.request.json();
    const email = String(body?.email || "").trim().toLowerCase();
    const password = String(body?.password || "");

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

    return json(
      {
        ok: true,
        user: {
          id: user.id,
          email: user.email,
          full_name: user.full_name || "",
        },
        access: {
          plan_code: accessRow?.plan_code || null,
          league_key: accessRow?.league_key || null,
          billing_cycle: accessRow?.billing_cycle || null,
        },
      },
      200,
      {
        "set-cookie": buildSessionCookie(token),
      },
    );
  } catch (error) {
    return json(
      { ok: false, error: "Login failed." },
      500,
      { "set-cookie": clearSessionCookie() },
    );
  }
}

export async function onRequestGet() {
  return json({ ok: false, error: "Method not allowed." }, 405);
}