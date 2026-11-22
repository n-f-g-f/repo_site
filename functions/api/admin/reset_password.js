// PBA — Admin: reset password
// POST /api/admin/reset_password
// Body: { user_id }
// Generates a new temporary password (returned ONCE), ends every session and
// marks the client's pending reset requests as processed.

import {
  requireAdmin, jsonResponse, errorResponse, methodNotAllowed, readJson, extractIP,
  parseUserId, getUserById, generateTempPassword, buildPasswordFields, auditStatement,
  RESET_DONE_STATUS,
} from "./_admin.js";

export async function onRequestPost(context) {
  const guard = await requireAdmin(context, { write: true });
  if (guard.response) return guard.response;
  const { admin } = guard;
  const db = context.env.AUTH_DB;
  const body = await readJson(context.request);

  const userId = parseUserId(body.user_id);
  if (!userId) return errorResponse("Cliente inválido.");
  const user = await getUserById(db, userId);
  if (!user) return errorResponse("Cliente não encontrado.", 404);

  const tempPassword = generateTempPassword();
  const { salt, passwordHash } = await buildPasswordFields(tempPassword);

  let sessionsEnded = 0;
  let requestsClosed = 0;
  try {
    const results = await db.batch([
      db.prepare("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?").bind(passwordHash, salt, userId),
      db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId),
      db.prepare(
        `UPDATE password_reset_requests
         SET status = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ?
         WHERE lower(email) = lower(?) AND status = 'pending'`
      ).bind(RESET_DONE_STATUS, admin.email, user.email),
      auditStatement(db, {
        admin,
        action: "reset_password",
        targetUserId: userId,
        targetEmail: user.email,
        details: {},
        ip: extractIP(context.request),
      }),
    ]);
    sessionsEnded = results?.[1]?.meta?.changes || 0;
    requestsClosed = results?.[2]?.meta?.changes || 0;
  } catch (_) {
    return errorResponse("Não foi possível repor a password.", 500);
  }

  return jsonResponse({
    ok: true,
    email: user.email,
    temp_password: tempPassword,
    sessions_ended: sessionsEnded,
    requests_closed: requestsClosed,
  });
}

export const onRequestGet = methodNotAllowed;
