// PBA — Admin: deactivate or reactivate an account
// POST /api/admin/set_active
// Body: { user_id, active: true|false }
// Changes users.is_active and ends every open session. Never deletes clients.

import {
  requireAdmin, jsonResponse, errorResponse, methodNotAllowed, readJson, extractIP,
  parseUserId, getUserById, auditStatement,
} from "./_admin.js";

export async function onRequestPost(context) {
  const guard = await requireAdmin(context, { write: true });
  if (guard.response) return guard.response;
  const { admin } = guard;
  const db = context.env.AUTH_DB;
  const body = await readJson(context.request);

  const userId = parseUserId(body.user_id);
  if (!userId) return errorResponse("Cliente inválido.");
  if (typeof body.active !== "boolean") return errorResponse("Estado inválido.");
  const active = body.active ? 1 : 0;

  if (userId === admin.id && !active) {
    return errorResponse("Não pode desativar a sua própria conta.");
  }

  const user = await getUserById(db, userId);
  if (!user) return errorResponse("Cliente não encontrado.", 404);

  let sessionsEnded = 0;
  try {
    const results = await db.batch([
      db.prepare("UPDATE users SET is_active = ? WHERE id = ?").bind(active, userId),
      db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId),
      auditStatement(db, {
        admin,
        action: active ? "reactivate_user" : "deactivate_user",
        targetUserId: userId,
        targetEmail: user.email,
        details: { before: { is_active: user.is_active }, after: { is_active: active } },
        ip: extractIP(context.request),
      }),
    ]);
    sessionsEnded = results?.[1]?.meta?.changes || 0;
  } catch (_) {
    return errorResponse("Não foi possível alterar o estado da conta.", 500);
  }

  return jsonResponse({ ok: true, is_active: active, sessions_ended: sessionsEnded });
}

export const onRequestGet = methodNotAllowed;
