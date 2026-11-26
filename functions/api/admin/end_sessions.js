// PBA — Admin: terminar sessões (Fase 3)
// POST /api/admin/end_sessions   body: { user_id }
// Ends every open session of the client (forced logout). Password, plan and
// account status are not changed. Registo: admin_audit_log, action = "end_sessions".
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
  if (userId === admin.id) return errorResponse("Não pode terminar as suas próprias sessões aqui.");

  const user = await getUserById(db, userId);
  if (!user) return errorResponse("Cliente não encontrado.", 404);

  const open = await db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?").bind(userId).first();
  const count = open?.n || 0;
  if (!count) return errorResponse("O cliente não tem sessões abertas.");

  let sessionsEnded = 0;
  try {
    const results = await db.batch([
      db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId),
      auditStatement(db, {
        admin,
        action: "end_sessions",
        targetUserId: userId,
        targetEmail: user.email,
        details: { sessions_ended: count },
        ip: extractIP(context.request),
      }),
    ]);
    sessionsEnded = results?.[0]?.meta?.changes || 0;
  } catch (_) {
    return errorResponse("Não foi possível terminar as sessões.", 500);
  }
  return jsonResponse({ ok: true, sessions_ended: sessionsEnded });
}

export const onRequestGet = methodNotAllowed;
