// PBA — Admin: change plan or leagues
// POST /api/admin/change_plan
// Body: { user_id, plan_code, billing_cycle, leagues[], starts_at, ends_at }
// Deactivates the current plan(s) and creates a new one in a single transaction.
// Never edits the leagues of an existing plan.

import {
  requireAdmin, jsonResponse, errorResponse, methodNotAllowed, readJson, extractIP,
  parseUserId, validatePlan, getUserById, getActivePlans, planInsertStatements, auditStatement,
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

  const { plan, error } = await validatePlan(db, body);
  if (error) return errorResponse(error);

  const before = await getActivePlans(db, userId);

  try {
    await db.batch([
      db.prepare("UPDATE access_rights SET is_active = 0 WHERE user_id = ? AND is_active = 1").bind(userId),
      ...planInsertStatements(db, user.email, plan),
      auditStatement(db, {
        admin,
        action: "change_plan",
        targetUserId: userId,
        targetEmail: user.email,
        details: { before, after: plan },
        ip: extractIP(context.request),
      }),
    ]);
  } catch (_) {
    return errorResponse("Não foi possível mudar o plano. Nada foi alterado.", 500);
  }

  return jsonResponse({ ok: true });
}

export const onRequestGet = methodNotAllowed;
