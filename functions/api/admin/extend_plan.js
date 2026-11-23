// PBA — Admin: prolongar plano (Fase 2)
// POST /api/admin/extend_plan   body: { user_id, ends_at: "AAAA-MM-DD" }
// Muda só a data de fim do plano ativo (mesmo plano, mesmas ligas).
// Plano expirado volta a ficar ativo se a nova data for >= hoje.
// Registo: admin_audit_log, action = "extend_plan", details = { before, after }.
import {
  requireAdmin, readJson, parseUserId, errorResponse, jsonResponse, methodNotAllowed,
  extractIP, getUserById, getActivePlans, auditStatement,
} from "./_admin.js";

const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
function isValidDate(value) {
  if (!DATE_REGEX.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await requireAdmin(context, { write: true });
  if (auth.response) return auth.response;
  const { admin } = auth;
  const db = env.AUTH_DB;

  const body = await readJson(request);
  const userId = parseUserId(body.user_id);
  if (!userId) return errorResponse("Cliente inválido.");
  const endsAt = String(body.ends_at || "").trim();
  if (!isValidDate(endsAt)) return errorResponse("Data de fim inválida (AAAA-MM-DD).");

  const user = await getUserById(db, userId);
  if (!user) return errorResponse("Cliente não encontrado.", 404);

  const plans = await getActivePlans(db, userId);
  const plan = plans[0];
  if (!plan) return errorResponse("O cliente não tem plano. Use “Mudar plano ou ligas”.");
  if (!plan.ends_at) return errorResponse("O plano não tem data de fim; não há nada a prolongar.");

  const today = new Date().toISOString().slice(0, 10);
  const currentEnd = String(plan.ends_at).slice(0, 10);
  if (plan.starts_at && endsAt < String(plan.starts_at).slice(0, 10)) {
    return errorResponse("A nova data de fim é anterior ao início do plano.");
  }
  if (endsAt <= currentEnd) return errorResponse(`A nova data tem de ser posterior ao fim atual (${currentEnd}).`);
  if (endsAt < today) return errorResponse("A nova data de fim já passou.");

  const results = await db.batch([
    db.prepare("UPDATE access_rights SET ends_at = ? WHERE id = ? AND user_id = ? AND is_active = 1")
      .bind(endsAt, plan.access_right_id, userId),
    auditStatement(db, {
      admin,
      action: "extend_plan",
      targetUserId: user.id,
      targetEmail: user.email,
      details: {
        access_right_id: plan.access_right_id,
        plan_code: plan.plan_code,
        before: { ends_at: currentEnd },
        after: { ends_at: endsAt },
      },
      ip: extractIP(request),
    }),
  ]);
  if (!results[0]?.meta?.changes) return errorResponse("O plano mudou entretanto. Recarregue a ficha.", 409);

  return jsonResponse({ ok: true, user_id: user.id, email: user.email, ends_at: endsAt });
}

export function onRequest() {
  return methodNotAllowed();
}
