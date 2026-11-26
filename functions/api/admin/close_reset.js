// PBA — Admin: fechar pedido de reposição sem gerar password (Fase 3)
// POST /api/admin/close_reset   body: { request_id, status: "processed" | "ignored", notes }
// For requests already solved another way, duplicates or emails without an account.
// To generate a new password use reset_password (it closes the pending requests itself).
// Registo: admin_audit_log, action = "close_reset_request".
import {
  requireAdmin, jsonResponse, errorResponse, methodNotAllowed, readJson, extractIP,
  auditStatement, RESET_DONE_STATUS,
} from "./_admin.js";

const ALLOWED = new Set([RESET_DONE_STATUS, "ignored"]);

export async function onRequestPost(context) {
  const guard = await requireAdmin(context, { write: true });
  if (guard.response) return guard.response;
  const { admin } = guard;
  const db = context.env.AUTH_DB;

  const body = await readJson(context.request);
  const requestId = Number(body.request_id);
  if (!Number.isInteger(requestId) || requestId <= 0) return errorResponse("Pedido inválido.");
  const status = String(body.status || "").trim();
  if (!ALLOWED.has(status)) return errorResponse("Estado inválido.");
  const notes = String(body.notes || "").trim().slice(0, 300);

  const req = await db.prepare(
    "SELECT id, email, status FROM password_reset_requests WHERE id = ?"
  ).bind(requestId).first();
  if (!req) return errorResponse("Pedido não encontrado.", 404);
  if (req.status !== "pending") return errorResponse("Este pedido já não está pendente. Recarregue a lista.", 409);

  try {
    const results = await db.batch([
      db.prepare(
        `UPDATE password_reset_requests
         SET status = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ?, notes = ?
         WHERE id = ? AND status = 'pending'`
      ).bind(status, admin.email, notes || null, requestId),
      auditStatement(db, {
        admin,
        action: "close_reset_request",
        targetEmail: req.email,
        details: { request_id: requestId, status, notes },
        ip: extractIP(context.request),
      }),
    ]);
    if (!results?.[0]?.meta?.changes) return errorResponse("Este pedido já não está pendente. Recarregue a lista.", 409);
  } catch (_) {
    return errorResponse("Não foi possível fechar o pedido.", 500);
  }
  return jsonResponse({ ok: true, request_id: requestId, status });
}

export const onRequestGet = methodNotAllowed;
