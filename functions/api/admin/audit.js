// PBA — Admin: action log
// GET /api/admin/audit?limit=200

import { requireAdmin, jsonResponse, methodNotAllowed } from "./_admin.js";

export async function onRequestGet(context) {
  const guard = await requireAdmin(context);
  if (guard.response) return guard.response;
  const db = context.env.AUTH_DB;

  const raw = Number(new URL(context.request.url).searchParams.get("limit"));
  const limit = Number.isInteger(raw) && raw > 0 ? Math.min(raw, 1000) : 200;

  const result = await db.prepare(
    `SELECT id, created_at, admin_email, action, target_user_id, target_email, details, ip_address
     FROM admin_audit_log
     ORDER BY id DESC
     LIMIT ?`
  ).bind(limit).all();

  return jsonResponse({ ok: true, entries: result?.results || [] });
}

export const onRequestPost = methodNotAllowed;
