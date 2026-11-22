// PBA — Admin: pending password reset requests
// GET /api/admin/reset_requests

import { requireAdmin, jsonResponse, methodNotAllowed } from "./_admin.js";

export async function onRequestGet(context) {
  const guard = await requireAdmin(context);
  if (guard.response) return guard.response;
  const db = context.env.AUTH_DB;

  const result = await db.prepare(
    `SELECT r.id, r.email, r.requested_at, r.ip_address,
            u.id AS user_id, u.full_name, u.is_active
     FROM password_reset_requests r
     LEFT JOIN users u ON lower(u.email) = lower(r.email)
     WHERE r.status = 'pending'
     ORDER BY r.requested_at DESC, r.id DESC`
  ).all();

  return jsonResponse({ ok: true, requests: result?.results || [] });
}

export const onRequestPost = methodNotAllowed;
