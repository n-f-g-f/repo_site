// PBA — Admin: metadata for the admin page
// GET /api/admin/meta

import { requireAdmin, jsonResponse, methodNotAllowed, PLAN_DEFS, BILLING_CYCLES } from "./_admin.js";

export async function onRequestGet(context) {
  const guard = await requireAdmin(context);
  if (guard.response) return guard.response;
  const db = context.env.AUTH_DB;

  const [leagues, pending] = await Promise.all([
    db.prepare("SELECT league_key, league_name FROM leagues ORDER BY league_name").all(),
    db.prepare("SELECT COUNT(*) AS n FROM password_reset_requests WHERE status = 'pending'").first(),
  ]);

  return jsonResponse({
    ok: true,
    admin_email: guard.admin.email,
    plans: Object.entries(PLAN_DEFS).map(([code, def]) => ({ code, label: def.label, leagues: def.leagues })),
    billing_cycles: Object.entries(BILLING_CYCLES).map(([code, label]) => ({ code, label })),
    leagues: leagues?.results || [],
    pending_resets: pending?.n || 0,
  });
}

export const onRequestPost = methodNotAllowed;
