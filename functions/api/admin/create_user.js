// PBA — Admin: create client
// POST /api/admin/create_user
// Body: { email, full_name, plan_code, billing_cycle, leagues[], starts_at, ends_at }
// Returns the temporary password ONCE. It is never stored in clear text nor logged.

import {
  requireAdmin, jsonResponse, errorResponse, methodNotAllowed, readJson, extractIP,
  normalizeEmail, validatePlan, generateTempPassword, buildPasswordFields,
  planInsertStatements, auditStatement,
} from "./_admin.js";

export async function onRequestPost(context) {
  const guard = await requireAdmin(context, { write: true });
  if (guard.response) return guard.response;
  const { admin } = guard;
  const db = context.env.AUTH_DB;
  const body = await readJson(context.request);

  const email = normalizeEmail(body.email);
  if (!email) return errorResponse("Email inválido.");
  const fullName = String(body.full_name || "").trim().slice(0, 120);
  if (!fullName) return errorResponse("Indique o nome do cliente.");

  const { plan, error } = await validatePlan(db, body);
  if (error) return errorResponse(error);

  const existing = await db.prepare("SELECT id FROM users WHERE lower(email) = ?").bind(email).first();
  if (existing) return errorResponse("Já existe um cliente com este email.", 409);

  const tempPassword = generateTempPassword();
  const { salt, passwordHash } = await buildPasswordFields(tempPassword);

  try {
    await db.batch([
      db.prepare(
        "INSERT INTO users (email, password_hash, salt, full_name, is_active) VALUES (?, ?, ?, ?, 1)"
      ).bind(email, passwordHash, salt, fullName),
      ...planInsertStatements(db, email, plan),
      auditStatement(db, {
        admin,
        action: "create_user",
        targetEmail: email,
        details: { full_name: fullName, plan },
        ip: extractIP(context.request),
      }),
    ]);
  } catch (err) {
    if (String(err?.message || "").includes("UNIQUE")) {
      return errorResponse("Já existe um cliente com este email.", 409);
    }
    return errorResponse("Não foi possível criar o cliente.", 500);
  }

  const created = await db.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  return jsonResponse({ ok: true, user_id: created?.id || null, email, temp_password: tempPassword });
}

export const onRequestGet = methodNotAllowed;
