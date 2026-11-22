// PBA — Admin helpers (Fase 1)
// Shared by every endpoint in functions/api/admin/ and by functions/admin.js.
// Access: only emails listed in the Cloudflare Pages variable ADMIN_EMAILS
// (comma-separated). If the variable is missing, nobody is admin (fail closed).

import { getSessionBundle, randomToken, hashPasswordPbkdf2 } from "../_auth.js";

// ── Configuração ───────────────────────────────────────────────────────
// leagues: "none" = acesso a todas, sem escolher ligas
//          "one"  = exatamente uma liga
//          "many" = uma ou mais ligas
export const PLAN_DEFS = {
  single_league_current: { label: "Uma liga (época atual)", leagues: "one" },
  all_leagues:           { label: "Todas as ligas",          leagues: "none" },
  full_access_yearly:    { label: "Acesso total",            leagues: "none" },
};

export const BILLING_CYCLES = {
  monthly: "Mensal",
  yearly:  "Anual",
};

// Estado gravado em password_reset_requests quando o admin repõe a password.
export const RESET_DONE_STATUS = "processed";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

// ── Respostas ──────────────────────────────────────────────────────────
export function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

export function errorResponse(message, status = 400) {
  return jsonResponse({ ok: false, error: message }, status);
}

export function methodNotAllowed() {
  return errorResponse("Método não permitido.", 405);
}

export function extractIP(request) {
  const cf = request.headers.get("CF-Connecting-IP");
  if (cf) return cf;
  const xff = request.headers.get("X-Forwarded-For");
  if (xff) return xff.split(",")[0].trim();
  return "";
}

// ── Autorização ────────────────────────────────────────────────────────
function adminEmails(env) {
  return String(env.ADMIN_EMAILS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

export async function getAdmin(env, request) {
  const session = await getSessionBundle(env, request);
  if (!session || !session.user) return { session: null, admin: null };
  const email = String(session.user.email || "").trim().toLowerCase();
  if (!email || !adminEmails(env).includes(email)) return { session, admin: null };
  return { session, admin: { id: session.user.id, email } };
}

// Returns { admin } or { response } (error already built).
export async function requireAdmin(context, { write = false } = {}) {
  const { request, env } = context;
  if (write) {
    const origin = request.headers.get("Origin");
    if (!origin || origin !== new URL(request.url).origin) {
      return { response: errorResponse("Origem do pedido inválida.", 403) };
    }
  }
  const { session, admin } = await getAdmin(env, request);
  if (!session) return { response: errorResponse("Sessão expirada. Volte a entrar.", 401) };
  if (!admin) return { response: errorResponse("Sem permissão.", 403) };
  return { admin };
}

export async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" ? body : {};
  } catch (_) {
    return {};
  }
}

// ── Validação ──────────────────────────────────────────────────────────
export function normalizeEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  return EMAIL_REGEX.test(email) && email.length <= 254 ? email : "";
}

export function parseUserId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : 0;
}

function isValidDate(value) {
  if (!DATE_REGEX.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

// Validates plan fields from the request body.
// Returns { plan } or { error }.
export async function validatePlan(db, body) {
  const planCode = String(body.plan_code || "").trim();
  const def = PLAN_DEFS[planCode];
  if (!def) return { error: "Plano inválido." };

  const billingCycle = String(body.billing_cycle || "").trim();
  if (!BILLING_CYCLES[billingCycle]) return { error: "Ciclo inválido." };

  const startsAt = String(body.starts_at || "").trim();
  const endsAt = String(body.ends_at || "").trim();
  if (!startsAt || !isValidDate(startsAt)) return { error: "Data de início inválida (AAAA-MM-DD)." };
  if (endsAt && !isValidDate(endsAt)) return { error: "Data de fim inválida (AAAA-MM-DD)." };
  if (endsAt && endsAt < startsAt) return { error: "A data de fim é anterior à data de início." };

  let leagues = [];
  if (def.leagues !== "none") {
    const requested = Array.from(new Set(
      (Array.isArray(body.leagues) ? body.leagues : [])
        .map((v) => String(v || "").trim().toLowerCase())
        .filter(Boolean)
    ));
    const result = await db.prepare("SELECT league_key FROM leagues").all();
    const known = new Map(
      (result?.results || []).map((r) => [String(r.league_key).toLowerCase(), r.league_key])
    );
    for (const key of requested) {
      if (!known.has(key)) return { error: `Liga desconhecida: ${key}` };
    }
    leagues = requested.map((key) => known.get(key));
    if (def.leagues === "one" && leagues.length !== 1) return { error: "Este plano exige exatamente uma liga." };
    if (def.leagues === "many" && leagues.length < 1) return { error: "Este plano exige pelo menos uma liga." };
  }

  return {
    plan: {
      plan_code: planCode,
      billing_cycle: billingCycle,
      starts_at: startsAt,
      ends_at: endsAt || null,
      leagues,
    },
  };
}

// ── Passwords temporárias ──────────────────────────────────────────────
// Sem caracteres ambíguos (0/O, 1/l/I).
const PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

export function generateTempPassword(length = 12) {
  const n = PASSWORD_ALPHABET.length;
  const limit = 256 - (256 % n);
  let out = "";
  while (out.length < length) {
    const bytes = new Uint8Array(length * 2);
    crypto.getRandomValues(bytes);
    for (const b of bytes) {
      if (b < limit) out += PASSWORD_ALPHABET[b % n];
      if (out.length === length) break;
    }
  }
  return out;
}

// Same format as _auth.js verifyPassword: users.salt + "pbkdf2$<iter>$<hex>".
export async function buildPasswordFields(password) {
  const salt = randomToken().slice(0, 32);
  const passwordHash = await hashPasswordPbkdf2(password, salt);
  return { salt, passwordHash };
}

// ── Statements reutilizados (db.batch corre numa só transação) ─────────
// Insere um plano novo e as respetivas ligas para o utilizador com este email.
export function planInsertStatements(db, email, plan) {
  const statements = [
    db.prepare(
      `INSERT INTO access_rights (user_id, plan_code, league_key, billing_cycle, starts_at, ends_at, is_active)
       VALUES ((SELECT id FROM users WHERE email = ?), ?, ?, ?, ?, ?, 1)`
    ).bind(
      email,
      plan.plan_code,
      plan.leagues.length === 1 ? plan.leagues[0] : null,
      plan.billing_cycle,
      plan.starts_at,
      plan.ends_at
    ),
  ];
  for (const leagueKey of plan.leagues) {
    statements.push(
      db.prepare(
        `INSERT INTO access_leagues (access_right_id, league_key)
         VALUES ((SELECT MAX(id) FROM access_rights WHERE user_id = (SELECT id FROM users WHERE email = ?)), ?)`
      ).bind(email, leagueKey)
    );
  }
  return statements;
}

export function auditStatement(db, { admin, action, targetUserId = null, targetEmail = "", details = {}, ip = "" }) {
  return db.prepare(
    `INSERT INTO admin_audit_log (admin_user_id, admin_email, action, target_user_id, target_email, details, ip_address)
     VALUES (?, ?, ?, COALESCE(?, (SELECT id FROM users WHERE email = ?)), ?, ?, ?)`
  ).bind(
    admin.id,
    admin.email,
    action,
    targetUserId,
    targetEmail,
    targetEmail,
    JSON.stringify(details),
    ip
  );
}

// Estado do plano, com a mesma regra de datas usada em _auth.js.
export function planStatusSql(a) {
  return `CASE
    WHEN ${a}.id IS NULL THEN 'none'
    WHEN ${a}.is_active = 0 THEN 'inactive'
    WHEN ${a}.ends_at IS NOT NULL AND date(${a}.ends_at) IS NULL THEN 'invalid_date'
    WHEN ${a}.starts_at IS NOT NULL AND date(${a}.starts_at) IS NULL THEN 'invalid_date'
    WHEN ${a}.ends_at IS NOT NULL AND date(${a}.ends_at) < date('now') THEN 'expired'
    WHEN ${a}.starts_at IS NOT NULL AND date(${a}.starts_at) > date('now') THEN 'scheduled'
    ELSE 'active'
  END`;
}

export async function getUserById(db, userId) {
  return db.prepare("SELECT id, email, full_name, is_active FROM users WHERE id = ?").bind(userId).first();
}

export async function getActivePlans(db, userId) {
  const result = await db.prepare(
    `SELECT a.id, a.plan_code, a.billing_cycle, a.starts_at, a.ends_at,
            (SELECT group_concat(league_key, ',') FROM access_leagues WHERE access_right_id = a.id) AS leagues
     FROM access_rights a
     WHERE a.user_id = ? AND a.is_active = 1
     ORDER BY a.id DESC`
  ).bind(userId).all();
  return (result?.results || []).map((r) => ({
    access_right_id: r.id,
    plan_code: r.plan_code,
    billing_cycle: r.billing_cycle,
    starts_at: r.starts_at,
    ends_at: r.ends_at,
    leagues: r.leagues ? String(r.leagues).split(",") : [],
  }));
}
