import {
    buildSessionCookie,
    clearSessionCookie,
    hashPasswordPbkdf2,
    json,
    randomToken,
    verifyPassword,
} from "./_auth.js";

function logEvent(event, data = {}) {
    try {
        console.log(JSON.stringify({
            event,
            timestamp: new Date().toISOString(),
            ...data,
        }));
    } catch (_) {
        // silent fail
    }
}

function extractIP(request) {
    const cf = request.headers.get("CF-Connecting-IP");
    if (cf) return cf;
    const xff = request.headers.get("X-Forwarded-For");
    if (xff) return xff.split(",")[0].trim();
    return "";
}

function normalizePath(pathname) {
    if (!pathname) return "/";
    return pathname.replace(/\/+/g, "/").replace(/\/index\.html$/, "").replace(/\/$/, "") || "/";
}

function normalizeNextPath(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";

    try {
        if (raw.startsWith("http://") || raw.startsWith("https://")) {
            const url = new URL(raw);
            return normalizePath(url.pathname) + (url.search || "");
        }
    } catch (_) {
        return "";
    }

    if (!raw.startsWith("/")) {
        return "";
    }

    if (raw.startsWith("/api/")) {
        return "";
    }

    return raw;
}

function canAccessLeaguePath(pathname, access) {
    const path = normalizePath(pathname);
    const parts = path.split("/").filter(Boolean);

    if (!parts.length) return true;
    if (parts[0] !== "leagues") return true;
    if (!access) return false;
    if (access.can_access_all) return true;

    const leagueKey = String(parts[1] || "").trim().toLowerCase();
    if (!leagueKey) return false;

    const allowedLeagues = Array.isArray(access.allowed_leagues) ? access.allowed_leagues : [];
    return allowedLeagues.includes(leagueKey);
}

function defaultRedirectForAccess(access) {
    if (!access || !access.plan_code) {
        return "/access.html";
    }

    if (access.can_access_all) {
        return "/";
    }

    const allowedLeagues = Array.isArray(access.allowed_leagues) ? access.allowed_leagues : [];
    if (!allowedLeagues.length) {
        return "/access.html";
    }

    return `/leagues/${allowedLeagues[0]}/index.html`;
}

function resolveRedirect(access, nextPath) {
    const normalizedNext = normalizeNextPath(nextPath);
    if (!normalizedNext) {
        return defaultRedirectForAccess(access);
    }

    const nextOnlyPath = normalizedNext.split("?")[0] || "/";
    if (canAccessLeaguePath(nextOnlyPath, access)) {
        return normalizedNext;
    }

    return "/access.html";
}

export async function onRequestPost(context) {
    const ip = extractIP(context.request);

    try {
        const body = await context.request.json();
        const email = String(body?.email || "").trim().toLowerCase();
        const password = String(body?.password || "");
        const nextPath = String(body?.next || "");

        if (!email || !password) {
            return json({ ok: false, error: "Email and password are required." }, 400);
        }

        const user = await context.env.AUTH_DB
            .prepare(
                `SELECT
                    id,
                    email,
                    password_hash,
                    salt,
                    full_name,
                    is_active
                FROM users
                WHERE email = ?
                LIMIT 1`
            )
            .bind(email)
            .first();

        if (!user || !user.is_active) {
            logEvent("login_failed", { email, ip, reason: "email_not_found" });
            return json({ ok: false, error: "Invalid email or password." }, 401);
        }

        const check = await verifyPassword(password, user.salt || "", user.password_hash);
        if (!check.ok) {
            logEvent("login_failed", { email, ip, user_id: user.id, reason: "wrong_password" });
            return json({ ok: false, error: "Invalid email or password." }, 401);
        }
        if (check.needsUpgrade) {
            // Transparent migration: legacy SHA-256 -> PBKDF2, same salt.
            try {
                const upgraded = await hashPasswordPbkdf2(password, user.salt || "");
                await context.env.AUTH_DB
                    .prepare("UPDATE users SET password_hash = ? WHERE id = ?")
                    .bind(upgraded, user.id)
                    .run();
                logEvent("password_hash_upgraded", { user_id: user.id });
            } catch (e) {
                logEvent("password_hash_upgrade_failed", { user_id: user.id, error: String(e?.message || e) });
            }
        }

        const token = randomToken();
        const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString();

        await context.env.AUTH_DB
            .prepare(
                `INSERT INTO sessions (
                    session_token,
                    user_id,
                    expires_at
                ) VALUES (?, ?, ?)`
            )
            .bind(token, user.id, expiresAt)
            .run();

        const accessRow = await context.env.AUTH_DB
            .prepare(
                `SELECT
                    id,
                    plan_code,
                    billing_cycle,
                    is_active
                FROM access_rights
                WHERE user_id = ? AND is_active = 1
                ORDER BY id DESC
                LIMIT 1`
            )
            .bind(user.id)
            .first();

        let leagueRows = [];
        if (accessRow?.id) {
            const result = await context.env.AUTH_DB
                .prepare(
                    `SELECT
                        league_key
                    FROM access_leagues
                    WHERE access_right_id = ?
                    ORDER BY id ASC`
                )
                .bind(accessRow.id)
                .all();

            leagueRows = Array.isArray(result?.results) ? result.results : [];
        }

        const allowedLeagues = Array.from(
            new Set(
                leagueRows
                    .map((row) => String(row?.league_key || "").trim().toLowerCase())
                    .filter(Boolean)
            )
        );

        const access = {
            plan_code: accessRow?.plan_code || null,
            billing_cycle: accessRow?.billing_cycle || null,
            allowed_leagues: allowedLeagues,
            can_access_all:
                accessRow?.plan_code === "all_leagues" || accessRow?.plan_code === "full_access_yearly",
        };

        logEvent("login_success", {
            user_id: user.id,
            email: user.email,
            ip,
            plan_code: access.plan_code,
        });

        return json(
            {
                ok: true,
                user: {
                    id: user.id,
                    email: user.email,
                    full_name: user.full_name || "",
                },
                access,
                redirect_to: resolveRedirect(access, nextPath),
            },
            200,
            {
                "set-cookie": buildSessionCookie(token),
            }
        );
    } catch (error) {
        logEvent("login_error", { ip, error: String(error?.message || error || "unknown") });
        return json(
            { ok: false, error: "Login failed." },
            500,
            { "set-cookie": clearSessionCookie() }
        );
    }
}

export async function onRequestGet() {
    return json({ ok: false, error: "Method not allowed." }, 405);
}
