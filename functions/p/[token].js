// functions/p/[token].js — public, temporary player profile shared by a member.
// GET /p/<token>: looks up shared_profiles in D1 (not revoked, not expired),
// reads the league's recruit_index.json through env.ASSETS (static asset, not
// exposed to the visitor) and renders ONE player only. No links into /leagues/.
const METRICS = [
  ["ppg", "PPG", "num"], ["rpg", "RPG", "num"], ["apg", "APG", "num"], ["mpg", "MPG", "num"],
  ["ts_pct", "TS%", "pct"], ["efg_pct", "eFG%", "pct"], ["tp_pct", "3P%", "pct"], ["ft_pct", "FT%", "pct"],
  ["usg_pct", "USG%", "pct"], ["ast_pct", "AST%", "pct"], ["tov_pct", "TOV%", "pct"], ["trb_pct", "TRB%", "pct"],
  ["stl_pct", "STL%", "pct"], ["blk_pct", "BLK%", "pct"], ["netrtg", "NetRtg", "num"], ["on_off_net_diff_per40", "On-Off/40", "num"],
];
// Same similarity model as /pba-similar.js (rule 8.60)
const SIM = [["ppg", 1.0], ["ts_pct", 1.0], ["usg_pct", 1.2], ["ast_pct", 1.2], ["tov_pct", 0.6], ["tp_pct", 0.8],
  ["orb_pct", 1.0], ["drb_pct", 0.8], ["stl_pct", 0.6], ["blk_pct", 0.8], ["on_off_net_diff_per40", 0.5]];
const SIM_LABEL = { ppg: "PPG", ts_pct: "TS%", usg_pct: "USG%", ast_pct: "AST%", tov_pct: "TOV%", tp_pct: "3P%", orb_pct: "ORB%", drb_pct: "DRB%", stl_pct: "STL%", blk_pct: "BLK%", on_off_net_diff_per40: "On-Off" };

function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function fmt(kind, v) { if (v == null) return "—"; return kind === "pct" ? (v * 100).toFixed(1) + "%" : Number(v).toFixed(1); }

function similar(data, t) {
  if (!t.q) return [];
  const out = [];
  for (const e of data) {
    if (!e.q || e === t) continue;
    if (t.gid && e.gid && String(t.gid) === String(e.gid)) continue;
    let s = 0, w = 0, n = 0; const diffs = [];
    for (const [k, wt] of SIM) {
      const a = (t.p || {})[k], b = (e.p || {})[k];
      if (a == null || b == null) continue;
      const d = a - b; s += wt * d * d; w += wt; n++; diffs.push([SIM_LABEL[k], Math.abs(d)]);
    }
    if (n < 6) continue;
    let dist = Math.sqrt(s / w);
    if (t.pos && e.pos && t.pos !== e.pos) dist += 8;
    diffs.sort((x, y) => x[1] - y[1]);
    out.push({ e, sim: Math.max(0, Math.round(100 - dist)), keys: diffs.slice(0, 3).map((x) => x[0]) });
  }
  return out.sort((a, b) => b.sim - a.sim).slice(0, 3);
}

function page(title, body, status = 200) {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>${esc(title)}</title>
<style>
@page{size:A4;margin:12mm}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#f1f5f9;color:#0f172a}
.wrap{max-width:900px;margin:0 auto;padding:24px 16px 40px}.sheet{background:#fff;border-radius:18px;padding:26px;box-shadow:0 2px 10px rgba(15,23,42,.08)}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;border-bottom:3px solid #0f172a;padding-bottom:14px}
.eyebrow{font-size:11px;font-weight:800;letter-spacing:.08em;color:#1d4ed8}h1{margin:4px 0;font-size:30px}.meta{color:#475569;font-size:14px}
.avatar{width:78px;height:78px;border-radius:50%;background:linear-gradient(135deg,#0f172a,#1d4ed8);color:#fff;display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:800;flex:0 0 auto}
h2{font-size:16px;margin:20px 0 8px;border-bottom:2px solid #e2e8f0;padding-bottom:4px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.cell{border:1px solid #e2e8f0;border-radius:10px;padding:8px 10px}
.cell .l{font-size:11px;color:#64748b;font-weight:700}.cell .v{font-size:18px;font-weight:800;margin-top:2px}
.bar{height:6px;border-radius:999px;background:#e2e8f0;margin-top:6px;overflow:hidden}.bar i{display:block;height:100%}
.p{font-size:11px;font-weight:800;margin-left:4px}.hi{color:#166534}.md{color:#475569}.lo{color:#991b1b}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:7px 8px;border-bottom:1px solid #e2e8f0;text-align:left}th{background:#f8fafc;font-size:12px}
.note{font-size:12px;color:#64748b;line-height:1.5;margin-top:10px}.foot{margin-top:18px;padding-top:10px;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
.actions{display:flex;gap:10px;justify-content:flex-end;margin-bottom:12px}.btn{border:0;border-radius:999px;padding:10px 16px;font-weight:800;cursor:pointer;background:#0f172a;color:#fff;text-decoration:none;font-size:13px}
.btn.ghost{background:#fff;color:#0f172a;border:1px solid #cbd5e1}
@media (max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}}@media print{body{background:#fff}.actions{display:none}.wrap{padding:0}.sheet{box-shadow:none;padding:0}}
</style></head><body><div class="wrap">${body}</div></body></html>`, {
    status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex, nofollow" },
  });
}

function notAvailable(msg) {
  return page("Profile not available · PBA", `<div class="sheet"><div class="eyebrow">PORTUGUESE BASKETBALL ANALYTICS</div>
<h1>Profile not available</h1><p class="meta">${esc(msg)}</p>
<div class="actions" style="justify-content:flex-start;margin-top:16px"><a class="btn" href="/access.html">Discover PBA</a></div></div>`, 410);
}

export async function onRequestGet({ request, env, params }) {
  const token = String(params.token || "").trim();
  if (!/^[a-f0-9]{24}$/.test(token)) return notAvailable("This link is not valid.");
  const row = await env.AUTH_DB.prepare(
    "SELECT s.*, u.full_name, u.is_active FROM shared_profiles s JOIN users u ON u.id = s.user_id WHERE s.token = ?"
  ).bind(token).first().catch(() => null);
  if (!row || row.revoked || Number(row.is_active) !== 1) return notAvailable("This link has been disabled by its owner.");
  if (String(row.expires_at) <= new Date().toISOString()) return notAvailable("This link has expired. Shared profiles are available for 14 days.");

  let data = [];
  try {
    const res = await env.ASSETS.fetch(new URL(`/leagues/${row.league_key}/recruit_index.json`, request.url));
    data = res.ok ? await res.json() : [];
  } catch (e) { data = []; }
  const t = (Array.isArray(data) ? data : []).find((e) => e.hub === row.hub_path);
  if (!t) return notAvailable("This player's profile is no longer available.");
  env.AUTH_DB.prepare("UPDATE shared_profiles SET views = views + 1 WHERE token = ?").bind(token).run().catch(() => {});

  const initials = String(t.n || "?").split(/[\s.]+/).filter(Boolean).map((x) => x[0]).join("").slice(0, 2).toUpperCase();
  const bio = [t.pos, t.age != null ? `${t.age} y/o` : "", t.ht ? `${(t.ht / 100).toFixed(2)} m` : "", t.nat].filter(Boolean).join(" · ");
  const cells = METRICS.map(([k, l, kind]) => {
    const v = (t.v || {})[k], p = (t.p || {})[k];
    const cls = p == null ? "" : (p >= 75 ? "hi" : p <= 25 ? "lo" : "md");
    const color = p == null ? "#cbd5e1" : (p >= 75 ? "#16a34a" : p <= 25 ? "#dc2626" : "#64748b");
    return `<div class="cell"><div class="l">${esc(l)}${p != null ? `<span class="p ${cls}">P${p}</span>` : ""}</div><div class="v">${fmt(kind, v)}</div>` +
      `<div class="bar"><i style="width:${p == null ? 0 : p}%;background:${color}"></i></div></div>`;
  }).join("");
  const zones = Array.isArray(t.z) && t.z.length
    ? `<h2>Shot profile</h2><table><thead><tr><th>Zone</th><th>Attempts</th><th>Share</th><th>FG%</th></tr></thead><tbody>${t.z.map((z) =>
      `<tr><td>${esc(z.z)}</td><td>${z.a == null ? "—" : z.a}</td><td>${fmt("pct", z.s)}</td><td>${fmt("pct", z.p)}</td></tr>`).join("")}</tbody></table>`
    : "";
  const sims = similar(data, t);
  const simHtml = sims.length
    ? `<h2>Similar profiles in ${esc(t.ln)}</h2><table><thead><tr><th>Player</th><th>Team · Season</th><th>Pos</th><th>Similarity</th><th>Closest on</th></tr></thead><tbody>${sims.map((s) =>
      `<tr><td>${esc(s.e.n)}</td><td>${esc(s.e.tn || s.e.t)} · ${esc(s.e.sl)}</td><td>${esc(s.e.pos || "—")}</td><td><b>${s.sim}%</b></td><td>${esc(s.keys.join(", "))}</td></tr>`).join("")}</tbody></table>`
    : "";
  const pctNote = t.q ? "P = percentile among qualified players of the same league and season (higher is always better; TOV% is inverted)." : "Not enough minutes or games yet for league percentiles.";
  const sharedBy = row.full_name ? `Shared by ${esc(row.full_name)} via PBA` : "Shared via PBA";
  const body = `<div class="actions"><button class="btn ghost" type="button" onclick="window.print()">Print / Save as PDF</button><a class="btn" href="/access.html">Discover PBA</a></div>
<div class="sheet"><div class="top"><div><div class="eyebrow">PLAYER PROFILE · ${esc(t.ln)} ${esc(t.sl)}</div><h1>${esc(t.n)}</h1>
<div class="meta">${esc(t.tn || t.t)}${bio ? " · " + esc(bio) : ""}${t.g != null ? " · " + t.g + " games" : ""}</div></div><div class="avatar">${esc(initials)}</div></div>
<h2>Season profile</h2><div class="grid">${cells}</div><div class="note">${pctNote}</div>
${zones}${simHtml}
<div class="foot"><span>${sharedBy}</span><span>Link valid until ${esc(String(row.expires_at).slice(0, 10))}</span><span>ptbballanalytics.com</span></div></div>`;
  return page(`${t.n} · Player profile · PBA`, body);
}
