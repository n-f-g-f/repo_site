
(function () {
  var LEAGUES = ["betclic", "betclic_fem", "proliga"];
  var METRICS = [{"k": "ppg", "l": "PPG", "w": 1.0}, {"k": "ts_pct", "l": "TS%", "w": 1.0}, {"k": "usg_pct", "l": "USG%", "w": 1.2}, {"k": "ast_pct", "l": "AST%", "w": 1.2}, {"k": "tov_pct", "l": "TOV%", "w": 0.6}, {"k": "tp_pct", "l": "3P%", "w": 0.8}, {"k": "orb_pct", "l": "ORB%", "w": 1.0}, {"k": "drb_pct", "l": "DRB%", "w": 0.8}, {"k": "stl_pct", "l": "STL%", "w": 0.6}, {"k": "blk_pct", "l": "BLK%", "w": 0.8}, {"k": "on_off_net_diff_per40", "l": "On-Off", "w": 0.5}];
  var MIN_COMMON = 6, POS_PENALTY = 8;
  var cache = null, signedIn = true;
  function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
  function norm(p) { return String(p || "").replace(/\.html$/, "").replace(/\/+$/, "").replace(/\/index$/, ""); }
  function load() {
    if (cache) return cache;
    cache = fetch("/api/session", { credentials: "include" }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; })
      .then(function (s) {
        signedIn = !!(s && s.authenticated);
        var acc = signedIn ? s.access : null, keys = LEAGUES.slice();
        if (!(acc && acc.can_access_all)) {
          var al = acc && Array.isArray(acc.allowed_leagues) ? acc.allowed_leagues.map(function (x) { return String(x).toLowerCase(); }) : [];
          keys = keys.filter(function (k) { return al.indexOf(k) >= 0; });
        }
        return Promise.all(keys.map(function (k) {
          return fetch("/leagues/" + k + "/recruit_index.json", { credentials: "include" }).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; });
        }));
      })
      .then(function (lists) { var d = []; lists.forEach(function (l) { if (Array.isArray(l)) d = d.concat(l); }); return d; });
    return cache;
  }
  function same(a, b) {
    if (a.gid && b.gid) return String(a.gid) === String(b.gid);
    return a.l === b.l && a.t === b.t && (a.id && b.id ? a.id === b.id : a.n === b.n);
  }
  function rank(data, target, opts) {
    opts = opts || {};
    if (!target || !target.q) return [];
    var out = [];
    data.forEach(function (e) {
      if (!e.q || e === target || same(e, target)) return;
      if (opts.current && !e.cur) return;
      if (opts.samePos && target.pos && e.pos !== target.pos) return;
      var s = 0, w = 0, n = 0, diffs = [];
      METRICS.forEach(function (m) {
        var a = (target.p || {})[m.k], b = (e.p || {})[m.k];
        if (a == null || b == null) return;
        var d = a - b; s += m.w * d * d; w += m.w; n++;
        diffs.push({ l: m.l, d: Math.abs(d) });
      });
      if (n < MIN_COMMON) return;
      var dist = Math.sqrt(s / w);
      if (target.pos && e.pos && target.pos !== e.pos) dist += POS_PENALTY;
      diffs.sort(function (x, y) { return x.d - y.d; });
      out.push({ e: e, sim: Math.max(0, Math.round(100 - dist)), keys: diffs.slice(0, 3).map(function (x) { return x.l; }) });
    });
    out.sort(function (a, b) { return b.sim - a.sim; });
    return out.slice(0, opts.limit || 5);
  }
  function f1(v) { return v == null ? "—" : Number(v).toFixed(1); }
  function table(rows) {
    if (!rows.length) return '<div class="pba-sim-empty">No comparable profiles with these filters.</div>';
    return '<div class="pba-sim-wrap"><table class="pba-sim-table"><thead><tr><th>Player</th><th>Team · League</th><th>Pos</th><th>Age</th><th>Ht</th><th>PPG</th><th>Similarity</th><th>Closest on</th></tr></thead><tbody>' +
      rows.map(function (r) {
        var e = r.e, name = e.hub ? '<a hr' + 'ef="' + esc(e.hub) + '">' + esc(e.n) + '</a>' : esc(e.n);
        var cls = r.sim >= 85 ? "hi" : (r.sim >= 75 ? "md" : "lo");
        return "<tr><td>" + name + (e.cur ? ' <span class="pba-sim-cur">current</span>' : "") + "</td><td>" + esc(e.tn || e.t) + ' · ' + esc(e.ln) + " " + esc(e.sl) + "</td><td>" + esc(e.pos || "—") +
          "</td><td>" + (e.age == null ? "—" : e.age) + "</td><td>" + (e.ht ? (e.ht / 100).toFixed(2) + " m" : "—") + "</td><td>" + f1((e.v || {}).ppg) +
          '</td><td><span class="pba-sim-score ' + cls + '">' + r.sim + "%</span></td><td>" + esc(r.keys.join(", ")) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }
  function css() {
    if (document.getElementById("pba-sim-css")) return;
    var st = document.createElement("style"); st.id = "pba-sim-css";
    st.textContent = ".pba-sim-bar{display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin:4px 0 12px;font-size:13px;color:#475569}" +
      ".pba-sim-bar label{display:inline-flex;gap:6px;align-items:center;cursor:pointer}.pba-sim-note{font-size:12px;color:#6b7280;margin:0 0 10px}" +
      ".pba-sim-wrap{overflow-x:auto}.pba-sim-table{width:100%;border-collapse:collapse;font-size:13px}" +
      ".pba-sim-table th,.pba-sim-table td{padding:8px 10px;border-bottom:1px solid #e5e7eb;text-align:left;white-space:nowrap}" +
      ".pba-sim-table th{background:#f3f4f6;font-size:12px;color:#374151}.pba-sim-table a{color:#2563eb;font-weight:700;text-decoration:none}" +
      ".pba-sim-score{display:inline-block;border-radius:999px;padding:2px 8px;font-weight:800;font-size:12px}" +
      ".pba-sim-score.hi{background:#dcfce7;color:#166534}.pba-sim-score.md{background:#fef9c3;color:#854d0e}.pba-sim-score.lo{background:#f3f4f6;color:#374151}" +
      ".pba-sim-cur{font-size:10px;font-weight:800;color:#166534;background:#dcfce7;border-radius:999px;padding:1px 6px}" +
      ".pba-sim-empty{color:#6b7280;font-style:italic;padding:6px 0}";
    document.head.appendChild(st);
  }
  function controls(id) {
    return '<div class="pba-sim-bar"><label><input type="checkbox" id="' + id + '-pos"> Same position only</label>' +
      '<label><input type="checkbox" id="' + id + '-cur"> Current season only</label></div>';
  }
  function bind(root, id, data, target, limit) {
    function draw() {
      var o = { samePos: root.querySelector("#" + id + "-pos").checked, current: root.querySelector("#" + id + "-cur").checked, limit: limit };
      root.querySelector(".pba-sim-out").innerHTML = table(rank(data, target, o));
    }
    root.querySelector("#" + id + "-pos").addEventListener("change", draw);
    root.querySelector("#" + id + "-cur").addEventListener("change", draw);
    draw();
  }
  function autoRender() {
    var box = document.getElementById("pba-similar");
    if (!box) return;
    css();
    var body = box.querySelector(".pba-sim-body");
    var here = norm(window.location.pathname);
    load().then(function (data) {
      if (!data.length) { body.innerHTML = '<div class="pba-sim-empty">' + (signedIn ? "No comparison data available for the leagues in your plan." : "Sign in to see similar players.") + "</div>"; return; }
      var target = data.filter(function (e) { return e.hub && norm(e.hub) === here; })[0];
      if (!target) { body.innerHTML = '<div class="pba-sim-empty">No profile found for this player.</div>'; return; }
      if (!target.q) { body.innerHTML = '<div class="pba-sim-empty">Not enough minutes yet for a reliable profile (needs about 10 MPG and 5 games).</div>'; return; }
      body.innerHTML = '<p class="pba-sim-note">Closest profiles across every league and season in your plan, compared on league percentiles (scoring, efficiency, usage, playmaking, ball security, shooting, rebounding, defense and on/off impact). Percentiles make players from different leagues comparable.</p>' +
        controls("pba-sim") + '<div class="pba-sim-out"></div>';
      bind(body, "pba-sim", data, target, 5);
    });
  }
  window.PBASimilar = { load: load, rank: rank, table: table, css: css, controls: controls, bind: bind };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", autoRender); else autoRender();
})();
