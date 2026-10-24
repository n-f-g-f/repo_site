
(function () {
  var G = [{"term": "G", "name": "Games played", "def": "Number of games in which the player or team appeared.", "formula": "", "note": "", "aliases": ["Games"]}, {"term": "MPG", "name": "Minutes per game", "def": "Average minutes played per game.", "formula": "", "note": "", "aliases": ["Min/G", "Minutes"]}, {"term": "PPG", "name": "Points per game", "def": "Average points scored per game.", "formula": "", "note": "", "aliases": ["Pts/G", "Points"]}, {"term": "RPG", "name": "Rebounds per game", "def": "Average total rebounds (offensive + defensive) per game.", "formula": "", "note": "", "aliases": ["Reb/G"]}, {"term": "APG", "name": "Assists per game", "def": "Average assists per game.", "formula": "", "note": "", "aliases": ["Ast/G"]}, {"term": "SPG", "name": "Steals per game", "def": "Average steals per game.", "formula": "", "note": "", "aliases": ["Stl/G"]}, {"term": "BPG", "name": "Blocks per game", "def": "Average blocked shots per game.", "formula": "", "note": "", "aliases": ["Blk/G"]}, {"term": "+/-", "name": "Plus/minus per game", "def": "Average point differential of the team while the player was on the floor.", "formula": "", "note": "Raw and noisy: depends heavily on teammates and opponents.", "aliases": ["+/-/G", "Plus/Minus Per Game"]}, {"term": "AST/TO", "name": "Assist to turnover ratio", "def": "Assists divided by turnovers.", "formula": "", "note": "Above 2.0 is a strong ball-security profile for a playmaker.", "aliases": ["Assist / Turnover Ratio"]}, {"term": "Per 40", "name": "Per 40 minutes", "def": "A counting stat scaled to 40 minutes of play (a full FIBA game), to compare players with different minutes.", "formula": "Stat × 40 ÷ minutes", "note": "", "aliases": ["Pts/40", "Reb/40", "Ast/40", "Stl/40", "Blk/40"]}, {"term": "FG%", "name": "Field goal percentage", "def": "Made field goals divided by attempted field goals (twos and threes).", "formula": "", "note": "", "aliases": ["Field Goal %"]}, {"term": "2PT%", "name": "Two-point percentage", "def": "Made two-point shots divided by two-point attempts.", "formula": "", "note": "", "aliases": ["2P%"]}, {"term": "3P%", "name": "Three-point percentage", "def": "Made three-point shots divided by three-point attempts.", "formula": "", "note": "", "aliases": ["3PT%", "3-Point %"]}, {"term": "FT%", "name": "Free throw percentage", "def": "Made free throws divided by free throw attempts.", "formula": "", "note": "", "aliases": ["Free Throw %"]}, {"term": "eFG%", "name": "Effective field goal percentage", "def": "Field goal percentage adjusted for the extra value of three-pointers.", "formula": "(FGM + 0.5 × 3PM) ÷ FGA", "note": "", "aliases": ["Effective FG %"]}, {"term": "TS%", "name": "True shooting percentage", "def": "Overall scoring efficiency, including twos, threes and free throws.", "formula": "Points ÷ (2 × (FGA + 0.44 × FTA))", "note": "The best single number for scoring efficiency.", "aliases": ["True Shooting %"]}, {"term": "3PA Rate", "name": "Three-point attempt rate", "def": "Share of field goal attempts taken from three.", "formula": "3PA ÷ FGA", "note": "A style metric: describes shot diet, not quality.", "aliases": ["3PA rate"]}, {"term": "FT Rate", "name": "Free throw rate", "def": "How often a player or team gets to the free throw line relative to shot attempts.", "formula": "FTA ÷ FGA", "note": "", "aliases": ["FTr", "Free Throw Rate"]}, {"term": "Pts/Shot", "name": "Points per shot", "def": "Points produced per field goal attempt.", "formula": "Points ÷ FGA", "note": "", "aliases": ["Pts/FGA", "Points Per Shot"]}, {"term": "3PM/G", "name": "Three-pointers made per game", "def": "Average made three-point shots per game.", "formula": "", "note": "", "aliases": ["3-Pointers Made Per Game"]}, {"term": "Shot Att", "name": "Shot attempts", "def": "Total field goal attempts with shot location data.", "formula": "", "note": "", "aliases": []}, {"term": "USG%", "name": "Usage rate", "def": "Share of team possessions used by the player while on the floor (shots, free throws and turnovers).", "formula": "", "note": "A role metric: high usage is not good or bad by itself.", "aliases": ["Usage %"]}, {"term": "AST%", "name": "Assist percentage", "def": "Share of teammate field goals the player assisted while on the floor.", "formula": "", "note": "", "aliases": ["Assist %"]}, {"term": "TOV%", "name": "Turnover percentage", "def": "Turnovers per 100 possessions used.", "formula": "TOV ÷ (FGA + 0.44 × FTA + TOV)", "note": "Lower is better.", "aliases": ["Turnover %"]}, {"term": "ORtg", "name": "Offensive rating", "def": "Points produced by the player per 100 individual possessions (Dean Oliver method).", "formula": "", "note": "Higher is better. Around 100–115 is typical.", "aliases": ["Offensive Rating"]}, {"term": "DRtg", "name": "Defensive rating", "def": "Estimated points allowed per 100 possessions while the player is on the floor (Dean Oliver method).", "formula": "", "note": "Lower is better. Heavily influenced by team defense.", "aliases": ["Defensive Rating"]}, {"term": "NetRtg", "name": "Net rating", "def": "Offensive rating minus defensive rating.", "formula": "ORtg − DRtg", "note": "", "aliases": ["Net Rating"]}, {"term": "P (percentile)", "name": "League percentile", "def": "Share of qualified players of the same league and season that the player outperforms (P85 = better than 85%).", "formula": "", "note": "For lower-is-better metrics (DRtg, TOV%) it is inverted, so a higher P is always better.", "aliases": []}, {"term": "ORB%", "name": "Offensive rebound percentage", "def": "Share of available offensive rebounds grabbed while on the floor.", "formula": "", "note": "", "aliases": ["Offensive Rebound %"]}, {"term": "DRB%", "name": "Defensive rebound percentage", "def": "Share of available defensive rebounds grabbed while on the floor.", "formula": "", "note": "", "aliases": ["Defensive Rebound %"]}, {"term": "TRB%", "name": "Total rebound percentage", "def": "Share of all available rebounds grabbed while on the floor.", "formula": "", "note": "", "aliases": ["Total Rebound %"]}, {"term": "STL%", "name": "Steal percentage", "def": "Share of opponent possessions that end in a steal by the player while on the floor.", "formula": "", "note": "", "aliases": ["Steal %"]}, {"term": "BLK%", "name": "Block percentage", "def": "Share of opponent two-point attempts blocked by the player while on the floor.", "formula": "", "note": "", "aliases": ["Block %"]}, {"term": "On Court %", "name": "On-court percentage", "def": "Share of team minutes the player spent on the floor.", "formula": "", "note": "", "aliases": ["On Court%"]}, {"term": "Min On", "name": "Minutes on", "def": "Total minutes the player was on the floor.", "formula": "", "note": "", "aliases": []}, {"term": "Min Off", "name": "Minutes off", "def": "Total team minutes with the player on the bench.", "formula": "", "note": "", "aliases": []}, {"term": "Net On/40", "name": "Net points on, per 40", "def": "Team point differential per 40 minutes with the player on the floor.", "formula": "", "note": "", "aliases": []}, {"term": "Net Off/40", "name": "Net points off, per 40", "def": "Team point differential per 40 minutes with the player on the bench.", "formula": "", "note": "", "aliases": []}, {"term": "On-Off/40", "name": "On-off net differential", "def": "How much better (or worse) the team's net result is per 40 minutes with the player on the floor than off it.", "formula": "Net On/40 − Net Off/40", "note": "Context-dependent: needs a decent minutes sample to be meaningful.", "aliases": ["On-Off Net/40", "On-Off Net / 40", "On-Off"]}, {"term": "WOWY", "name": "With or without you", "def": "Compares team results in four states for two players: both on, only A, only B, both off.", "formula": "", "note": "", "aliases": ["Duo WOWY"]}, {"term": "OffRtg", "name": "Team offensive rating", "def": "Points scored per 100 possessions.", "formula": "", "note": "", "aliases": ["Off Rtg", "OFF RTG"]}, {"term": "DefRtg", "name": "Team defensive rating", "def": "Points allowed per 100 possessions.", "formula": "", "note": "Lower is better.", "aliases": ["Def Rtg", "DEF RTG"]}, {"term": "Pace", "name": "Pace", "def": "Estimated possessions per 40 minutes. Higher means a faster game.", "formula": "", "note": "", "aliases": []}, {"term": "Poss", "name": "Possessions", "def": "Estimated possessions.", "formula": "FGA − ORB + TOV + 0.44 × FTA", "note": "", "aliases": ["Possessions"]}, {"term": "Opp eFG%", "name": "Opponent effective FG%", "def": "Effective field goal percentage allowed to opponents.", "formula": "", "note": "Lower is better.", "aliases": []}, {"term": "Four factors", "name": "Dean Oliver's four factors", "def": "The four team keys to winning: shooting (eFG%), turnovers (TOV%), offensive rebounding (ORB%) and free throws (FT Rate).", "formula": "", "note": "", "aliases": []}, {"term": "Lineup", "name": "Lineup (five-man unit)", "def": "A group of five players on the floor together; ratings are per 100 possessions of that unit.", "formula": "", "note": "Small minute samples are unreliable; use the Min Minutes filter.", "aliases": []}];
  var MAP = {};
  function key(s) { return String(s || "").replace(/[\u2195\u2191\u2193]/g, "").replace(/\s+/g, "").toUpperCase(); }
  G.forEach(function (e) {
    [e.term].concat(e.aliases || []).forEach(function (a) { var k = key(a); if (k && !MAP[k]) MAP[k] = e; });
  });
  var SEL = "th, .metric-label, .stat-label, .snapshot-label, .stat-lbl, .snap-lbl, .insight-lbl, .card-title, label";
  var tip = null;
  function ensureTip() {
    if (tip) return tip;
    var css = document.createElement("style");
    css.textContent = ".pba-gl{text-decoration:underline dotted rgba(100,116,139,.8);text-underline-offset:3px;cursor:help}" +
      ".pba-gl-tip{position:fixed;z-index:9999;max-width:320px;background:#0f172a;color:#e2e8f0;border-radius:10px;padding:10px 12px;font:12px/1.5 Arial,Helvetica,sans-serif;box-shadow:0 10px 24px rgba(0,0,0,.3);pointer-events:none;display:none}" +
      ".pba-gl-tip b{color:#fff;font-size:13px}.pba-gl-tip .f{margin-top:4px;color:#93c5fd;font-family:Consolas,monospace}.pba-gl-tip .n{margin-top:4px;color:#fde68a}";
    document.head.appendChild(css);
    tip = document.createElement("div");
    tip.className = "pba-gl-tip";
    document.body.appendChild(tip);
    return tip;
  }
  function esc(s) { return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  function show(ev) {
    var e = MAP[ev.currentTarget.getAttribute("data-pba-gl")];
    if (!e) return;
    var t = ensureTip();
    t.innerHTML = "<b>" + esc(e.term) + "</b> — " + esc(e.name) + "<div>" + esc(e.def) + "</div>" +
      (e.formula ? '<div class="f">' + esc(e.formula) + "</div>" : "") + (e.note ? '<div class="n">' + esc(e.note) + "</div>" : "");
    t.style.display = "block";
    move(ev);
  }
  function move(ev) {
    if (!tip || tip.style.display !== "block") return;
    var x = ev.clientX + 14, y = ev.clientY + 16;
    var w = tip.offsetWidth, h = tip.offsetHeight;
    if (x + w > window.innerWidth - 8) x = window.innerWidth - w - 8;
    if (y + h > window.innerHeight - 8) y = ev.clientY - h - 12;
    tip.style.left = x + "px"; tip.style.top = y + "px";
  }
  function hide() { if (tip) tip.style.display = "none"; }
  function scan(root) {
    var nodes = (root || document).querySelectorAll(SEL);
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.hasAttribute("data-pba-gl") || el.closest(".pba-context-header, .pba-site-chrome-header, .pba-gl-tip")) continue;
      if (el.children.length > 1) continue;
      var k = key(el.textContent);
      if (!k || k.length > 22 || !MAP[k]) continue;
      el.setAttribute("data-pba-gl", k);
      el.classList.add("pba-gl");
      el.addEventListener("mouseenter", show);
      el.addEventListener("mousemove", move);
      el.addEventListener("mouseleave", hide);
    }
  }
  function start() {
    ensureTip();
    scan(document);
    var pending = null;
    new MutationObserver(function () {
      if (pending) return;
      pending = setTimeout(function () { pending = null; scan(document); }, 150);
    }).observe(document.body, { childList: true, subtree: true });
    window.addEventListener("scroll", hide, true);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
