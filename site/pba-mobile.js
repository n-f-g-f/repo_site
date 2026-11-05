(function () {
  var mq = window.matchMedia("screen and (max-width: 820px)");
  function scrollableAncestor(el) {
    var p = el.parentElement;
    while (p && p !== document.body) {
      var ox = window.getComputedStyle(p).overflowX;
      if (ox === "auto" || ox === "scroll") return p;
      p = p.parentElement;
    }
    return null;
  }
  function wrap(el) {
    if (!el.parentNode || el.closest(".pba-mscroll") || scrollableAncestor(el)) return;
    var w = document.createElement("div");
    w.className = "pba-mscroll";
    el.parentNode.insertBefore(w, el);
    w.appendChild(el);
  }
  function hint(w) {
    if (w.__pbaHint || !w.parentNode) return;
    if (w.scrollWidth > w.clientWidth + 8) {
      var h = document.createElement("div");
      h.className = "pba-mscroll-hint";
      h.textContent = "Swipe sideways to see all columns \u2192";
      w.parentNode.insertBefore(h, w);
      w.__pbaHint = h;
    }
  }
  function fix() {
    if (!mq.matches) return;
    document.querySelectorAll("table").forEach(function (t) {
      if (!t.closest(".pba-context-header, .pba-site-chrome-header")) wrap(t);
    });
    document.querySelectorAll("svg[viewBox]").forEach(function (s) {
      var vb = (s.getAttribute("viewBox") || "").split(/[\s,]+/);
      var w = parseFloat(vb[2]);
      if (!(w >= 600) || s.closest(".pba-context-header")) return;
      s.style.minWidth = "560px";
      s.style.width = "100%";
      s.style.height = "auto";
      wrap(s);
    });
    document.querySelectorAll(".pba-mscroll").forEach(hint);
  }
  // Tap support for glossary tooltips on touch screens
  var lastTip = null;
  document.addEventListener("click", function (ev) {
    var g = ev.target && ev.target.closest ? ev.target.closest(".pba-gl") : null;
    if (lastTip && lastTip !== g) { lastTip.dispatchEvent(new MouseEvent("mouseleave")); lastTip = null; }
    if (g && window.matchMedia("(hover: none)").matches) {
      g.dispatchEvent(new MouseEvent("mouseenter", { clientX: ev.clientX, clientY: ev.clientY }));
      lastTip = g;
    }
  }, true);
  function start() {
    fix();
    var pending = null;
    new MutationObserver(function () {
      if (pending) return;
      pending = setTimeout(function () { pending = null; fix(); }, 200);
    }).observe(document.body, { childList: true, subtree: true });
    if (mq.addEventListener) mq.addEventListener("change", fix);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
