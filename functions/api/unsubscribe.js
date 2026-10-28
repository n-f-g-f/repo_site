// functions/api/unsubscribe.js — one-click unsubscribe from the weekly digest.
// GET  /api/unsubscribe?token=...  -> confirmation page
// POST /api/unsubscribe?token=...  -> RFC 8058 one-click (mail clients)
// Never reveals whether a token exists.
const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Unsubscribed · PBA</title><meta name="robots" content="noindex"></head>
<body style="margin:0;font-family:Arial,Helvetica,sans-serif;background:#f1f5f9;color:#0f172a">
<div style="max-width:520px;margin:60px auto;background:#fff;border-radius:16px;padding:28px">
<h1 style="margin:0 0 10px;font-size:22px">You have been unsubscribed</h1>
<p style="font-size:15px;line-height:1.6;color:#475569">You will no longer receive the PBA weekly digest. Your account and access are not affected.</p>
<p><a href="/" style="color:#1d4ed8;font-weight:700">Back to ptbballanalytics.com</a></p></div></body></html>`;

async function unsubscribe(request, env) {
  const token = new URL(request.url).searchParams.get("token") || "";
  if (/^[a-f0-9]{48}$/.test(token)) {
    try {
      await env.AUTH_DB.prepare("UPDATE users SET digest_opt_in = 0 WHERE digest_token = ?").bind(token).run();
    } catch (e) {
      console.log(JSON.stringify({ event: "digest_unsubscribe_error", message: String(e && e.message || e) }));
    }
  }
}

export async function onRequestGet({ request, env }) {
  await unsubscribe(request, env);
  return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

export async function onRequestPost({ request, env }) {
  await unsubscribe(request, env);
  return new Response("OK", { headers: { "cache-control": "no-store" } });
}
