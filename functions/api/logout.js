import { clearSessionCookie, getCookie, json } from "./_auth.js";

async function destroySession(env, request) {
  const token = getCookie(request, "pba_session");
  if (token) {
    await env.AUTH_DB.prepare("DELETE FROM sessions WHERE session_token = ?").bind(token).run();
  }
}

export async function onRequestPost(context) {
  await destroySession(context.env, context.request);
  return json(
    { ok: true },
    200,
    { "set-cookie": clearSessionCookie() },
  );
}

export async function onRequestGet(context) {
  await destroySession(context.env, context.request);
  return Response.redirect(new URL("/login.html", context.request.url).toString(), 302);
}