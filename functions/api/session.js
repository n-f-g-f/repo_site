import { clearSessionCookie, getSessionBundle, json } from "./_auth.js";

export async function onRequestGet(context) {
  const bundle = await getSessionBundle(context.env, context.request);
  if (!bundle) {
    return json(
      {
        ok: false,
        authenticated: false,
      },
      401,
      { "set-cookie": clearSessionCookie() },
    );
  }

  return json({
    ok: true,
    authenticated: true,
    user: bundle.user,
    access: bundle.access,
  });
}