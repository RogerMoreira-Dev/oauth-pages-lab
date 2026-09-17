
import { sha256Hex } from "../_shared/crypto.js";
import { parseCookies, clearSessionCookie } from "../_shared/cookies.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
  }

  const cookies = parseCookies(request);
  const sessionCookie = cookies["__Host-session"];

  if (sessionCookie) {
    const sessionHash = await sha256Hex(sessionCookie);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(sessionHash).run();
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Set-Cookie": clearSessionCookie(),
      "Cache-Control": "no-store",
    },
  });
}
