
import { sha256Hex } from "../_shared/crypto.js";
import { parseCookies } from "../_shared/cookies.js";

export async function onRequestGet(context) {
  const { request, env } = context;
  const cookies = parseCookies(request);
  const sessionCookie = cookies["__Host-session"];

  if (!sessionCookie) {
    return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  const sessionHash = await sha256Hex(sessionCookie);
  const now = Math.floor(Date.now() / 1000);

  const row = await env.DB.prepare(
    `SELECT * FROM sessions WHERE id_hash = ? AND expires_at > ?`
  ).bind(sessionHash, now).first();

  if (!row) {
    return new Response("Unauthorized", { status: 401, headers: { "Cache-Control": "no-store" } });
  }

  return Response.json(
    {
      email: row.email,
      displayName: row.display_name,
      issuer: row.issuer,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
