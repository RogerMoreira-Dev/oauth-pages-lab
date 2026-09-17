import { sha256Hex, randomToken } from "../../_shared/crypto.js";
import { parseCookies, clearTxCookie, setSessionCookie } from "../../_shared/cookies.js";
import { getProviderConfig } from "../../_shared/providers.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error || !code || !state) {
    return new Response("Bad request", { status: 400 });
  }

  const cookies = parseCookies(request);
  const txCookie = cookies["__Host-oauth-tx"];
  if (!txCookie) {
    return new Response("Bad request", { status: 400 });
  }

  const txHash = await sha256Hex(txCookie);
  const stateHash = await sha256Hex(state);

  const row = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ?`
  ).bind(txHash, provider).first();

  const now = Math.floor(Date.now() / 1000);

  if (!row || row.expires_at < now || row.state_hash !== stateHash) {
    return new Response("Bad request", { status: 400 });
  }

  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(txHash).run();

  const config = getProviderConfig(provider, env);
  const baseUrl = env.PUBLIC_BASE_URL;
  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;

  const tokenBody = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: row.code_verifier,
  });

  const tokenRes = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept": "application/json",
    },
    body: tokenBody.toString(),
  });

  if (!tokenRes.ok) {
    return new Response("Bad gateway", { status: 502 });
  }

  const tokenData = await tokenRes.json();

  let issuer, subject, email, displayName;

  if (provider === "google") {
    const idToken = tokenData.id_token;
    if (!idToken) return new Response("Bad gateway", { status: 502 });

    let payload;
    try {
      payload = await verifyGoogleIdToken(
        idToken,
        config.clientId,
        row.nonce,
        config.discoveryUrl
      );
    } catch (e) {
      return new Response("Bad request", { status: 400 });
    }

    issuer = payload.iss;
    subject = payload.sub;
    email = payload.email || null;
    displayName = payload.name || null;
  } else {
    const accessToken = tokenData.access_token;
    const tokenType = tokenData.token_type;
    if (!accessToken || !/^bearer$/i.test(tokenType || "")) {
      return new Response("Bad gateway", { status: 502 });
    }

    const userRes = await fetch("https://api.github.com/user", {
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "oauth-pages-lab",
      },
    });

    if (userRes.status !== 200) {
      return new Response("Bad gateway", { status: 502 });
    }

    const userData = await userRes.json();
    if (!userData.id) {
      return new Response("Bad gateway", { status: 502 });
    }

    issuer = "https://github.com";
    subject = String(userData.id);
    email = userData.email || null;
    displayName = userData.name || userData.login || null;

    const revokeAuth = btoa(`${config.clientId}:${config.clientSecret}`);
    const revokeRes = await fetch(
      `https://api.github.com/applications/${config.clientId}/grant`,
      {
        method: "DELETE",
        headers: {
          "Authorization": `Basic ${revokeAuth}`,
          "Accept": "application/vnd.github+json",
          "X-GitHub-Api-Version": "2026-03-10",
          "Content-Type": "application/json",
          "User-Agent": "oauth-pages-lab",
        },
        body: JSON.stringify({ access_token: accessToken }),
      }
    );

    if (revokeRes.status !== 204) {
      return new Response("Bad gateway", { status: 502 });
    }
  }

  const sessionValue = randomToken();
  const sessionHash = await sha256Hex(sessionValue);
  const sessionExpiresAt = now + 28800;

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(sessionHash, issuer, subject, email, displayName, sessionExpiresAt, now).run();

    const headers = new Headers();
  headers.set("Location", baseUrl);
  headers.append("Set-Cookie", setSessionCookie(sessionValue));
  headers.append("Set-Cookie", clearTxCookie());
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
