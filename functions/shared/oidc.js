
async function getJwks(discoveryUrl) {
  const discoveryRes = await fetch(discoveryUrl);
  const discovery = await discoveryRes.json();
  const jwksRes = await fetch(discovery.jwks_uri);
  const jwks = await jwksRes.json();
  return { jwks, issuer: discovery.issuer };
}

function base64urlToUint8Array(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const raw = atob(b64 + pad);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

function decodeJwtPart(part) {
  const bytes = base64urlToUint8Array(part);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text);
}

export async function verifyGoogleIdToken(idToken, expectedAud, expectedNonce, discoveryUrl) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt_format");

  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);

  if (header.alg !== "RS256") throw new Error("invalid_alg");

  const { jwks, issuer } = await getJwks(discoveryUrl);
  const jwk = jwks.keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error("key_not_found");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const signature = base64urlToUint8Array(parts[2]);

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature,
    signedData
  );
  if (!valid) throw new Error("invalid_signature");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer) throw new Error("invalid_issuer");
  if (payload.aud !== expectedAud) throw new Error("invalid_audience");
  if (payload.exp < now) throw new Error("token_expired");
  if (payload.iat > now + 60) throw new Error("invalid_iat");
  if (payload.nonce !== expectedNonce) throw new Error("invalid_nonce");

  return payload;
}
