
export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  header.split(";").forEach(pair => {
    const idx = pair.indexOf("=");
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    cookies[key] = value;
  });
  return cookies;
}

export function setTxCookie(value) {
  return `__Host-oauth-tx=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

export function clearTxCookie() {
  return `__Host-oauth-tx=deleted; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function setSessionCookie(value) {
  return `__Host-session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

export function clearSessionCookie() {
  return `__Host-session=deleted; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
