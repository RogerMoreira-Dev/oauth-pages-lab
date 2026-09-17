
export function getProviderConfig(provider, env) {
  if (provider === "google") {
    return {
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      authEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      tokenEndpoint: "https://oauth2.googleapis.com/token",
      issuer: "https://accounts.google.com",
      discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
      scope: "openid email profile",
    };
  }
  if (provider === "github") {
    return {
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      authEndpoint: "https://github.com/login/oauth/authorize",
      tokenEndpoint: "https://github.com/login/oauth/access_token",
      issuer: "https://github.com",
    };
  }
  return null;
}
