
import { randomToken, sha256Hex, sha256Base64url } from "../../_shared/crypto.js";
import { setTxCookie } from "../../_shared/cookies.js";
import { getProviderConfig } from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const { env, params } = context;
  const provider = params.provider;

  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  const config = getProviderConfig(provider, env);
  const baseUrl = env.PUBLIC_BASE_URL;
