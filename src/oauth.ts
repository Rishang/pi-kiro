// Kiro OAuth — AWS Builder ID and IAM Identity Center (IdC).
//
// Two login methods, selected interactively:
//
//   1. Builder ID — AWS's personal-account SSO. Fixed start URL
//      (https://view.awsapps.com/start), always us-east-1.
//   2. IdC — enterprise SSO. User supplies their company start URL
//      (e.g. https://mycompany.awsapps.com/start); region is auto-detected
//      across common AWS regions, or the user can specify it.
//
// Both methods use the same AWS SSO-OIDC device-code flow and the same
// refresh endpoint. Social login (Google/GitHub) is not supported — it
// requires kiro-cli, which we intentionally don't depend on.
//
// NOTE on mirrored-cursor rendering glitch:
// pi's login-dialog (modes/interactive/components/login-dialog.ts) appends
// `this.input` to `contentContainer` on every `showPrompt` call without
// clearing the container first. The second `onPrompt` call therefore shows
// two visible Input widgets bound to the same buffer — typing in one updates
// both. Our user's input is still captured correctly (both widgets share
// `this.input`). The glitch is cosmetic, upstream, and out of scope for this
// extension to fix. Report upstream: add `this.contentContainer.clear()` at
// the top of `showPrompt`, or allocate a new Input per call.

import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import { log } from "./debug";
import { isPermanentError } from "./health";
import {
  fetchAvailableModels,
  buildModelsFromApi,
  resolveApiRegion,
  setCachedDynamicModels,
  resolveProfileArn,
} from "./models";
import type { KiroCliCredentials, KiroCredentialSource } from "./kiro-cli-sync";
import { createServer, type Server } from "node:http";
import { randomBytes, createHash } from "node:crypto";

export const BUILDER_ID_START_URL = "https://view.awsapps.com/start";
export const BUILDER_ID_REGION = "us-east-1";
export const SSO_SCOPES = [
  "codewhisperer:completions",
  "codewhisperer:analysis",
  "codewhisperer:conversations",
  "codewhisperer:transformations",
  "codewhisperer:taskassist",
];

/** Regions probed when an IdC user leaves the region blank. */
const IDC_PROBE_REGIONS = [
  "us-east-1",
  "eu-west-1",
  "eu-central-1",
  "us-east-2",
  "eu-west-2",
  "eu-west-3",
  "eu-north-1",
  "ap-southeast-1",
  "ap-northeast-1",
  "us-west-2",
];

/** 5-minute safety buffer subtracted from real token expiry. */
const EXPIRES_BUFFER_MS = 5 * 60 * 1000;

export interface KiroCredentials extends OAuthCredentials {
  clientId: string;
  /**
   * OIDC client secret from AWS SSO-OIDC client registration.
   *
   * SENSITIVE: persist only in secure storage (e.g. keychain, encrypted
   * file, HTTP-only cookie). Do not log, do not send to telemetry, do not
   * embed in URLs or query strings. Together with `refresh`, it can mint
   * new access tokens for the user's AWS identity.
   */
  clientSecret: string;
  region: string;
  /**
   * Which SSO flow produced this credential.
   * - `builder-id`: AWS Builder ID (personal AWS account, us-east-1).
   * - `idc`: IAM Identity Center (enterprise SSO, any region).
   * - `desktop`: Kiro IDE native install (bare refresh token, no clientId/clientSecret).
   */
  authMethod: "builder-id" | "idc" | "desktop" | "social";
  /** Profile ARN from Kiro, used to scope API calls. */
  profileArn?: string;
  /** Local Kiro source, used only to decide safe CLI DB write-back. */
  kiroSyncSource?: KiroCredentialSource;
  /** Exact `auth_kv.key` imported from the kiro-cli DB. */
  kiroSyncTokenKey?: string;
}

interface DeviceAuthResponse {
  verificationUri: string;
  verificationUriComplete: string;
  userCode: string;
  deviceCode: string;
  interval: number;
  expiresIn: number;
}

interface ClientRegisterResponse {
  clientId: string;
  clientSecret: string;
}

interface TokenResponse {
  error?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
}

/** Promise-based delay that rejects promptly if the signal fires. */
function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(signal.reason ?? new Error("Login cancelled"));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason ?? new Error("Login cancelled"));
      },
      { once: true },
    );
  });
}

async function tryRegisterAndAuthorize(
  startUrl: string,
  region: string,
): Promise<{
  clientId: string;
  clientSecret: string;
  oidcEndpoint: string;
  devAuth: DeviceAuthResponse;
} | null> {
  const oidcEndpoint = `https://oidc.${region}.amazonaws.com`;

  const regResp = await fetch(`${oidcEndpoint}/client/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "pi-kiro" },
    body: JSON.stringify({
      clientName: "pi-kiro",
      clientType: "public",
      scopes: SSO_SCOPES,
      grantTypes: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    }),
  });
  if (!regResp.ok) return null;
  const { clientId, clientSecret } = (await regResp.json()) as ClientRegisterResponse;

  const devResp = await fetch(`${oidcEndpoint}/device_authorization`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "pi-kiro" },
    body: JSON.stringify({ clientId, clientSecret, startUrl }),
  });
  if (!devResp.ok) return null;

  return {
    clientId,
    clientSecret,
    oidcEndpoint,
    devAuth: (await devResp.json()) as DeviceAuthResponse,
  };
}

async function pollForToken(
  oidcEndpoint: string,
  clientId: string,
  clientSecret: string,
  devAuth: DeviceAuthResponse,
  signal: AbortSignal | undefined,
): Promise<TokenResponse> {
  const deadline = Date.now() + (devAuth.expiresIn || 600) * 1000;
  const baseInterval = (devAuth.interval || 5) * 1000;
  let interval = baseInterval;

  while (Date.now() < deadline) {
    if (signal?.aborted) throw new Error("Login cancelled");
    await abortableDelay(interval, signal);

    // Any transient failure (network, 5xx, non-JSON body) is treated like
    // `authorization_pending` — we keep polling until the deadline. The OIDC
    // token endpoint occasionally returns HTML error pages under load; those
    // should not abort a still-valid device code.
    let resp: Response;
    try {
      resp = await fetch(`${oidcEndpoint}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "pi-kiro" },
        body: JSON.stringify({
          clientId,
          clientSecret,
          deviceCode: devAuth.deviceCode,
          grantType: "urn:ietf:params:oauth:grant-type:device_code",
        }),
      });
    } catch {
      continue;
    }

    // 5xx → transient, keep polling.
    if (resp.status >= 500) continue;

    let data: TokenResponse;
    try {
      data = (await resp.json()) as TokenResponse;
    } catch {
      // Non-JSON body (HTML error page, empty, etc.) — treat as transient
      // unless the status itself is a hard 4xx we can't interpret.
      if (!resp.ok) {
        throw new Error(`Authorization failed: HTTP ${resp.status}`);
      }
      continue;
    }

    if (!data.error && data.accessToken && data.refreshToken) return data;
    if (data.error === "authorization_pending") continue;
    if (data.error === "slow_down") {
      interval += baseInterval;
      continue;
    }
    if (data.error) throw new Error(`Authorization failed: ${data.error}`);
  }
  throw new Error("Authorization timed out");
}

// ── Social sign-in (PKCE + authorization code) ──────────────────────
//
// Used for Builder ID (personal AWS account). Matches the Kiro CLI flow:
// opens https://app.kiro.dev/signin with a PKCE challenge, listens on a
// localhost port for the OAuth redirect, then exchanges the authorization
// code for tokens via the desktop auth endpoint.
//
// Key advantage over the device-code flow: the token exchange returns
// profileArn immediately, eliminating the post-login resolution step.

const KIRO_SOCIAL_PORTAL = "https://app.kiro.dev";
const KIRO_SOCIAL_AUTH_ENDPOINT = `https://prod.${BUILDER_ID_REGION}.auth.desktop.kiro.dev`;
const SOCIAL_REDIRECT_PORT = 49153;
const SOCIAL_REDIRECT_URI = `http://localhost:${SOCIAL_REDIRECT_PORT}`;

function generateRandomState(): string {
  return randomBytes(16).toString("base64url");
}

function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

function generateCodeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function buildSocialSignInURL(
  redirectUri: string,
  codeChallenge: string,
  state: string,
): string {
  const params = new URLSearchParams();
  params.set("code_challenge", codeChallenge);
  params.set("code_challenge_method", "S256");
  params.set("redirect_from", "kirocli");
  params.set("redirect_uri", redirectUri);
  params.set("state", state);
  return `${KIRO_SOCIAL_PORTAL}/signin?${params.toString()}`;
}

function parseAuthRedirectInput(input: string): { code?: string; state?: string } {
  const trimmed = input.trim();
  if (!trimmed) return {};
  try {
    const url = new URL(trimmed);
    return {
      code: url.searchParams.get("code") ?? undefined,
      state: url.searchParams.get("state") ?? undefined,
    };
  } catch {
    // Not a URL — treat as a raw authorization code.
    return { code: trimmed };
  }
}

/**
 * Reconstruct the redirect_uri for the token exchange.
 * Kiro redirects the browser to {baseURI}/oauth/callback?login_option=...
 * and the token endpoint expects this exact URI back.
 * Matches sub2api's BuildSocialTokenRedirectURI.
 */
function buildTokenRedirectUri(callbackPath: string, loginOption: string | null): string {
  const path = callbackPath || "/oauth/callback";
  const base = `${SOCIAL_REDIRECT_URI}${path}`;
  if (loginOption) {
    return `${base}?login_option=${encodeURIComponent(loginOption)}`;
  }
  return base;
}

/**
 * Render a styled OAuth callback page (success or error).
 * Dark theme with the Kiro ghost logo and PI-KIRO branding.
 * Success pages show a 3→2→1 countdown then redirect to app.kiro.dev.
 */
function oauthCallbackPage(
  kind: "success" | "error",
  title: string,
  message: string,
  redirectUrl = "https://app.kiro.dev",
): string {
  const borderColor = kind === "success" ? "#22c55e" : "#ef4444";
  const iconSvg =
    kind === "success"
      ? `<svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M16.67 5L7.5 14.17 3.33 10" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
      : `<svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M15 5L5 15M5 5l10 10" stroke="#ef4444" stroke-width="2" stroke-linecap="round"/></svg>`;

  // Kiro ghost SVG (simplified, white fill)
  const ghostSvg = `<svg width="56" height="56" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M50 5C28.5 5 11 22.5 11 44v36c0 2.8 1.2 5.4 3.2 7.2 2 1.8 4.7 2.6 7.4 2.2l3.4-.5c3.2-.5 6.5.4 9 2.5l2.2 1.8c2.4 2 5.4 3 8.5 3h10.6c3.1 0 6.1-1.1 8.5-3l2.2-1.8c2.5-2.1 5.8-3 9-2.5l3.4.5c2.7.4 5.4-.4 7.4-2.2 2-1.8 3.2-4.4 3.2-7.2V44C89 22.5 71.5 5 50 5z" fill="white"/>
    <circle cx="37" cy="45" r="7" fill="#0a0a0a"/>
    <circle cx="63" cy="45" r="7" fill="#0a0a0a"/>
  </svg>`;

  const redirectHost = (() => {
    try { return new URL(redirectUrl).hostname; } catch { return redirectUrl; }
  })();

  const countdownHtml =
    kind === "success"
      ? `
    <div class="countdown" id="countdown">
      <svg class="ring" viewBox="0 0 60 60">
        <circle cx="30" cy="30" r="26" stroke="#1a1a1a" stroke-width="3" fill="none"/>
        <circle id="ring-progress" cx="30" cy="30" r="26" stroke="#22c55e" stroke-width="3" fill="none"
          stroke-dasharray="163.36" stroke-dashoffset="0" stroke-linecap="round"
          transform="rotate(-90 30 30)" style="transition:stroke-dashoffset 1s linear"/>
      </svg>
      <span class="countdown-num" id="countdown-num">3</span>
    </div>
    <p class="subtitle">Redirecting to <strong>${redirectHost}</strong>…</p>
    <script>
      (function(){
        var n=3, el=document.getElementById('countdown-num'),
            ring=document.getElementById('ring-progress'), circ=163.36;
        function tick(){
          if(n<=0){window.location.href=${JSON.stringify(redirectUrl)};return}
          el.textContent=n;
          ring.setAttribute('stroke-dashoffset', String(circ*(1-n/3)));
          n--;
          setTimeout(tick,1000);
        }
        tick();
      })();
    </script>`
      : `<p class="subtitle">Please close this window and try again</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PI-KIRO — Authentication</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0a0a0a;color:#e5e5e5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
    .container{max-width:420px;padding:2rem}
    .logo{display:flex;align-items:center;justify-content:center;gap:16px;margin-bottom:48px}
    .logo-text{font-size:42px;font-weight:700;letter-spacing:6px;color:#7c3aed;font-family:'Courier New',monospace}
    .status-box{border:1.5px solid ${borderColor};border-radius:12px;padding:20px 28px;display:flex;align-items:flex-start;gap:14px;text-align:left;margin-bottom:20px;background:rgba(${kind === "success" ? "34,197,94" : "239,68,68"},0.04)}
    .status-icon{flex-shrink:0;margin-top:2px}
    .status-title{font-size:15px;font-weight:600;color:${borderColor};margin-bottom:4px}
    .status-msg{font-size:13px;color:#a3a3a3;line-height:1.4}
    .subtitle{font-size:13px;color:#737373;margin-top:4px}
    .subtitle strong{color:#a3a3a3}
    .countdown{position:relative;width:60px;height:60px;margin:24px auto 12px}
    .ring{width:60px;height:60px}
    .countdown-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#22c55e;font-variant-numeric:tabular-nums}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      ${ghostSvg}
      <span class="logo-text">PI-KIRO</span>
    </div>
    <div class="status-box">
      <span class="status-icon">${iconSvg}</span>
      <div>
        <div class="status-title">${title}</div>
        <div class="status-msg">${message}</div>
      </div>
    </div>
    ${countdownHtml}
  </div>
</body>
</html>`;
}

/**
 * Enterprise IdC delegation page: polls /idc-verify until the device
 * verification URL is ready, then does a 3→2→1 countdown and redirects.
 */
function oauthIdcDelegationPage(): string {
  const ghostSvg = `<svg width="56" height="56" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M50 5C28.5 5 11 22.5 11 44v36c0 2.8 1.2 5.4 3.2 7.2 2 1.8 4.7 2.6 7.4 2.2l3.4-.5c3.2-.5 6.5.4 9 2.5l2.2 1.8c2.4 2 5.4 3 8.5 3h10.6c3.1 0 6.1-1.1 8.5-3l2.2-1.8c2.5-2.1 5.8-3 9-2.5l3.4.5c2.7.4 5.4-.4 7.4-2.2 2-1.8 3.2-4.4 3.2-7.2V44C89 22.5 71.5 5 50 5z" fill="white"/>
    <circle cx="37" cy="45" r="7" fill="#0a0a0a"/>
    <circle cx="63" cy="45" r="7" fill="#0a0a0a"/>
  </svg>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PI-KIRO — Enterprise Sign-In</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0a0a0a;color:#e5e5e5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center}
    .container{max-width:420px;padding:2rem}
    .logo{display:flex;align-items:center;justify-content:center;gap:16px;margin-bottom:48px}
    .logo-text{font-size:42px;font-weight:700;letter-spacing:6px;color:#7c3aed;font-family:'Courier New',monospace}
    .status-box{border:1.5px solid #22c55e;border-radius:12px;padding:20px 28px;display:flex;align-items:flex-start;gap:14px;text-align:left;margin-bottom:20px;background:rgba(34,197,94,0.04)}
    .status-icon{flex-shrink:0;margin-top:2px}
    .status-title{font-size:15px;font-weight:600;color:#22c55e;margin-bottom:4px}
    .status-msg{font-size:13px;color:#a3a3a3;line-height:1.4}
    .subtitle{font-size:13px;color:#737373;margin-top:4px}
    .subtitle strong{color:#a3a3a3}
    .spinner{width:28px;height:28px;border:3px solid #1a1a1a;border-top-color:#22c55e;border-radius:50%;animation:spin 0.8s linear infinite;margin:24px auto 12px}
    @keyframes spin{to{transform:rotate(360deg)}}
    .countdown{position:relative;width:60px;height:60px;margin:24px auto 12px;display:none}
    .ring{width:60px;height:60px}
    .countdown-num{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#22c55e;font-variant-numeric:tabular-nums}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      ${ghostSvg}
      <span class="logo-text">PI-KIRO</span>
    </div>
    <div class="status-box">
      <span class="status-icon"><svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M16.67 5L7.5 14.17 3.33 10" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      <div>
        <div class="status-title">Enterprise sign-in</div>
        <div class="status-msg" id="status-msg">Preparing device authorization…</div>
      </div>
    </div>
    <div class="spinner" id="spinner"></div>
    <div class="countdown" id="countdown">
      <svg class="ring" viewBox="0 0 60 60">
        <circle cx="30" cy="30" r="26" stroke="#1a1a1a" stroke-width="3" fill="none"/>
        <circle id="ring-progress" cx="30" cy="30" r="26" stroke="#22c55e" stroke-width="3" fill="none"
          stroke-dasharray="163.36" stroke-dashoffset="0" stroke-linecap="round"
          transform="rotate(-90 30 30)" style="transition:stroke-dashoffset 1s linear"/>
      </svg>
      <span class="countdown-num" id="countdown-num">3</span>
    </div>
    <p class="subtitle" id="subtitle">Waiting for device authorization…</p>
    <script>
      (function(){
        var msg=document.getElementById('status-msg'),
            spinner=document.getElementById('spinner'),
            cd=document.getElementById('countdown'),
            cdNum=document.getElementById('countdown-num'),
            ring=document.getElementById('ring-progress'),
            sub=document.getElementById('subtitle'),
            circ=163.36;

        function poll(){
          fetch('/idc-verify').then(function(r){return r.json()}).then(function(d){
            if(d.url){
              spinner.style.display='none';
              cd.style.display='block';
              msg.textContent='Device authorization ready';
              try{sub.innerHTML='Redirecting to <strong>'+new URL(d.url).hostname+'</strong>…'}catch(e){}
              countdown(3,d.url);
            } else {
              setTimeout(poll,500);
            }
          }).catch(function(){setTimeout(poll,1000)});
        }

        function countdown(n,url){
          if(n<=0){window.location.href=url;return}
          cdNum.textContent=n;
          ring.setAttribute('stroke-dashoffset',String(circ*(1-n/3)));
          setTimeout(function(){countdown(n-1,url)},1000);
        }

        poll();
      })();
    </script>
  </div>
</body>
</html>`;
}

function startCallbackServer(
  expectedState: string,
): Promise<{
  server: Server;
  redirectUri: string;
  waitForCode: () => Promise<SocialCallbackResult | null>;
  cancelWait: () => void;
  setIdcVerifyUrl: (url: string) => void;
}> {
  return new Promise((resolve, reject) => {
    let settleWait: ((result: SocialCallbackResult | null) => void) | undefined;
    const waitForCodePromise = new Promise<SocialCallbackResult | null>((res) => {
      settleWait = res;
    });

    let idcVerifyUrl: string | null = null;

    const server = createServer((req, res) => {
      try {
        const url = new URL(req.url ?? "", SOCIAL_REDIRECT_URI);

        // /idc-verify endpoint: returns the device verification URL when ready.
        if (url.pathname === "/idc-verify") {
          res.writeHead(200, {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
          });
          res.end(JSON.stringify({ url: idcVerifyUrl }));
          return;
        }

        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const loginOption = url.searchParams.get("login_option");
        const issuerUrl = url.searchParams.get("issuer_url");
        const idcRegion = url.searchParams.get("idc_region");

        // IdC delegation: login_option=awsidc + issuer_url + state (no code)
        const isIdcDelegation = loginOption === "awsidc" && !!issuerUrl && !!state;

        if (!state || (!code && !isIdcDelegation)) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end("");
          return;
        }

        if (state !== expectedState) {
          res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
          res.end(oauthCallbackPage("error", "State mismatch", "The OAuth state parameter did not match. Please try logging in again."));
          return;
        }

        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        if (isIdcDelegation) {
          res.end(oauthIdcDelegationPage());
        } else {
          res.end(oauthCallbackPage("success", "Request approved", "PI-KIRO has been given requested permissions."));
        }
        settleWait?.({
          code,
          state,
          callbackPath: url.pathname,
          loginOption,
          issuerUrl: issuerUrl ?? undefined,
          idcRegion: idcRegion ?? undefined,
        });
      } catch {
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Internal error");
      }
    });

    server.on("error", (err) => {
      reject(err);
    });

    server.listen(SOCIAL_REDIRECT_PORT, "localhost", () => {
      resolve({
        server,
        redirectUri: SOCIAL_REDIRECT_URI,
        cancelWait: () => { settleWait?.(null); },
        waitForCode: () => waitForCodePromise,
        setIdcVerifyUrl: (url: string) => { idcVerifyUrl = url; },
      });
    });
  });
}

/** Result from the localhost callback server. */
interface SocialCallbackResult {
  /** Authorization code (null for IdC delegation). */
  code: string | null;
  state: string;
  callbackPath: string;
  loginOption: string | null;
  /** IdC delegation: the issuer/start URL from Kiro portal. */
  issuerUrl?: string;
  /** IdC delegation: the IdC region from Kiro portal. */
  idcRegion?: string;
}

interface SocialTokenResponse {
  accessToken: string;
  refreshToken: string;
  profileArn?: string;
  expiresIn?: number;
}

async function runSocialSignInFlow(
  callbacks: OAuthLoginCallbacks,
): Promise<KiroCredentials> {
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const state = generateRandomState();

  const callbackServer = await startCallbackServer(state);

  try {
    const signInUrl = buildSocialSignInURL(callbackServer.redirectUri, challenge, state);

    callbacks.onAuth({
      url: signInUrl,
      instructions: "Complete sign-in in your browser.",
    });

    callbacks.onProgress?.("Waiting for browser sign-in…");

    let code: string | undefined;
    let tokenRedirectUri = SOCIAL_REDIRECT_URI;

    // Race: localhost callback vs manual code input (if available).
    let callbackResult: SocialCallbackResult | null = null;

    if (callbacks.onManualCodeInput) {
      let manualInput: string | undefined;
      let manualError: Error | undefined;
      const manualPromise = callbacks
        .onManualCodeInput()
        .then((input) => {
          manualInput = input;
          callbackServer.cancelWait();
        })
        .catch((err) => {
          manualError = err instanceof Error ? err : new Error(String(err));
          callbackServer.cancelWait();
        });

      callbackResult = await callbackServer.waitForCode();

      if (manualError) throw manualError;

      // IdC delegation: skip manual-input fallback — no code expected.
      if (callbackResult?.loginOption !== "awsidc" || !callbackResult.issuerUrl) {
        if (callbackResult?.code) {
          code = callbackResult.code;
          tokenRedirectUri = buildTokenRedirectUri(callbackResult.callbackPath, callbackResult.loginOption);
        } else if (manualInput) {
          code = parseAuthRedirectInput(manualInput).code;
        }

        if (!code) {
          await manualPromise;
          if (manualError) throw manualError;
          if (manualInput) {
            code = parseAuthRedirectInput(manualInput).code;
          }
        }
      }
    } else {
      callbackResult = await callbackServer.waitForCode();
      if (callbackResult?.code) {
        code = callbackResult.code;
        tokenRedirectUri = buildTokenRedirectUri(callbackResult.callbackPath, callbackResult.loginOption);
      }
    }

    // IdC delegation: Kiro portal redirected with issuer_url + idc_region.
    // Keep the callback server alive so the browser can poll /idc-verify.
    // Wrap callbacks.onAuth to pipe the verification URL to the browser tab.
    if (callbackResult?.loginOption === "awsidc" && callbackResult.issuerUrl) {
      callbacks.onProgress?.("Enterprise sign-in detected — starting device authorization…");
      const idcRegion = callbackResult.idcRegion || BUILDER_ID_REGION;
      const wrappedCallbacks: OAuthLoginCallbacks = {
        ...callbacks,
        onAuth: (info) => {
          // Pipe the verification URL to the browser tab via /idc-verify
          callbackServer.setIdcVerifyUrl(info.url);
          // Log instructions to progress so the user has them in the terminal,
          // but do NOT call callbacks.onAuth to avoid opening a redundant browser tab.
          if (info.instructions) {
            callbacks.onProgress?.(info.instructions);
          }
        },
      };
      try {
        return await runDeviceCodeFlow(wrappedCallbacks, callbackResult.issuerUrl, [idcRegion], "idc");
      } finally {
        callbackServer.server.close();
      }
    }

    // Fallback: prompt the user to paste the redirect URL or code.
    if (!code) {
      const input = await callbacks.onPrompt({
        message: "Paste the authorization code or the full redirect URL:",
        placeholder: SOCIAL_REDIRECT_URI,
      });
      code = parseAuthRedirectInput(input).code;
    }

    if (!code) {
      throw new Error("Missing authorization code — sign-in was not completed");
    }

    callbacks.onProgress?.("Exchanging authorization code…");

    const resp = await fetch(`${KIRO_SOCIAL_AUTH_ENDPOINT}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "pi-kiro" },
      body: JSON.stringify({
        code,
        code_verifier: verifier,
        redirect_uri: tokenRedirectUri,
      }),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new Error(`Token exchange failed: ${resp.status} ${body}`);
    }

    const data = (await resp.json()) as SocialTokenResponse;

    if (!data.accessToken || !data.refreshToken) {
      throw new Error("Token exchange returned no tokens");
    }

    // Social flow returns profileArn — fetch and cache models immediately.
    if (data.profileArn) {
      try {
        const apiRegion = resolveApiRegion(BUILDER_ID_REGION);
        const apiModels = await fetchAvailableModels(data.accessToken, apiRegion, data.profileArn);
        setCachedDynamicModels(buildModelsFromApi(apiModels));
        log.info(`Fetched and cached ${apiModels.length} models after social sign-in`);
      } catch (err) {
        log.warn(`Failed to fetch models after social sign-in: ${err}`);
      }
    }

    return {
      refresh: `${data.refreshToken}|||social`,
      access: data.accessToken,
      expires: Date.now() + (data.expiresIn ?? 3600) * 1000 - EXPIRES_BUFFER_MS,
      clientId: "",
      clientSecret: "",
      region: BUILDER_ID_REGION,
      authMethod: "social",
      profileArn: data.profileArn,
    };
  } finally {
    callbackServer.server.close();
  }
}

/**
 * Interactive login. Asks the user to pick Builder ID, IdC, or Desktop,
 * then runs the appropriate flow.
 *
 * Uses `callbacks.onPrompt`, which is the path pi's login-dialog is wired
 * to. Escape/ctrl+c rejects the promise with "Login cancelled", propagating
 * out of this function automatically.
 */
export async function loginKiro(callbacks: OAuthLoginCallbacks): Promise<KiroCredentials> {
  const method = await callbacks.onSelect({
    message: "Select login method:",
    options: [
      { id: "builder-id", label: "AWS Builder ID (personal account)" },
      { id: "idc",        label: "IAM Identity Center (enterprise SSO)" },
      { id: "sync",       label: "Import from Kiro CLI/IDE (auto-sync local DB)" },
      { id: "desktop",    label: "Desktop refresh token (manual)" },
    ],
  });

  if (!method) throw new Error("Login cancelled");

  // ── Kiro CLI Sync ───────────────────────────────────────────────
  if (method === "sync") {
    return loginCliSync(callbacks);
  }

  // ── Desktop (manual refresh token) ──────────────────────────────
  if (method === "desktop") {
    return loginDesktopManual(callbacks);
  }

  // ── Builder ID (social sign-in with PKCE) ──────────────────────
  if (method === "builder-id") {
    return runSocialSignInFlow(callbacks);
  }

  // ── IdC ─────────────────────────────────────────────────────────
  const startUrl = (await callbacks.onPrompt({
    message: "Paste your IAM Identity Center start URL:",
    placeholder: "https://mycompany.awsapps.com/start",
    allowEmpty: false,
  }))?.trim();

  if (!startUrl || !startUrl.startsWith("http")) {
    throw new Error(
      `Invalid start URL "${startUrl ?? ""}" — expected https://…`,
    );
  }

  const regionRaw = await callbacks.onPrompt({
    message: `Identity Center region, or blank to auto-detect (${IDC_PROBE_REGIONS.join(", ")})`,
    placeholder: "us-east-1",
    allowEmpty: true,
  });

  const region = (regionRaw ?? "").trim();
  const regions = region ? [region] : IDC_PROBE_REGIONS;
  callbacks.onProgress?.(
    region ? `Connecting to ${region}…` : "Detecting your Identity Center region…",
  );

  return runDeviceCodeFlow(callbacks, startUrl, regions, "idc");
}

/**
 * CLI Sync login: auto-import credentials from Kiro IDE's local SQLite DB.
 * Fails with a clear message if Kiro IDE is not installed or has no valid tokens.
 */
async function loginCliSync(callbacks: OAuthLoginCallbacks): Promise<KiroCredentials> {
  callbacks.onProgress?.("Scanning for Kiro IDE credentials (~/.kiro/db)…");

  const { importFromKiroCli } = await import("./kiro-cli-sync");
  const imported = await importFromKiroCli();

  if (!imported || (!imported.accessToken && !imported.refreshToken)) {
    throw new Error(
      "No Kiro IDE credentials found.\n" +
      "Make sure Kiro IDE is installed and you're logged in, then try again.\n" +
      "Alternatively, use 'desktop' to paste a refresh token manually.",
    );
  }

  log.info("Successfully imported credentials from Kiro IDE");
  callbacks.onProgress?.(
    `Imported from Kiro IDE (${imported.authMethod}, ${imported.region}` +
    `${imported.email ? `, ${imported.email}` : ""})`,
  );

  if (imported.profileArn) {
    try {
      const apiRegion = resolveApiRegion(imported.region);
      const apiModels = await fetchAvailableModels(imported.accessToken, apiRegion, imported.profileArn);
      setCachedDynamicModels(buildModelsFromApi(apiModels));
      log.info(`Fetched and cached ${apiModels.length} models after CLI sync`);
    } catch (err) {
      log.warn(`Failed to fetch models after CLI sync: ${err}`);
    }
  }

  // Route through kiroCredsFromCliImport so the struct `authMethod` is
  // aligned with the refresh endpoint we can actually hit. The SSO cache
  // fallback has no OIDC clientId/secret, so authMethod is forced to
  // "desktop" there and the pack ends in "|||desktop" — keeping both
  // consistent prevents the next refresh from failing the
  // "missing clientId/clientSecret" precheck.
  return kiroCredsFromCliImport(imported);
}

/**
 * Desktop manual login: prompt the user for a raw refresh token
 * and region, then exchange it for an access token via the desktop
 * auth endpoint.
 */
async function loginDesktopManual(callbacks: OAuthLoginCallbacks): Promise<KiroCredentials> {
  const refreshRaw = await callbacks.onPrompt({
    message:
      "Paste your Kiro desktop refresh token\n" +
      "(find it in ~/.kiro/db/kiro.db → auth_kv table):",
    placeholder: "refresh-token",
    allowEmpty: true,
  });

  const refreshToken = (refreshRaw ?? "").trim();
  if (!refreshToken) {
    throw new Error("Login cancelled — no refresh token provided");
  }

  const regionRaw = await callbacks.onPrompt({
    message: "Kiro region:",
    placeholder: "us-east-1",
    allowEmpty: true,
  });
  const region = (regionRaw ?? "").trim() || "us-east-1";

  const refreshCreds: KiroCredentials = {
    refresh: `${refreshToken}|||desktop`,
    access: "",
    expires: 0,
    clientId: "",
    clientSecret: "",
    region,
    authMethod: "desktop",
  };

  callbacks.onProgress?.("Exchanging refresh token…");
  return refreshKiroToken(refreshCreds);
}


async function runDeviceCodeFlow(
  callbacks: OAuthLoginCallbacks,
  startUrl: string,
  regions: string[],
  authMethod: "builder-id" | "idc",
): Promise<KiroCredentials> {
  let result: Awaited<ReturnType<typeof tryRegisterAndAuthorize>> | null = null;
  let detectedRegion = "";
  for (const region of regions) {
    result = await tryRegisterAndAuthorize(startUrl, region);
    if (result) {
      detectedRegion = region;
      if (regions.length > 1) callbacks.onProgress?.(`Region: ${region}`);
      break;
    }
  }
  if (!result || !detectedRegion) {
    throw new Error(
      `Could not authorize ${startUrl} in ${regions.join(", ")}. ` +
        `Check your start URL${regions.length === 1 ? " and region" : ""} and try again.`,
    );
  }

  // Pi's login-dialog renders `url` prominently (clickable link on macOS)
  // and auto-opens the browser. `instructions` appears below in warning
  // color — use it for the code + expiry hint only. Don't duplicate the URL.
  callbacks.onAuth({
    url: result.devAuth.verificationUriComplete,
    instructions: `Code: ${result.devAuth.userCode}\nComplete authorization within 10 minutes.`,
  });

  callbacks.onProgress?.("Waiting for browser authorization (up to 10 minutes)…");

  const tok = await pollForToken(
    result.oidcEndpoint,
    result.clientId,
    result.clientSecret,
    result.devAuth,
    callbacks.signal,
  );
  if (!tok.accessToken || !tok.refreshToken) {
    throw new Error("Authorization completed but no tokens returned");
  }

  // Resolve profileArn immediately after successful authorization so models can load without restarting pi.
  callbacks.onProgress?.("Resolving Kiro profile…");
  let profileArn: string | undefined;
  try {
    const apiRegion = resolveApiRegion(detectedRegion);
    const resolved = await resolveProfileArn(tok.accessToken, apiRegion);
    if (resolved) {
      profileArn = resolved;
      log.info(`Resolved profileArn during login: ${profileArn}`);
      try {
        const apiModels = await fetchAvailableModels(tok.accessToken, apiRegion, profileArn);
        setCachedDynamicModels(buildModelsFromApi(apiModels));
        log.info(`Fetched and cached ${apiModels.length} models after login`);
      } catch (err) {
        log.warn(`Failed to fetch models during login: ${err}`);
      }
    } else {
      log.warn("Could not resolve profileArn during login");
    }
  } catch (err) {
    log.warn(`Failed to resolve profileArn during login: ${err}`);
  }

  return {
    refresh: `${tok.refreshToken}|${result.clientId}|${result.clientSecret}|${authMethod}`,
    access: tok.accessToken,
    expires: Date.now() + (tok.expiresIn ?? 3600) * 1000 - EXPIRES_BUFFER_MS,
    clientId: result.clientId,
    clientSecret: result.clientSecret,
    region: detectedRegion,
    authMethod,
    ...(profileArn ? { profileArn } : {}),
  };
}

/**
 * Sync refreshed credentials back to the Kiro CLI DB.
 * Fire-and-forget — a failed write-back is non-fatal. Only credentials
 * imported from a specific kiro-cli DB token row are eligible; Kiro IDE SSO
 * cache / desktop refresh tokens are a different token family and must not be
 * written into the CLI DB.
 */
async function syncBackToKiroCli(result: KiroCredentials): Promise<void> {
  if (result.kiroSyncSource !== "kiro-cli-db" || !result.kiroSyncTokenKey) {
    log.debug("Credential sync-back skipped: credential did not originate from kiro-cli DB");
    return;
  }

  try {
    const { saveKiroCliCredentials } = await import("./kiro-cli-sync");
    const synced = await saveKiroCliCredentials({
      accessToken: result.access,
      refreshToken: result.refresh.split("|")[0] ?? "",
      region: result.region,
      authMethod: result.authMethod === "builder-id" || result.authMethod === "social" ? "desktop" : result.authMethod,
      source: result.kiroSyncSource,
      tokenKey: result.kiroSyncTokenKey,
    });
    if (synced) log.info("Synced refreshed credentials back to Kiro CLI DB");
  } catch (err) {
    log.debug(`Credential sync-back skipped: ${err}`);
  }
}

/**
 * Build KiroCredentials from a KiroCliCredentials import.
 * Used by the fallback layers of the refresh cascade.
 *
 * `authMethod` is derived from what's actually refreshable: the OIDC path
 * needs clientId+clientSecret, and the only viable refresh path without
 * them is the desktop endpoint. When clientId is missing, the struct
 * `authMethod` is forced to `"desktop"` so the next refresh hits the
 * correct endpoint instead of failing the "missing clientId/clientSecret"
 * precheck in `refreshTokenInner`.
 */
function kiroCredsFromCliImport(imported: KiroCliCredentials): KiroCredentials {
  const hasOidcCreds = !!imported.clientId && !!imported.clientSecret;
  const authMethod: "builder-id" | "idc" | "desktop" =
    hasOidcCreds && imported.authMethod === "idc"
      ? "idc"
      : "desktop";
  const refreshPacked = hasOidcCreds
    ? `${imported.refreshToken}|${imported.clientId}|${imported.clientSecret ?? ""}|${authMethod}`
    : `${imported.refreshToken}|||desktop`;

  return {
    refresh: refreshPacked,
    access: imported.accessToken,
    expires: Date.now() + 3600 * 1000 - EXPIRES_BUFFER_MS,
    clientId: imported.clientId ?? "",
    clientSecret: imported.clientSecret ?? "",
    region: imported.region,
    authMethod,
    profileArn: imported.profileArn,
    kiroSyncSource: imported.source,
    kiroSyncTokenKey: imported.tokenKey,
  };
}

/**
 * Core token refresh against the appropriate endpoint (OIDC or desktop).
 * This is the "inner" refresh — extracted so the cascade can call it
 * with different credential sets.
 *
 * Throws on failure (caller catches and falls through to next layer).
 */
async function refreshTokenInner(credentials: KiroCredentials): Promise<KiroCredentials> {
  const parts = credentials.refresh.split("|");
  const refreshToken = parts[0] ?? "";
  const clientId = parts[1] ?? credentials.clientId ?? "";
  const clientSecret = parts[2] ?? credentials.clientSecret ?? "";
  const region = credentials.region;
  const authMethod = credentials.authMethod;

  if (!refreshToken || !region) {
    throw new Error("Refresh token is missing region — re-login required");
  }
  if (authMethod !== "desktop" && authMethod !== "social" && (!clientId || !clientSecret)) {
    throw new Error("Refresh token is missing clientId/clientSecret — re-login required");
  }

  // Desktop auth uses Kiro's own auth endpoint (no OIDC client required).
  if (authMethod === "desktop" || authMethod === "social") {
    const desktopEndpoint = `https://prod.${region}.auth.desktop.kiro.dev/refreshToken`;
    const resp = await fetch(desktopEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "pi-kiro" },
      body: JSON.stringify({ refreshToken }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new Error(`Desktop token refresh failed: ${resp.status} ${body}`);
    }

    const data = (await resp.json()) as {
      accessToken: string;
      refreshToken: string;
      expiresIn?: number;
    };

    let profileArn = credentials.profileArn;
    if (!profileArn) {
      try {
        const apiRegion = resolveApiRegion(region);
        const resolved = await resolveProfileArn(data.accessToken, apiRegion);
        if (resolved) {
          profileArn = resolved;
          log.info(`Resolved profileArn during desktop refresh: ${profileArn}`);
        }
      } catch (err) {
        log.warn(`Failed to resolve profileArn during desktop refresh: ${err}`);
      }
    }

    if (profileArn) {
      try {
        const apiRegion = resolveApiRegion(region);
        const apiModels = await fetchAvailableModels(data.accessToken, apiRegion, profileArn);
        setCachedDynamicModels(buildModelsFromApi(apiModels));
        log.info(`Fetched and cached ${apiModels.length} models after desktop token refresh`);
      } catch (err) {
        log.warn(`Failed to fetch models after desktop token refresh: ${err}`);
      }
    }

    return {
      refresh: `${data.refreshToken}|||${authMethod}`,
      access: data.accessToken,
      expires: Date.now() + (data.expiresIn ?? 3600) * 1000 - EXPIRES_BUFFER_MS,
      clientId: "",
      clientSecret: "",
      region,
      authMethod,
      profileArn,
      kiroSyncSource: credentials.kiroSyncSource,
      kiroSyncTokenKey: credentials.kiroSyncTokenKey,
    };
  }

  const endpoint = `https://oidc.${region}.amazonaws.com/token`;
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "pi-kiro" },
    body: JSON.stringify({ clientId, clientSecret, refreshToken, grantType: "refresh_token" }),
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`Token refresh failed: ${resp.status} ${body}`);
  }

  const data = (await resp.json()) as {
    accessToken: string;
    refreshToken: string;
    expiresIn?: number;
  };

  let profileArn = credentials.profileArn;
  if (!profileArn) {
    try {
      const apiRegion = resolveApiRegion(region);
      const resolved = await resolveProfileArn(data.accessToken, apiRegion);
      if (resolved) {
        profileArn = resolved;
        log.info(`Resolved profileArn during OIDC refresh: ${profileArn}`);
      }
    } catch (err) {
      log.warn(`Failed to resolve profileArn during OIDC refresh: ${err}`);
    }
  }

  if (profileArn) {
    try {
      const apiRegion = resolveApiRegion(region);
      const apiModels = await fetchAvailableModels(data.accessToken, apiRegion, profileArn);
      setCachedDynamicModels(buildModelsFromApi(apiModels));
      log.info(`Fetched and cached ${apiModels.length} models after token refresh`);
    } catch (err) {
      log.warn(`Failed to fetch models after token refresh, falling back: ${err}`);
    }
  }

  return {
    refresh: `${data.refreshToken}|${clientId}|${clientSecret}|${authMethod}`,
    access: data.accessToken,
    expires: Date.now() + (data.expiresIn ?? 3600) * 1000 - EXPIRES_BUFFER_MS,
    clientId,
    clientSecret,
    region,
    authMethod,
    profileArn,
    kiroSyncSource: credentials.kiroSyncSource,
    kiroSyncTokenKey: credentials.kiroSyncTokenKey,
  };
}

/**
 * 5-layer credential refresh cascade.
 *
 * Layers (each falls through to the next on failure):
 *   1. Normal OIDC/desktop refresh with current credentials
 *   2. Import fresh credentials from Kiro CLI DB → use as-is
 *   3. Import fresh credentials from Kiro CLI DB → refresh those
 *   4. Import expired credentials from Kiro CLI DB → use as-is
 *   5. Import expired credentials from Kiro CLI DB → refresh those
 *
 * After any successful refresh, the new tokens are synced back to the
 * Kiro CLI DB (fire-and-forget) for bidirectional sync.
 */
export async function refreshKiroToken(
  credentials: OAuthCredentials,
): Promise<KiroCredentials> {
  const inputMethod = (credentials as Partial<KiroCredentials>).authMethod;
  const authMethod: "builder-id" | "idc" | "desktop" | "social" =
    inputMethod === "builder-id" || inputMethod === "idc" || inputMethod === "desktop" || inputMethod === "social"
      ? inputMethod
      : "idc";
  if (
    inputMethod !== undefined &&
    inputMethod !== "builder-id" &&
    inputMethod !== "idc" &&
    inputMethod !== "desktop" &&
    inputMethod !== "social"
  ) {
    log.warn(`refreshKiroToken: unrecognized authMethod "${String(inputMethod)}" — defaulting to "idc"`);
  }

  const baseCreds: KiroCredentials = {
    ...credentials,
    clientId: (credentials as KiroCredentials).clientId ?? credentials.refresh.split("|")[1] ?? "",
    clientSecret: (credentials as KiroCredentials).clientSecret ?? credentials.refresh.split("|")[2] ?? "",
    region: (credentials as KiroCredentials).region,
    authMethod,
  };

  const errors: string[] = [];

  // ── Layer 1: Normal refresh with current credentials ──────────
  try {
    log.debug("refresh.cascade: layer 1 — normal refresh");
    const result = await refreshTokenInner(baseCreds);
    void syncBackToKiroCli(result);
    return result;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`L1(normal): ${msg}`);
    log.warn(`refresh.cascade: layer 1 failed — ${msg}`);
  }

  // ── Layer 2: Import fresh Kiro CLI credentials → use as-is ────
  let freshImport: KiroCliCredentials | null = null;
  try {
    log.debug("refresh.cascade: layer 2 — fresh kiro-cli import");
    const { importFromKiroCli } = await import("./kiro-cli-sync");
    freshImport = await importFromKiroCli();
    if (freshImport?.accessToken) {
      const result = kiroCredsFromCliImport(freshImport);
      log.info("refresh.cascade: layer 2 succeeded — using fresh kiro-cli credentials");
      return result;
    }
    errors.push("L2(fresh-import): no valid credentials found");
    log.debug("refresh.cascade: layer 2 — no fresh credentials");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`L2(fresh-import): ${msg}`);
    log.warn(`refresh.cascade: layer 2 failed — ${msg}`);
  }

  // ── Layer 3: Refresh the fresh Kiro CLI credentials ───────────
  if (freshImport?.refreshToken) {
    try {
      log.debug("refresh.cascade: layer 3 — refresh fresh kiro-cli creds");
      const freshCreds = kiroCredsFromCliImport(freshImport);
      const result = await refreshTokenInner(freshCreds);
      void syncBackToKiroCli(result);
      log.info("refresh.cascade: layer 3 succeeded — refreshed fresh kiro-cli credentials");
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`L3(refresh-fresh): ${msg}`);
      log.warn(`refresh.cascade: layer 3 failed — ${msg}`);
    }
  }

  // ── Layer 4: Import expired Kiro CLI credentials → use as-is ──
  let expiredImport: KiroCliCredentials | null = null;
  try {
    log.debug("refresh.cascade: layer 4 — expired kiro-cli import");
    const { getKiroCliCredentialsAllowExpired } = await import("./kiro-cli-sync");
    expiredImport = await getKiroCliCredentialsAllowExpired(freshImport);
    if (expiredImport?.accessToken) {
      const result = kiroCredsFromCliImport(expiredImport);
      log.info("refresh.cascade: layer 4 succeeded — using expired kiro-cli credentials");
      return result;
    } else {
      errors.push("L4(expired-import): no different expired credentials");
      log.debug("refresh.cascade: layer 4 — no additional expired credentials");
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`L4(expired-import): ${msg}`);
    log.warn(`refresh.cascade: layer 4 failed — ${msg}`);
  }

  // ── Layer 5: Refresh the expired Kiro CLI credentials ─────────
  if (expiredImport?.refreshToken) {
    try {
      log.debug("refresh.cascade: layer 5 — refresh expired kiro-cli creds");
      const expiredCreds = kiroCredsFromCliImport(expiredImport);
      const result = await refreshTokenInner(expiredCreds);
      void syncBackToKiroCli(result);
      log.info("refresh.cascade: layer 5 succeeded — refreshed expired kiro-cli credentials");
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`L5(refresh-expired): ${msg}`);
      log.warn(`refresh.cascade: layer 5 failed — ${msg}`);
    }
  }

  // All layers exhausted.
  throw new Error(
    `Kiro token refresh failed — all 5 cascade layers exhausted. ` +
    `Re-login required.\n${errors.join("\n")}`,
  );
}
