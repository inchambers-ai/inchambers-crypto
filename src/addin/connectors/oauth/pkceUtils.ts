/**
 * PKCE OAuth utilities for client-side connector authentication.
 * All crypto operations use Web Crypto API — no secrets touch our servers.
 */

/** Generate a 128-byte random code verifier (base64url encoded) */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(96);
  crypto.getRandomValues(array);
  return base64url(array);
}

/** Generate SHA-256 code challenge from verifier */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64url(new Uint8Array(digest));
}

/** Generate a 32-byte random state parameter (hex) */
export function generateState(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * PKCE params stashed before the authorize redirect. `app` (F7) pins the
 * exchange to the SAME Azure app the authorize used — the firm's OWN app for
 * own-mode org connectors — so the token isn't minted against the inchambers app.
 */
export interface PKCEParams {
  verifier: string;
  state: string;
  connectorId: string;
  app?: { clientId: string; tenant?: string };
}

/**
 * Store PKCE params in sessionStorage for callback verification. Keyed by
 * `state` so concurrent flows (the F7 silent-iframe connect fired at login AND
 * a manual "Connect" click) don't clobber each other's verifier. A legacy
 * single-key copy is also written as a fallback for any in-flight flow that
 * started before this change / can't recover the state.
 */
export function storePKCEParams(params: PKCEParams): void {
  const json = JSON.stringify(params);
  sessionStorage.setItem(`connector_pkce:${params.state}`, json);
  sessionStorage.setItem('connector_pkce', json);
}

/**
 * Retrieve and clear PKCE params. Pass the `state` returned on the callback to
 * fetch the exact flow's params (per-state key); falls back to the legacy key.
 */
export function retrievePKCEParams(state?: string): PKCEParams | null {
  let raw: string | null = null;
  if (state) {
    const key = `connector_pkce:${state}`;
    raw = sessionStorage.getItem(key);
    if (raw) sessionStorage.removeItem(key);
  }
  if (!raw) raw = sessionStorage.getItem('connector_pkce');
  sessionStorage.removeItem('connector_pkce');
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Base64url encode a Uint8Array (RFC 7636) */
function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
