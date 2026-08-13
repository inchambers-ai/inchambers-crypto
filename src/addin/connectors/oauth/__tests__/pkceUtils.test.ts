/**
 * @jest-environment jsdom
 *
 * PKCE utilities for the connector OAuth flows.
 *
 * These are the only thing standing between an intercepted authorization code
 * and a usable connector token, so the properties below are security properties,
 * not formatting preferences:
 *
 *   - the verifier and state must be unguessable and correctly base64url/hex
 *     encoded. A `+` or `/` surviving into the verifier makes the exchange fail
 *     at the provider, which surfaces as a mystery "connect did nothing".
 *   - the challenge must be the exact SHA-256 base64url of the verifier. The
 *     RFC 7636 appendix B vector is used, so this catches an encoding change
 *     that still looks plausible.
 *   - storage is keyed by `state` precisely so two concurrent flows (the silent
 *     iframe connect fired at login AND a manual Connect click) cannot consume
 *     each other's verifier. That is the bug the per-state key was added for.
 *
 * jsdom is needed for sessionStorage, btoa and crypto.subtle.
 */

import { webcrypto } from 'crypto';
import { TextEncoder as NodeTextEncoder } from 'util';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  storePKCEParams,
  retrievePKCEParams,
} from '../pkceUtils';

// jsdom wires neither crypto.subtle nor TextEncoder. Node's own implementations
// are the real ones, which is what we want the digest checked against rather
// than a stub that would make the RFC vector below meaningless.
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
}
if (typeof globalThis.TextEncoder === 'undefined') {
  globalThis.TextEncoder = NodeTextEncoder as unknown as typeof globalThis.TextEncoder;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

describe('generateCodeVerifier', () => {
  it('emits base64url with no padding or url-unsafe characters', () => {
    // 96 random bytes. `+`, `/` or `=` reaching the authorize URL breaks the
    // exchange at the provider with an opaque error.
    const v = generateCodeVerifier();
    expect(v).toMatch(BASE64URL);
    expect(v).not.toContain('=');
  });

  it('stays inside the RFC 7636 length window', () => {
    // 43 to 128 characters. 96 bytes encodes to 128, the maximum allowed.
    const v = generateCodeVerifier();
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });

  it('does not repeat', () => {
    const seen = new Set(Array.from({ length: 20 }, () => generateCodeVerifier()));
    expect(seen.size).toBe(20);
  });
});

describe('generateCodeChallenge', () => {
  it('matches the RFC 7636 appendix B test vector', async () => {
    // The one assertion here that a plausible-looking encoding change cannot
    // survive. Everything else about PKCE can be self-consistent and wrong.
    const challenge = await generateCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
    expect(challenge).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('is deterministic for a verifier and differs between verifiers', async () => {
    const a = await generateCodeChallenge('verifier-one');
    expect(await generateCodeChallenge('verifier-one')).toBe(a);
    expect(await generateCodeChallenge('verifier-two')).not.toBe(a);
  });

  it('emits unpadded base64url of a 32 byte digest', () => {
    return generateCodeChallenge(generateCodeVerifier()).then((c) => {
      expect(c).toMatch(BASE64URL);
      expect(c).toHaveLength(43);
    });
  });
});

describe('generateState', () => {
  it('is 32 bytes of lowercase hex', () => {
    expect(generateState()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('does not repeat', () => {
    const seen = new Set(Array.from({ length: 20 }, () => generateState()));
    expect(seen.size).toBe(20);
  });
});

describe('PKCE param storage', () => {
  beforeEach(() => sessionStorage.clear());

  it('round-trips the stored params for a given state', () => {
    const params = { verifier: 'v1', state: 's1', connectorId: 'google_workspace' };
    storePKCEParams(params);
    expect(retrievePKCEParams('s1')).toEqual(params);
  });

  it('preserves the pinned app, so the exchange targets the same tenant', () => {
    // Own-mode org connectors mint against the firm's OWN Azure app. Losing
    // `app` here silently exchanges the code against the inchambers app.
    const params = {
      verifier: 'v1', state: 's1', connectorId: 'microsoft_365',
      app: { clientId: 'firm-app-id', tenant: 'firm-tenant-id' },
    };
    storePKCEParams(params);
    expect(retrievePKCEParams('s1')?.app).toEqual({ clientId: 'firm-app-id', tenant: 'firm-tenant-id' });
  });

  it('consumes the params, so a replayed callback gets nothing', () => {
    storePKCEParams({ verifier: 'v1', state: 's1', connectorId: 'google_workspace' });
    expect(retrievePKCEParams('s1')).not.toBeNull();
    expect(retrievePKCEParams('s1')).toBeNull();
  });

  it('gives each concurrent flow its own verifier', () => {
    // The reason the per-state key exists. Before it, the second flow to start
    // overwrote the first flow's verifier and the first callback failed with
    // invalid_grant.
    storePKCEParams({ verifier: 'verifier-A', state: 'state-A', connectorId: 'google_workspace' });
    storePKCEParams({ verifier: 'verifier-B', state: 'state-B', connectorId: 'microsoft_365' });
    expect(retrievePKCEParams('state-A')?.verifier).toBe('verifier-A');
    expect(retrievePKCEParams('state-B')?.verifier).toBe('verifier-B');
  });

  it('falls back to the legacy single key when no state is supplied', () => {
    // Kept for a flow that started before the per-state key shipped, or a
    // callback that could not recover its state.
    storePKCEParams({ verifier: 'v1', state: 's1', connectorId: 'google_workspace' });
    expect(retrievePKCEParams()?.verifier).toBe('v1');
  });

  it('returns null rather than throwing on corrupted storage', () => {
    // sessionStorage is shared with everything else on the origin. A partial
    // write must not take down the callback page with a parse error.
    sessionStorage.setItem('connector_pkce:s1', '{not json');
    expect(retrievePKCEParams('s1')).toBeNull();
  });

  it('returns null when nothing was ever stored', () => {
    expect(retrievePKCEParams('never-stored')).toBeNull();
  });
});
