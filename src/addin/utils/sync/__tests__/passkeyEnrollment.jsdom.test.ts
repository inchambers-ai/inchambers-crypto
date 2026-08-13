/**
 * @jest-environment jsdom
 */
/// <reference types="jest" />
/**
 * Enrolling an authenticator against the user's half of the key.
 *
 * The whole file exists to enforce one rule: never mint a second half for a
 * user who already has one. That failure is silent and irreversible. Both
 * halves are cryptographically valid, nothing errors, and everything written
 * under the old one simply stops opening. `refuses to enrol when the store
 * cannot be read` is the test carrying it, because an unreachable store is the
 * realistic way an empty list gets mistaken for a new user.
 *
 * Falsifying that guard turns out to be impossible without breaking the build:
 * `WrapStore.list` returns a discriminated union, so `listed.wraps` cannot be
 * read until the error case has been handled. The compiler enforces the rule
 * and these tests pin the behaviour that follows from it.
 *
 * The escrow test unseals with the private key rather than trusting that the
 * bytes look right, so the format is proven rather than asserted.
 */

import { webcrypto } from 'crypto';

if (!(globalThis as { crypto?: Crypto }).crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto as unknown as Crypto,
    configurable: true,
  });
}

let prfState: 'available' | 'blocked-in-frame' | 'unsupported' = 'available';
let unlockResult: any = null;
let mintedHalves: Uint8Array[] = [];

jest.mock('../passkeyHalf', () => ({
  prfCapability: () => prfState,
  generateUserHalf: () => new Uint8Array(32).fill(1),
  unlockUserHalf: async () => unlockResult,
  enrollAuthenticator: async (opts: { existingHalf?: Uint8Array }) => {
    const half = opts.existingHalf ?? new Uint8Array(32).fill(mintedHalves.length + 40);
    mintedHalves.push(new Uint8Array(half));
    return {
      status: 'ok',
      userHalf: new Uint8Array(half),
      wrap: { version: 1, credentialId: `cred-${mintedHalves.length}`, salt: 's', sealed: 'sealed' },
    };
  },
}));

import { enrollDevice, sealToEscrowKey, escrowFingerprint } from '../passkeyEnrollment';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function store(listResult: any, onStore = jest.fn(async () => ({ id: 'w1_abc' }))) {
  return { list: jest.fn(async () => listResult), store: onStore };
}

beforeEach(() => {
  prfState = 'available';
  unlockResult = null;
  mintedHalves = [];
});

describe('enrolling an authenticator', () => {
  it('mints a half on a genuine first enrolment', async () => {
    const s = store({ status: 'ok', wraps: [], escrowKey: null });
    const seen: Uint8Array[] = [];
    const out = await enrollDevice({
      store: s, userName: 'a@firm.com',
      onHalf: async (h) => { seen.push(new Uint8Array(h)); },
    });

    expect(out).toEqual({ status: 'enrolled', wrapId: 'w1_abc', first: true });
    expect(seen).toHaveLength(1);
    expect(s.store).toHaveBeenCalled();
  });

  /**
   * Adding a second device must re-wrap the SAME secret. If it minted a new
   * one, the laptop and the YubiKey would each open only their own rows and
   * neither would report a problem.
   */
  it('re-wraps the existing half when adding a device', async () => {
    const existing = new Uint8Array(32).fill(7);
    unlockResult = { status: 'ok', userHalf: new Uint8Array(existing) };
    const s = store({
      status: 'ok',
      wraps: [{ version: 1, credentialId: 'cred-old', salt: 's', sealed: 'x' }],
      escrowKey: null,
    });
    const seen: Uint8Array[] = [];
    const out = await enrollDevice({
      store: s, userName: 'a@firm.com',
      onHalf: async (h) => { seen.push(new Uint8Array(h)); },
    });

    expect(out.status).toBe('enrolled');
    if (out.status === 'enrolled') expect(out.first).toBe(false);
    expect(hex(seen[0])).toBe(hex(existing));
    expect(hex(mintedHalves[0])).toBe(hex(existing));
  });

  /**
   * THE RULE. An unreachable store returns no wraps, which looks exactly like a
   * new user. Enrolling on that basis mints a second half and orphans
   * everything already encrypted, silently and permanently.
   */
  it('refuses to enrol when the store cannot be read', async () => {
    const s = store({ status: 'error' });
    const out = await enrollDevice({
      store: s, userName: 'a@firm.com', onHalf: async () => {},
    });

    expect(out.status).toBe('failed');
    expect(s.store).not.toHaveBeenCalled();
    expect(mintedHalves).toHaveLength(0);
  });

  /**
   * Wraps exist but this device cannot open one, so the existing half is
   * unavailable. Enrolling anyway would orphan it. Asking for a key the user
   * already owns is the lesser cost by a wide margin.
   */
  it('refuses rather than minting when the existing half cannot be unlocked', async () => {
    unlockResult = { status: 'no-matching-authenticator' };
    const s = store({
      status: 'ok',
      wraps: [{ version: 1, credentialId: 'cred-old', salt: 's', sealed: 'x' }],
      escrowKey: null,
    });
    const out = await enrollDevice({
      store: s, userName: 'a@firm.com', onHalf: async () => {},
    });

    expect(out.status).toBe('needs-existing-authenticator');
    expect(s.store).not.toHaveBeenCalled();
    expect(mintedHalves).toHaveLength(0);
  });

  it('reports the taskpane frame restriction without touching the store', async () => {
    prfState = 'blocked-in-frame';
    const s = store({ status: 'ok', wraps: [], escrowKey: null });
    const out = await enrollDevice({
      store: s, userName: 'a@firm.com', onHalf: async () => {},
    });

    expect(out.status).toBe('blocked-in-frame');
    expect(s.list).not.toHaveBeenCalled();
  });

  /** A gateway with no wrap storage is not a partial success. */
  it('does not enrol against a gateway that cannot store wraps', async () => {
    const s = store({ status: 'unsupported' });
    const out = await enrollDevice({
      store: s, userName: 'a@firm.com', onHalf: async () => {},
    });
    expect(out.status).toBe('failed');
    expect(mintedHalves).toHaveLength(0);
  });
});

describe('break-glass escrow', () => {
  /**
   * Proven by unsealing with the private key, not by inspecting the blob. The
   * firm's recovery depends on this format being readable years later by code
   * that does not exist yet, so "it looks like base64" is not evidence.
   */
  it('seals to the firm key and opens with the private half', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    ) as CryptoKeyPair;
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const spkiB64 = btoa(String.fromCharCode(...spki));

    const half = new Uint8Array(32).fill(23);
    const sealed = await sealToEscrowKey(half, spkiB64);

    // What a firm's recovery tool does, given the private key from the bundle.
    const raw = Uint8Array.from(atob(sealed), c => c.charCodeAt(0));
    const ephLen = (raw[0] << 8) | raw[1];
    const ephPub = raw.slice(2, 2 + ephLen);
    const iv = raw.slice(2 + ephLen, 2 + ephLen + 12);
    const ct = raw.slice(2 + ephLen + 12);

    const ephemeral = await crypto.subtle.importKey(
      'spki', ephPub as BufferSource, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeral }, pair.privateKey, 256,
    );
    const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF', hash: 'SHA-256',
        salt: new Uint8Array(0) as BufferSource,
        info: new TextEncoder().encode('ic-half-escrow-v1') as BufferSource,
      },
      base, 256,
    );
    const key = await crypto.subtle.importKey(
      'raw', bits, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
    );
    const opened = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct as BufferSource),
    );
    expect(hex(opened)).toBe(hex(half));
  });

  /** A DIFFERENT firm key must not open it, or escrow would be firm-agnostic. */
  it('cannot be opened by another firm key', async () => {
    const a = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    ) as CryptoKeyPair;
    const b = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    ) as CryptoKeyPair;
    const spkiA = new Uint8Array(await crypto.subtle.exportKey('spki', a.publicKey));
    const sealed = await sealToEscrowKey(
      new Uint8Array(32).fill(5), btoa(String.fromCharCode(...spkiA)),
    );

    const raw = Uint8Array.from(atob(sealed), c => c.charCodeAt(0));
    const ephLen = (raw[0] << 8) | raw[1];
    const ephemeral = await crypto.subtle.importKey(
      'spki', raw.slice(2, 2 + ephLen) as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' }, false, [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephemeral }, b.privateKey, 256,
    );
    const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF', hash: 'SHA-256',
        salt: new Uint8Array(0) as BufferSource,
        info: new TextEncoder().encode('ic-half-escrow-v1') as BufferSource,
      },
      base, 256,
    );
    const key = await crypto.subtle.importKey(
      'raw', bits, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
    );
    await expect(crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(2 + ephLen, 2 + ephLen + 12) },
      key,
      raw.slice(2 + ephLen + 12) as BufferSource,
    )).rejects.toThrow();
  });

  it('fingerprints the key so a blob records which one it needs', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    ) as CryptoKeyPair;
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    const b64 = btoa(String.fromCharCode(...spki));
    const fp = await escrowFingerprint(b64);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(await escrowFingerprint(b64)).toBe(fp);
  });
});
