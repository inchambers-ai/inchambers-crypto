/**
 * @jest-environment jsdom
 */
/// <reference types="jest" />
/**
 * The user's half of the sync key, held by their own authenticator.
 *
 * This is what removes InChambers from key custody, so the assertions that
 * matter are the negative ones. `a stored wrap alone does not reveal the half`
 * is the whole feature: the gateway holds every wrap, and holding them must not
 * be the same as holding the key, or we have moved the problem rather than
 * solved it.
 *
 * The second load-bearing test is the multi-device one. Deriving the key
 * straight from the PRF output is the obvious design and it fails silently on
 * the user's second device, because a YubiKey and a platform passkey are
 * different credentials with different PRF outputs. `a second authenticator
 * opens the SAME half` is why the indirection through a wrapped random secret
 * exists at all.
 *
 * WebAuthn is stubbed rather than mocked away, following
 * `platform-ui/src/lib/__tests__/recoveryKey.test.ts`: the real enrolment and
 * unlock code runs, HKDF and AES-GCM included, with only the authenticator
 * replaced by a deterministic HMAC. That is what a real authenticator computes
 * (`HMAC-SHA256(credential_secret, salt)`), so the stub is faithful to the
 * mechanism rather than standing in for it.
 */

import { webcrypto } from 'crypto';

if (!(globalThis as { crypto?: Crypto }).crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto as unknown as Crypto,
    configurable: true,
  });
}

import {
  enrollAuthenticator, unlockUserHalf, generateUserHalf, prfCapability,
  type KeyWrap,
} from '../passkeyHalf';

const RP_ID = 'app.inchambers.ai';
const OPTS = { userName: 'lawyer@firm.com', rpId: RP_ID };

/** One authenticator: a distinct internal secret and credential id per device. */
interface Device {
  secret: string;
  credentialId: Uint8Array;
  prf: boolean;
}

function device(secret: string, idByte: number, prf = true): Device {
  return { secret, credentialId: new Uint8Array(16).fill(idByte), prf };
}

/**
 * Install a set of authenticators. `get()` answers as the first device whose
 * credential id appears in allowCredentials, which is what a browser does when
 * it picks whichever key is actually present.
 */
/** Only the fields the stub reads. The real options type is far larger. */
interface AssertionRequest {
  publicKey: {
    allowCredentials?: Array<{ id: Uint8Array }>;
    extensions: { prf: { eval: { first: Uint8Array } } };
  };
}

function installAuthenticators(devices: Device[]) {
  const prfFor = async (secret: string, salt: Uint8Array) => {
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret) as BufferSource,
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    return crypto.subtle.sign('HMAC', key, salt as BufferSource);
  };

  const sameId = (a: Uint8Array, b: Uint8Array) =>
    a.length === b.length && a.every((v, i) => v === b[i]);

  Object.defineProperty(window, 'PublicKeyCredential', { value: function () {}, configurable: true });
  Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: {
      // Creation always lands on the first device, as if the user just touched it.
      create: async () => ({
        rawId: devices[0].credentialId.buffer.slice(
          devices[0].credentialId.byteOffset,
          devices[0].credentialId.byteOffset + devices[0].credentialId.byteLength,
        ),
        getClientExtensionResults: () => ({}),
      }),
      get: async (o: AssertionRequest) => {
        const allowed: Uint8Array[] = (o.publicKey.allowCredentials || [])
          .map((c) => new Uint8Array(c.id));
        const match = devices.find(d => allowed.some(id => sameId(id, d.credentialId)));
        if (!match) throw Object.assign(new Error('no key'), { name: 'NotAllowedError' });
        const salt = new Uint8Array(o.publicKey.extensions.prf.eval.first);
        const first = match.prf ? await prfFor(match.secret, salt) : undefined;
        return {
          rawId: match.credentialId.buffer.slice(
            match.credentialId.byteOffset,
            match.credentialId.byteOffset + match.credentialId.byteLength,
          ),
          getClientExtensionResults: () => (match.prf ? { prf: { results: { first } } } : {}),
        };
      },
    },
  });
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

const LAPTOP = () => device('touch-id-secret', 1);
const YUBIKEY = () => device('yubikey-secret', 2);

describe('passkey-held user half', () => {
  /**
   * THE FEATURE. Every wrap sits in the firm gateway's database, so a wrap must
   * be worthless without the authenticator. If it were not, the gateway (and
   * anyone who takes its database) would hold the user half outright and this
   * whole mechanism would be decoration.
   */
  it('a stored wrap alone does not reveal the half', async () => {
    installAuthenticators([LAPTOP()]);
    const enrolled = await enrollAuthenticator(OPTS);
    expect(enrolled.status).toBe('ok');
    if (enrolled.status !== 'ok') return;

    // Everything the gateway holds, as JSON. The half must not be in it, and
    // must not be derivable from it.
    const stored = JSON.stringify(enrolled.wrap);
    expect(stored).not.toContain(hex(enrolled.userHalf));
    expect(stored).not.toContain(Buffer.from(enrolled.userHalf).toString('base64'));

    // And with the authenticator gone, the wrap opens for nobody. The exact
    // status is the browser's business (a real one raises NotAllowedError once
    // the prompt finds no matching key); what must hold is that no half comes
    // back.
    installAuthenticators([YUBIKEY()]);
    const attacked = await unlockUserHalf([enrolled.wrap], RP_ID);
    expect(attacked.status).not.toBe('ok');
    expect(attacked).not.toHaveProperty('userHalf');
  });

  /**
   * THE REASON FOR THE INDIRECTION. Deriving the key straight from the PRF
   * output looks simpler and breaks on the second device, silently, because
   * each credential has its own PRF secret. Wrapping one random half under each
   * authenticator is what makes a laptop and a YubiKey open the same rows.
   */
  it('a second authenticator opens the SAME half', async () => {
    installAuthenticators([LAPTOP()]);
    const first = await enrollAuthenticator(OPTS);
    if (first.status !== 'ok') throw new Error('first enrolment failed');

    // Adding a device: the already-unlocked half is re-wrapped, not replaced.
    installAuthenticators([YUBIKEY()]);
    const second = await enrollAuthenticator({ ...OPTS, existingHalf: first.userHalf });
    if (second.status !== 'ok') throw new Error('second enrolment failed');

    expect(hex(second.userHalf)).toBe(hex(first.userHalf));
    // Different authenticator, so the stored blob differs even though the
    // secret inside it is the same.
    expect(second.wrap.sealed).not.toBe(first.wrap.sealed);

    const unlocked = await unlockUserHalf([first.wrap, second.wrap], RP_ID);
    expect(unlocked.status).toBe('ok');
    if (unlocked.status !== 'ok') return;
    expect(hex(unlocked.userHalf)).toBe(hex(first.userHalf));
  });

  /**
   * The footgun the API doc warns about, pinned so it cannot be introduced
   * quietly: enrolling a second device WITHOUT passing the unlocked half mints
   * a different secret, and everything written under the first becomes
   * unreadable. Callers must always pass `existingHalf` when one exists.
   */
  it('enrolling without the existing half mints a DIFFERENT one', async () => {
    installAuthenticators([LAPTOP()]);
    const a = await enrollAuthenticator(OPTS);
    installAuthenticators([YUBIKEY()]);
    const b = await enrollAuthenticator(OPTS);
    if (a.status !== 'ok' || b.status !== 'ok') throw new Error('enrolment failed');

    expect(hex(b.userHalf)).not.toBe(hex(a.userHalf));
  });

  /**
   * With several devices enrolled, unlock offers all of them in one prompt and
   * opens the wrap belonging to whichever one actually answered. Picking by
   * position instead of by returned credential id would decrypt to garbage.
   */
  it('opens the wrap belonging to the authenticator that answered', async () => {
    installAuthenticators([LAPTOP()]);
    const laptop = await enrollAuthenticator(OPTS);
    if (laptop.status !== 'ok') throw new Error('enrolment failed');
    installAuthenticators([YUBIKEY()]);
    const yubi = await enrollAuthenticator({ ...OPTS, existingHalf: laptop.userHalf });
    if (yubi.status !== 'ok') throw new Error('enrolment failed');

    // Only the YubiKey is present, but the laptop's wrap is listed first.
    installAuthenticators([YUBIKEY()]);
    const unlocked = await unlockUserHalf([laptop.wrap, yubi.wrap], RP_ID);
    expect(unlocked.status).toBe('ok');
    if (unlocked.status !== 'ok') return;
    expect(hex(unlocked.userHalf)).toBe(hex(laptop.userHalf));
  });

  /** An authenticator without PRF is named as such, not reported as a failure. */
  it('reports an authenticator with no PRF support instead of failing obscurely', async () => {
    installAuthenticators([device('no-prf-key', 3, false)]);
    const enrolled = await enrollAuthenticator(OPTS);
    expect(enrolled.status).toBe('no-prf');
  });

  /** Never enrolled anywhere reads differently from "your key did not work". */
  it('distinguishes never-enrolled from no-authenticator-present', async () => {
    installAuthenticators([LAPTOP()]);
    expect((await unlockUserHalf([], RP_ID)).status).toBe('not-enrolled');
  });

  /**
   * A damaged or stale wrap must not be fatal while another wrap could still
   * work, and it must never yield plausible-looking wrong bytes. AES-GCM's
   * authentication is what guarantees the second half of that.
   */
  it('skips a corrupted wrap rather than returning wrong bytes', async () => {
    installAuthenticators([LAPTOP()]);
    const enrolled = await enrollAuthenticator(OPTS);
    if (enrolled.status !== 'ok') throw new Error('enrolment failed');

    const corrupted: KeyWrap = { ...enrolled.wrap, sealed: enrolled.wrap.sealed.replace(/^.{8}/, 'AAAAAAAA') };
    const result = await unlockUserHalf([corrupted], RP_ID);
    expect(result.status).toBe('no-matching-authenticator');
  });

  /**
   * The Word taskpane is a cross-origin iframe Office controls, and WebAuthn
   * needs a permissions-policy grant the embedder never gives. Saying so is the
   * difference between "open this in a window" and a bare NotAllowedError that
   * reads as a broken security key.
   */
  it('names the iframe restriction rather than attempting a doomed call', async () => {
    installAuthenticators([LAPTOP()]);
    Object.defineProperty(window, 'parent', { value: { name: 'the-office-host' }, configurable: true });
    try {
      expect(prfCapability()).toBe('blocked-in-frame');
      expect((await enrollAuthenticator(OPTS)).status).toBe('blocked-in-frame');
      expect((await unlockUserHalf([{ version: 1, credentialId: 'x', salt: 'x', sealed: 'x' }], RP_ID)).status)
        .toBe('blocked-in-frame');
    } finally {
      Object.defineProperty(window, 'parent', { value: window, configurable: true });
    }
  });

  /** A browser with no WebAuthn at all is a third, distinct answer. */
  it('separates no-WebAuthn from a blocked frame', async () => {
    installAuthenticators([LAPTOP()]);
    Object.defineProperty(window, 'PublicKeyCredential', { value: undefined, configurable: true });
    expect(prfCapability()).toBe('unsupported');
    expect((await enrollAuthenticator(OPTS)).status).toBe('unsupported');
  });

  /** The half is a full AES-256 key's worth of entropy, like both other halves. */
  it('generates a 32-byte half', () => {
    expect(generateUserHalf().length).toBe(32);
    expect(hex(generateUserHalf())).not.toBe(hex(generateUserHalf()));
  });
});
