/**
 * The user's half of the sync key, held by their own authenticator.
 *
 * ## What this replaces, and why
 *
 * The sync key used to be `HKDF(ic_half ‖ firm_half)`, where `ic_half` came from
 * `/api/user/sync-key` on our servers. That was two-of-two and it was a real
 * improvement over one-of-one, but it left two problems standing:
 *
 *   1. We remained a mandatory party. A firm could not read its own files
 *      without us, so losing `SYNC_DEK_SECRET` (or losing the company) took
 *      their synced history with it. Vendor lock-in expressed as cryptography.
 *   2. We still held something. "InChambers cannot decrypt your work product"
 *      needed an asterisk, and a security review finds asterisks.
 *
 * Both go away if our half is replaced by one the user holds in hardware. The
 * firm half is unchanged, so the gateway is still a second party and a stolen
 * gateway database is still useless on its own.
 *
 * ## Why a wrapped random secret, and not the PRF output directly
 *
 * The obvious design derives the key straight from the authenticator's PRF
 * output. It does not survive contact with a second device: a YubiKey and a
 * platform passkey are different credentials and produce different PRF outputs,
 * so the user's laptop and their phone would derive different keys and each
 * would decrypt nothing the other wrote.
 *
 * So the secret is a random 32 bytes generated once, and each enrolled
 * authenticator gets its own WRAP of it:
 *
 *     user_half   32 random bytes, generated in the browser, never sent anywhere
 *     wrap_i      AES-GCM(user_half) under HKDF(PRF_i(salt))
 *
 * Enrolling a second authenticator re-wraps the same secret. Losing one is a
 * revoked wrap, not a lost key. This is the same shape password managers use for
 * multi-device vault unlock, for the same reason.
 *
 * The wraps live on the firm's gateway, which is safe because they are inert
 * without the authenticator, and convenient because that is the one place every
 * device of the user already talks to.
 *
 * ## Why this cannot run in the Word taskpane
 *
 * The taskpane is a cross-origin iframe owned by Office, and WebAuthn requires
 * the embedding page to grant `publickey-credentials-get` through permissions
 * policy. Office does not, and we cannot make it: the iframe is not ours.
 *
 * So enrolment and unlock happen in a TOP-LEVEL context (a browser tab, the
 * desktop shell, or the Office Dialog popout the add-in already opens for other
 * flows), and the derived key is cached for the device as a non-extractable
 * CryptoKey. The taskpane reads that cache and never touches WebAuthn.
 *
 * Caching is not a weakening of the threat model this exists to fix. The passkey
 * defends against US and against whoever takes the gateway's database. It was
 * never defending against someone in possession of an unlocked device, which is
 * equally true of the server-fetched key it replaces.
 *
 * ## No server-side WebAuthn
 *
 * This is key derivation, not authentication. No assertion signature is
 * verified, no challenge is validated, no attestation is checked, and there is
 * no server-side WebAuthn library on either side. The gateway stores opaque
 * blobs it cannot open. `gateway/platform-ui/src/lib/recoveryKey.ts` makes the
 * same argument for the admin recovery file, and this module is a port of it.
 *
 * Deliberately dependency-free: this file is part of the key-handling surface
 * intended for the public audit repo, so it must not reach into the app.
 */

/** HKDF info for the wrapping key. Bumping this orphans every existing wrap. */
const PRF_INFO = 'ic-user-half-v3';
export const KEY_WRAP_VERSION = 1;
/** The user half is an AES-256 key's worth of entropy, like both other halves. */
export const USER_HALF_BYTES = 32;

/**
 * One authenticator's wrap of the user half.
 *
 * `credentialId` and `salt` are not secrets. `sealed` is not usable without the
 * authenticator named by `credentialId`, which is why the whole record can sit
 * in the gateway's database.
 */
export interface KeyWrap {
  /** Server-assigned. Absent on a wrap that has not been stored yet. */
  id?: string;
  version: number;
  /** base64url, as WebAuthn hands it to us. */
  credentialId: string;
  /** base64. The PRF salt; the output cannot be reproduced without it. */
  salt: string;
  /** base64(IV ‖ AES-GCM ciphertext) of the 32-byte user half. */
  sealed: string;
  /** Shown when revoking, e.g. "MacBook Touch ID". Never a secret. */
  label?: string;
  createdAt?: string;
}

const b64 = {
  enc: (b: Uint8Array) => btoa(String.fromCharCode(...b)),
  dec: (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
};
/** WebAuthn ids travel as base64url; convert for JSON storage and back. */
const b64url = {
  enc: (b: Uint8Array) => b64.enc(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s: string) => b64.dec(s.replace(/-/g, '+').replace(/_/g, '/')),
};

/** The slice of the WebAuthn PRF extension result this module reads. */
interface PrfExtensionResults {
  prf?: { results?: { first?: ArrayBuffer } };
}

/** Permissions Policy, which TypeScript's DOM lib does not yet describe. */
interface FeaturePolicyLike {
  allowsFeature(feature: string): boolean;
}

export type PrfCapability =
  /** WebAuthn is reachable. Whether the AUTHENTICATOR does PRF is only
   *  discoverable by asking it, so callers must still handle 'no-prf'. */
  | 'available'
  /** A frame that was not granted publickey-credentials-get. The Word taskpane
   *  is always this, and no amount of retrying changes it. */
  | 'blocked-in-frame'
  /** No WebAuthn at all, or an insecure context. */
  | 'unsupported';

/**
 * Whether a WebAuthn call can even be attempted here.
 *
 * The frame check matters because the failure mode without it is a bare
 * `NotAllowedError` from inside the Word taskpane, which reads to a user as
 * "my security key is broken" rather than "this has to happen in a window".
 */
export function prfCapability(): PrfCapability {
  if (typeof window === 'undefined'
    || !window.PublicKeyCredential
    || !navigator.credentials
    || !window.isSecureContext) {
    return 'unsupported';
  }
  // `parent !== self` rather than `top !== self`: identical for the question
  // being asked (am I inside ANY frame), and the property jsdom lets a test
  // redefine, so the taskpane case is actually covered rather than asserted.
  if (window.parent === window.self) return 'available';

  const doc = document as Document & {
    featurePolicy?: FeaturePolicyLike;
    permissionsPolicy?: FeaturePolicyLike;
  };
  const policy = doc.featurePolicy || doc.permissionsPolicy;
  if (policy?.allowsFeature) {
    try {
      return policy.allowsFeature('publickey-credentials-get') ? 'available' : 'blocked-in-frame';
    } catch { /* fall through to the conservative answer */ }
  }
  // No policy API to ask. Assume a nested document is restricted: being wrong
  // this way costs one unnecessary popout, and being wrong the other way hands
  // the user an opaque SecurityError at the moment they are trying to get set
  // up. Office desktop is exactly the browser without the policy API.
  return 'blocked-in-frame';
}

function prfOutput(cred: PublicKeyCredential | null): Uint8Array | null {
  const res = (cred?.getClientExtensionResults() as PrfExtensionResults)?.prf?.results?.first;
  return res ? new Uint8Array(res as ArrayBuffer) : null;
}

/** AES-GCM wrapping key from an authenticator's PRF output. */
async function wrapKeyFrom(prf: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', prf as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: new TextEncoder().encode(PRF_INFO) as BufferSource,
    },
    base,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Fresh user half. Generated here and nowhere else: no server ever sees it. */
export function generateUserHalf(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(USER_HALF_BYTES));
}

async function sealUnder(prf: Uint8Array, userHalf: Uint8Array): Promise<string> {
  const key = await wrapKeyFrom(prf);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, userHalf as BufferSource);
  const sealed = new Uint8Array(iv.length + ct.byteLength);
  sealed.set(iv);
  sealed.set(new Uint8Array(ct), iv.length);
  return b64.enc(sealed);
}

/** Ask a specific set of authenticators for the PRF output over `salt`. */
async function evaluatePrf(
  credentialIds: Uint8Array[],
  salt: Uint8Array,
  rpId: string,
): Promise<{ credentialId: Uint8Array; prf: Uint8Array } | null> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      allowCredentials: credentialIds.map(id => ({ type: 'public-key' as const, id: id as BufferSource })),
      userVerification: 'preferred',
      timeout: 120_000,
      extensions: { prf: { eval: { first: salt as BufferSource } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  const prf = prfOutput(assertion);
  if (!assertion || !prf) return null;
  return { credentialId: new Uint8Array(assertion.rawId), prf };
}

export type EnrollResult =
  | { status: 'ok'; wrap: KeyWrap; userHalf: Uint8Array }
  /** The authenticator works but has no PRF (older CTAP2, some platform keys). */
  | { status: 'no-prf' }
  | { status: 'blocked-in-frame' }
  | { status: 'unsupported' }
  | { status: 'failed'; reason: string };

/**
 * Enrol an authenticator against the user half, creating the half if this is
 * the first one.
 *
 * `existingHalf` is what makes a SECOND device work: pass the already-unlocked
 * half and this wraps that same secret under the new authenticator, so both can
 * open the same rows. Omit it only on genuine first enrolment, because
 * generating a new half when one already exists silently orphans everything
 * written under the old one.
 *
 * Two round trips on purpose. `create()` establishes the credential, then
 * `get()` obtains the PRF output, because evaluating PRF during creation is not
 * supported everywhere and a single flow that silently produced no secret on
 * some authenticators would be worse than one extra touch.
 */
export async function enrollAuthenticator(opts: {
  userName: string;
  rpId: string;
  /** The unlocked half, when adding an authenticator to an existing enrolment. */
  existingHalf?: Uint8Array;
  label?: string;
}): Promise<EnrollResult> {
  const cap = prfCapability();
  if (cap !== 'available') return { status: cap === 'unsupported' ? 'unsupported' : 'blocked-in-frame' };

  const salt = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  let created: PublicKeyCredential | null;
  try {
    created = (await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'InChambers Sync', id: opts.rpId },
        user: { id: userId, name: opts.userName, displayName: opts.userName },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        // 'preferred', not 'discouraged' as the recovery file uses: unlock has
        // to find this credential on a device that may hold no local record of
        // it, and a discoverable credential is what makes that possible.
        authenticatorSelection: { userVerification: 'preferred', residentKey: 'preferred' },
        timeout: 120_000,
        extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential | null;
  } catch (e: unknown) {
    return { status: 'failed', reason: friendly(e, 'The security key was not set up') };
  }
  if (!created) return { status: 'failed', reason: 'The security key was not set up.' };

  const credentialId = new Uint8Array(created.rawId);
  let evaluated: { credentialId: Uint8Array; prf: Uint8Array } | null;
  try {
    evaluated = await evaluatePrf([credentialId], salt, opts.rpId);
  } catch (e: unknown) {
    return { status: 'failed', reason: friendly(e, 'The security key was not read') };
  }
  if (!evaluated) return { status: 'no-prf' };

  const userHalf = opts.existingHalf ?? generateUserHalf();
  try {
    const sealed = await sealUnder(evaluated.prf, userHalf);
    return {
      status: 'ok',
      userHalf,
      wrap: {
        version: KEY_WRAP_VERSION,
        credentialId: b64url.enc(credentialId),
        salt: b64.enc(salt),
        sealed,
        label: opts.label,
      },
    };
  } finally {
    evaluated.prf.fill(0);
  }
}

export type UnlockResult =
  | { status: 'ok'; userHalf: Uint8Array }
  /** No wraps at all: this user has never enrolled anywhere. */
  | { status: 'not-enrolled' }
  /** Wraps exist, but none of the authenticators present could open one. */
  | { status: 'no-matching-authenticator' }
  | { status: 'blocked-in-frame' }
  | { status: 'unsupported' }
  | { status: 'failed'; reason: string };

/**
 * Recover the user half using whichever enrolled authenticator is to hand.
 *
 * Every credential is offered in ONE `get()` per distinct salt, so the normal
 * case (all wraps sharing a salt) is a single touch no matter how many devices
 * are enrolled. The browser picks whichever authenticator is actually present,
 * and `rawId` tells us which wrap to open.
 *
 * A wrap that fails to decrypt is skipped rather than fatal: it means that
 * record is damaged or stale, and another wrap may still work. Returning a
 * plausible-looking wrong answer is the one thing this must never do, and
 * AES-GCM's authentication is what guarantees it does not.
 */
export async function unlockUserHalf(wraps: KeyWrap[], rpId: string): Promise<UnlockResult> {
  if (!wraps.length) return { status: 'not-enrolled' };
  const cap = prfCapability();
  if (cap !== 'available') return { status: cap === 'unsupported' ? 'unsupported' : 'blocked-in-frame' };

  // Group by salt so the common case is one prompt. Different salts can only
  // arise from wraps created before a salt scheme change, and they still work,
  // just with one prompt per group.
  const bySalt = new Map<string, KeyWrap[]>();
  for (const w of wraps) {
    const group = bySalt.get(w.salt);
    if (group) group.push(w); else bySalt.set(w.salt, [w]);
  }

  for (const [saltB64, group] of bySalt) {
    let evaluated: { credentialId: Uint8Array; prf: Uint8Array } | null;
    try {
      evaluated = await evaluatePrf(
        group.map(w => b64url.dec(w.credentialId)),
        b64.dec(saltB64),
        rpId,
      );
    } catch (e: unknown) {
      // NotAllowedError also covers "the user cancelled", which is not an error
      // worth escalating past the next group.
      if (bySalt.size === 1) return { status: 'failed', reason: friendly(e, 'The security key was not read') };
      continue;
    }
    if (!evaluated) continue;

    const wantedId = b64url.enc(evaluated.credentialId);
    const wrap = group.find(w => w.credentialId === wantedId);
    try {
      if (!wrap) continue;
      const key = await wrapKeyFrom(evaluated.prf);
      const sealed = b64.dec(wrap.sealed);
      const half = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: sealed.slice(0, 12) },
        key,
        sealed.slice(12) as BufferSource,
      );
      return { status: 'ok', userHalf: new Uint8Array(half) };
    } catch {
      // Damaged or stale wrap. Try the next group rather than concluding the
      // user has lost their key.
      continue;
    } finally {
      evaluated.prf.fill(0);
    }
  }

  return { status: 'no-matching-authenticator' };
}

/**
 * Turn a DOMException into something an actual person can act on.
 *
 * The raw name ("NotAllowedError") is what the browser reports for a dismissed
 * prompt, a timeout, and a key that was never inserted, and it tells a user
 * nothing about which of those happened.
 */
function friendly(e: unknown, prefix: string): string {
  const name = (e as { name?: string })?.name || 'error';
  if (name === 'NotAllowedError') {
    return `${prefix}. The prompt was dismissed or timed out, or the security key was not present.`;
  }
  if (name === 'InvalidStateError') {
    return `${prefix}. This authenticator is already enrolled for this account.`;
  }
  if (name === 'SecurityError') {
    return `${prefix}. Security keys cannot be used on this page. Open InChambers in a browser window and try again.`;
  }
  return `${prefix} (${name}).`;
}

/**
 * base64 helpers, exported because the escrow path seals the same 32 bytes to
 * the firm's break-glass key and must agree on the encoding byte for byte.
 * Nothing else should reach for these.
 */
export const b64Codec = { encode: b64.enc, decode: b64.dec };
