/**
 * Evidence signing — the authorship half of a tamper-evident export.
 *
 * The manifest proves integrity: these are the bytes. A signature proves
 * authorship: this firm, or this user, produced them. The two are separable on
 * purpose, because integrity is always available and authorship is not.
 *
 * DUAL ANCHOR. Which key signs depends on which trust zone the user is in
 * (docs/architecture/privacy.mdx, "Three trust zones"):
 *
 *  - A firm with its own gateway signs with a FIRM key held on the firm's own
 *    box. The bundle then carries firm identity, which is what a court or an
 *    opposing party actually cares about, and the key survives a laptop being
 *    reimaged. Route: POST <firmGateway>/api/evidence/sign.
 *
 *  - Everyone else signs with a PER-USER DEVICE key. Ed25519, generated in
 *    WebCrypto, private half NON-EXTRACTABLE and never leaving the device — so
 *    unlike the reference implementation we compared against, inchambers cannot
 *    sign on a user's behalf even if it wanted to. Only the PUBLIC half is
 *    registered with inchambers, so a third party can fetch it and verify. A
 *    public key is not content, so this does not touch zero-knowledge.
 *
 * HONESTY RULE. Ed25519 in WebCrypto is not universally available (older WebKit
 * has no support, and Safari only gained it in 17). When we cannot sign we say
 * so and emit an unsigned bundle. We never emit a bundle that claims a signature
 * it does not have, and we never silently downgrade to a weaker algorithm.
 */

import { apiUrl } from '../apiConfig';
import { evidenceHost } from './hostBindings';

/** How a bundle was signed, or why it was not. */
export type SignatureAnchor = 'firm-gateway' | 'user-device' | 'unsigned';

export interface EvidenceSignature {
  /**
   * Narrower than `SignatureAnchor` on purpose: a SIGNATURE cannot be unsigned.
   *
   * This was the full alias, which meant `EvidenceSignature | UnsignedResult` was
   * not a discriminated union, so `anchor === 'unsigned'` narrowed nothing and a
   * value could claim to be a signature that was not signed. `SignatureAnchor`
   * keeps all three for callers that describe an OUTCOME.
   */
  anchor: Exclude<SignatureAnchor, 'unsigned'>;
  algorithm: 'Ed25519';
  /** Base64 signature over the ASCII bytes of the manifest's `rootSha256`. */
  signature: string;
  /** Identifier a verifier resolves to a public key. */
  keyId: string;
  /**
   * Where the public key can be fetched. For a firm key this is the firm's own
   * gateway; for a device key it is inchambers.
   */
  publicKeyUrl: string;
  /** Base64 SPKI of the public key, inlined so offline verification works too. */
  publicKeySpki: string;
  signedAt: number;
  /**
   * Which bytes the signature covers.
   *
   * 2: `${rootSha256}\n${signedAt}`. 1: the root alone, which left `signedAt`
   * editable beside the signature, so a bundle holder could move a signature to
   * either side of a revocation date. A firm gateway older than this change does
   * not return a timestamp, and a bundle it signs is recorded as 1 rather than
   * claiming a protection it does not have.
   */
  formatVersion: 1 | 2;
  /**
   * Whose clock produced `signedAt`. A firm gateway attests it server-side, which
   * the signer does not control; a device asserts its own, which it does.
   */
  timeSource: 'firm-gateway' | 'signing-device';
  /**
   * Set when a firm key was EXPECTED and a device key was used instead.
   *
   * Without this the downgrade is invisible: the bundle says "signed with your
   * device key" and a firm whose gateway key is misconfigured reads that as normal,
   * because it looks identical to a firm that never configured one.
   */
  downgradedFrom?: { expected: 'firm-gateway'; detail: string };
  /** Display-only. Never treat as proof; the key is the proof. */
  signerLabel?: string;
}

/** Why signing was skipped, surfaced to the user rather than swallowed. */
export interface UnsignedResult {
  anchor: 'unsigned';
  reason:
    | 'ed25519-unsupported'
    | 'no-session'
    | 'key-registration-failed'
    | 'gateway-refused'
    /** The caller asked for an unsigned bundle. Not a failure. */
    | 'skipped-by-request'
    /** The stored device public key is not a usable Ed25519 SPKI. */
    | 'local-key-invalid'
    | 'signing-failed';
  detail?: string;
}

export type SignOutcome = EvidenceSignature | UnsignedResult;

const DEVICE_KEY_ENTRY = 'evidence_signing_key_v1';
const DEVICE_KEYID_ENTRY = 'evidence_signing_keyid_v1';

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/**
 * Is Ed25519 usable here? Feature-detected by actually generating a key, because
 * some engines expose the algorithm name but reject it at generate time, and a
 * capability we only discover at signing time is a capability we cannot warn
 * about. Cached for the session: generation is not free.
 */
let ed25519Supported: boolean | null = null;
export async function isEd25519Available(): Promise<boolean> {
  if (ed25519Supported === true) return true;
  try {
    const probe = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    ed25519Supported = !!(probe as CryptoKeyPair).privateKey;
    return ed25519Supported;
  } catch {
    // NOT cached. A negative used to be remembered for the session, so one
    // transient failure (a locked keystore, a momentary out-of-memory) disabled
    // signing until the tab was reloaded, and reported it as "this browser does
    // not support Ed25519", which was a lie about the browser.
    return false;
  }
}

/**
 * The exact bytes a format-2 signature covers.
 *
 * One definition, used by signing and by verification, because a mismatch between
 * the two would make every signature we produce fail our own check, and the
 * published `openssl` procedure has to reproduce this byte for byte.
 */
export function signedMaterial(rootSha256: string, signedAt: number): ArrayBuffer {
  const bytes = new TextEncoder().encode(`${rootSha256}\n${signedAt}`);
  // Returned as a plain ArrayBuffer: under newer lib.dom typings a
  // `Uint8Array<ArrayBufferLike>` is not assignable to `BufferSource`, and
  // widening at the call sites would hide that from the next caller.
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// ─── Device key (no firm gateway) ────────────────────────────────────────────

interface DeviceKey {
  keyId: string;
  privateKey: CryptoKey;
  publicKeySpki: string;
}

/**
 * Load this device's signing key, generating and registering it on first use.
 *
 * The keypair is generated with `extractable: false`, so the private half cannot
 * be read back out of IndexedDB even by script running on our own origin. This
 * is the same protection the AES content key relies on (privacy.mdx, "At rest,
 * client-side"), and it means a signature is evidence that the holder of that
 * device produced the bundle.
 */
async function loadOrCreateDeviceKey(): Promise<DeviceKey> {
  const existingKey = (await evidenceHost().store.get(DEVICE_KEY_ENTRY)) as
    | CryptoKeyPair
    | null;
  const existingId = (await evidenceHost().store.get(DEVICE_KEYID_ENTRY)) as
    | { keyId: string; publicKeySpki: string }
    | null;

  if (existingKey?.privateKey && existingId?.keyId) {
    // The stored public half used to be trusted unchecked. A corrupt entry then
    // produced a bundle that verified against nothing, and the failure surfaced as
    // a broken firm gateway (the self-verify step rewrote the reason), so the one
    // cause nobody could diagnose was the real one.
    if (!(await isUsableSpki(existingId.publicKeySpki))) {
      throw new Error('local key invalid');
    }
    // Ask the server whether this key is still the active one. A revoked key can
    // still sign (the private half is non-extractable and cannot be reached, let
    // alone deleted, remotely), so the only way revocation changes behaviour is if
    // an honest client stops using it. Best-effort: offline keeps signing, and a
    // verifier can still detect it from `revokedAt` against the signed timestamp.
    if (await isKeyRevoked(existingId.keyId)) {
      return await registerFreshDeviceKey();
    }
    return {
      keyId: existingId.keyId,
      privateKey: existingKey.privateKey,
      publicKeySpki: existingId.publicKeySpki,
    };
  }

  return await registerFreshDeviceKey();
}

/**
 * Is this base64 a public key WebCrypto will actually accept?
 *
 * Structural checks alone (length, DER prefix) would pass a string that
 * `importKey` then rejects, and the point is to find that out before signing
 * rather than after shipping the bundle. The server has its own validator
 * (`api/_lib/ed25519Spki.ts`) using Node's `createPublicKey`; the two cannot share
 * an implementation because the primitives differ, so both are tested separately.
 */
async function isUsableSpki(spki: string | undefined): Promise<boolean> {
  if (!spki) return false;
  try {
    const raw = Uint8Array.from(atob(spki), c => c.charCodeAt(0));
    await crypto.subtle.importKey('spki', raw, { name: 'Ed25519' }, false, ['verify']);
    return true;
  } catch {
    return false;
  }
}

/**
 * Has the server retired this key? `false` when we cannot tell.
 *
 * Silence is treated as "not revoked" deliberately: refusing to sign because the
 * network is down would make evidence export depend on connectivity it does not
 * otherwise need, and the verifier retains the ability to detect the case.
 */
async function isKeyRevoked(keyId: string): Promise<boolean> {
  try {
    const token = evidenceHost().accessToken();
    if (!token) return false;
    const res = await fetch(apiUrl('/api/user/signing-key'), {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) return false;
    const data = await res.json();
    const active = data?.keyId ?? data?.key_id ?? null;
    const revokedAt = data?.revokedAt ?? data?.revoked_at ?? null;
    // Either the server has no active key, or its active key is a different one:
    // both mean this device's key has been retired.
    if (active === null) return true;
    if (active !== keyId) return true;
    return revokedAt !== null;
  } catch {
    return false;
  }
}

/** Generate, register and store a new device key. */
async function registerFreshDeviceKey(): Promise<DeviceKey> {

  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const spki = toBase64(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)));

  // Register the PUBLIC half so a third party can verify without us handing them
  // anything private. Registration is authoritative: the server assigns the key
  // id, so two devices cannot collide and we cannot mint ids offline.
  const keyId = await registerPublicKey(spki);

  // Store the whole pair. The private CryptoKey is non-extractable, so what
  // lands in IndexedDB is an opaque handle, not key material.
  await evidenceHost().store.set(DEVICE_KEY_ENTRY, pair);
  await evidenceHost().store.set(DEVICE_KEYID_ENTRY, { keyId, publicKeySpki: spki });

  return { keyId, privateKey: pair.privateKey, publicKeySpki: spki };
}

async function registerPublicKey(publicKeySpki: string): Promise<string> {
  const token = evidenceHost().accessToken();
  if (!token) throw new Error('no session');
  const res = await fetch(apiUrl('/api/user/signing-key'), {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKeySpki, algorithm: 'Ed25519' }),
  });
  if (!res.ok) throw new Error(`signing key registration failed: ${res.status}`);
  const data = await res.json();
  if (!data?.keyId) throw new Error('signing key registration returned no keyId');
  return data.keyId as string;
}

// ─── Firm gateway key ────────────────────────────────────────────────────────

/**
 * Ask the firm's own gateway to sign. Firm-only by construction: the route is
 * compiled out of the platform gateway binary, and `getFirmGatewayUrl()` never
 * returns the platform URL, so a personal-domain user cannot reach it even by
 * accident.
 */
async function signViaFirmGateway(
  gatewayUrl: string,
  rootSha256: string,
): Promise<EvidenceSignature | UnsignedResult> {
  const token = evidenceHost().accessToken();
  if (!token) return { anchor: 'unsigned', reason: 'no-session' };
  try {
    const res = await fetch(`${gatewayUrl}/api/evidence/sign`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ root_sha256: rootSha256 }),
    });
    if (!res.ok) {
      return {
        anchor: 'unsigned',
        reason: 'gateway-refused',
        detail: `gateway responded ${res.status}`,
      };
    }
    const data = await res.json();
    if (!data?.signature || !data?.key_id || !data?.public_key_spki) {
      return { anchor: 'unsigned', reason: 'gateway-refused', detail: 'incomplete response' };
    }
    // VERSION NEGOTIATION, off the gateway's own answer rather than an assumption.
    // A gateway that predates format 2 returns no `signed_at`; claiming v2 for its
    // signature would publish a verification procedure that cannot succeed.
    const gatewaySignedAt =
      typeof data.signed_at === 'number' && Number.isFinite(data.signed_at)
        ? data.signed_at
        : null;
    return {
      anchor: 'firm-gateway',
      algorithm: 'Ed25519',
      signature: data.signature,
      keyId: data.key_id,
      publicKeyUrl: `${gatewayUrl}/api/evidence/pubkey?key_id=${encodeURIComponent(data.key_id)}`,
      publicKeySpki: data.public_key_spki,
      // The gateway's clock when it has one, because the signer cannot choose it.
      signedAt: gatewaySignedAt ?? Date.now(),
      formatVersion: gatewaySignedAt === null ? 1 : 2,
      timeSource: gatewaySignedAt === null ? 'signing-device' : 'firm-gateway',
      signerLabel: data.signer_label || undefined,
    };
  } catch (err) {
    return {
      anchor: 'unsigned',
      reason: 'gateway-refused',
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * The key id this device currently holds, or null.
 *
 * Exposed so the settings surface can show and revoke the key without knowing the
 * storage entry names, which are an implementation detail of this module.
 */
export async function getDeviceKeyId(): Promise<string | null> {
  try {
    const entry = (await evidenceHost().store.get(DEVICE_KEYID_ENTRY)) as
      | { keyId?: string }
      | null;
    return entry?.keyId ?? null;
  } catch {
    return null;
  }
}

/**
 * Forget this device's signing key, so the next export registers a fresh one.
 *
 * Called after a successful server-side revoke. The pre-sign check would also
 * notice the revocation and rotate, but that depends on a network round trip, and a
 * user who has just revoked a key should not have it sign one more bundle because
 * they happened to be offline. Removes only OUR entries; the private key is
 * non-extractable and was never ours to hand out, which is the honest limit here.
 */
export async function forgetDeviceKey(): Promise<void> {
  await evidenceHost().store.remove(DEVICE_KEY_ENTRY);
  await evidenceHost().store.remove(DEVICE_KEYID_ENTRY);
}

// ─── Public entry point ──────────────────────────────────────────────────────

/**
 * Sign a manifest root, choosing the anchor from the caller's trust zone.
 *
 * Never throws. A bundle that cannot be signed is still a useful bundle (the
 * digests stand on their own), so every failure path returns an `UnsignedResult`
 * carrying the reason for the UI to show, rather than losing the export.
 *
 * What is signed is the ASCII of the hex root digest, not the manifest JSON.
 * That keeps the signed material short, canonical, and independent of JSON
 * formatting, and because the root covers every entry it transitively covers
 * every document byte.
 */
export async function signManifestRoot(rootSha256: string): Promise<SignOutcome> {
  // Firm gateway FIRST, before the local Ed25519 probe.
  //
  // The probe used to gate this, so a browser that cannot do Ed25519 locally was
  // denied gateway signing, which is done server-side and needs no local Ed25519
  // at all. Firm identity also beats device identity, and it keeps the key on
  // infrastructure the firm controls.
  let firmGateway: string | null = null;
  try {
    firmGateway = await evidenceHost().firmGatewayUrl();
  } catch {
    firmGateway = null;
  }

  // Records that a firm key was expected, so a device-signed bundle can say the
  // firm key was not used and why, instead of looking like a firm that never had
  // one. This is the difference a misconfigured gateway key hid.
  let firmDowngrade: { expected: 'firm-gateway'; detail: string } | null = null;

  if (firmGateway) {
    const viaFirm = await signViaFirmGateway(firmGateway, rootSha256);
    // A firm whose gateway has no signing key configured should still get a
    // usable bundle, so fall through to the device key rather than failing.
    if (viaFirm.anchor === 'firm-gateway') return viaFirm;
    // Narrowed in its own statement: inside an object literal the compiler does
    // not apply the discriminant check.
    const why = viaFirm.anchor === 'unsigned' ? viaFirm.detail : undefined;
    firmDowngrade = { expected: 'firm-gateway', detail: why || 'the firm gateway did not sign' };
  }

  if (!(await isEd25519Available())) {
    return {
      anchor: 'unsigned',
      reason: 'ed25519-unsupported',
      detail: firmDowngrade?.detail,
    };
  }

  let key: DeviceKey;
  try {
    key = await loadOrCreateDeviceKey();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      anchor: 'unsigned',
      reason: msg === 'no session' ? 'no-session' : 'key-registration-failed',
      detail: msg,
    };
  }

  try {
    // Fixed before signing, because it is part of what gets signed.
    const signedAt = Date.now();
    const sig = await crypto.subtle.sign(
      { name: 'Ed25519' },
      key.privateKey,
      signedMaterial(rootSha256, signedAt),
    );
    let label: string | undefined;
    try {
      label = (await evidenceHost().session())?.user?.email || undefined;
    } catch {
      /* label is cosmetic */
    }
    return {
      anchor: 'user-device',
      algorithm: 'Ed25519',
      signature: toBase64(new Uint8Array(sig)),
      keyId: key.keyId,
      publicKeyUrl: apiUrl(`/api/public/signing-key/${encodeURIComponent(key.keyId)}`),
      publicKeySpki: key.publicKeySpki,
      signedAt,
      formatVersion: 2,
      // A device asserts its own clock. Signed, so it cannot be altered afterwards,
      // but the device chose it, and the bundle must not imply otherwise.
      timeSource: 'signing-device',
      downgradedFrom: firmDowngrade ?? undefined,
      signerLabel: label,
    };
  } catch (err) {
    return {
      anchor: 'unsigned',
      reason: 'signing-failed',
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Verify a signature locally against the public key inlined in the bundle.
 *
 * Note what this does and does not establish. It proves the signature matches
 * the root and the inlined key. It does NOT establish that the key belongs to
 * the claimed signer — for that a verifier must fetch `publicKeyUrl` and compare
 * the SPKI. The distinction is spelled out in VERIFY.md so nobody mistakes a
 * green tick here for proof of authorship.
 */
export async function verifySignatureLocally(
  sig: EvidenceSignature,
  rootSha256: string,
): Promise<boolean> {
  try {
    const spki = Uint8Array.from(atob(sig.publicKeySpki), c => c.charCodeAt(0));
    const pub = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
    const raw = Uint8Array.from(atob(sig.signature), c => c.charCodeAt(0));
    // Must match what was signed, per format. Verifying v2 against the root alone
    // would fail every signature we produce, and the caller reacts to a failed
    // self-check by downgrading the bundle to unsigned, so the whole feature would
    // quietly stop signing while reporting a signing failure.
    const material =
      (sig.formatVersion ?? 1) === 2
        ? signedMaterial(rootSha256, sig.signedAt)
        : (new TextEncoder().encode(rootSha256).buffer as ArrayBuffer);
    return await crypto.subtle.verify({ name: 'Ed25519' }, pub, raw, material);
  } catch {
    return false;
  }
}
