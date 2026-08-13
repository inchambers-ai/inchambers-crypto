/**
 * Content encryption for Drive-backed storage (solo practitioners).
 *
 * A solo practitioner's Clients, Matters, Docket, Timesheets and Intake records
 * live in their own OneDrive or Google Drive, encrypted here before they are
 * written.
 *
 *     dcv2 = HKDF(user_half, salt = user id, info = "ic-drive-dek-v2")
 *
 * `user_half` comes from the user's own passkey and never leaves their devices
 * unwrapped. There is no second half, deliberately: a solo user has no firm
 * gateway to be the other party, and manufacturing one from an identifier we
 * already store would be worse than useless.
 *
 * `dcv1` is GONE. It fetched the whole key from `/api/user/sync-key`, which we
 * derived from a server secret, so we could read every solo user's entire
 * practice on demand. It is deleted rather than kept readable because no
 * production data was ever written under it, and keeping the read path would
 * have meant keeping the server secret alive.
 *
 * THE CONSEQUENCE IS A HARD REQUIREMENT: a user who has not enrolled a security
 * key cannot use Drive-backed storage. `ensureKey` throws a message that says
 * so, rather than failing obscurely, because that is the only honest outcome
 * once the weaker key no longer exists.
 */

import { apiUrl } from '../apiConfig';
import { readCachedKey, writeCachedKey } from '../sync/deviceKeyCache';
import { authToken } from '../sync/tokenProvider';

const DRIVE_PAYLOAD_PREFIX_V2 = 'dcv2:';

/** The passkey-derived key. Held in memory only. */
let driveKeyV2: CryptoKey | null = null;
let v2Loading: Promise<CryptoKey | null> | null = null;
/**
 * Whether the attempt has already been made and failed.
 *
 * Without this, a null result is retried on EVERY read and write: a
 * `/api/user/key-wraps` round trip per Drive operation, and a fresh
 * security-key prompt for a user who dismissed the last one. Solo
 * practice-management modules write often enough for that to be a modal storm.
 * `clearContentKey()` resets it, which is what enrolment calls.
 */
let v2Attempted = false;

export function clearContentKey(): void {
  driveKeyV2 = null;
  v2Loading = null;
  v2Attempted = false;
}

/** Read the `sub` the wraps were enrolled against, from the session JWT. */
function subFromToken(token: string): string {
  try {
    const payload = token.split('.')[1];
    if (!payload) return '';
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return String(claims?.sub || '');
  } catch {
    return '';
  }
}

/**
 * Derive the passkey-held Drive key, or report that we cannot.
 *
 * Returns null rather than throwing so the CALLER decides what to do, and the
 * two callers decide differently: the write path turns null into a thrown
 * error, because there is no weaker envelope to fall back to any more.
 *
 * This comment used to say `dcv1:` still works for a user who has not
 * enrolled. That has been false since dcv1 was deleted with SYNC_DEK_SECRET.
 * There is exactly one Drive generation now, and no enrolment means no
 * Drive-backed storage at all.
 */
async function ensureV2Key(): Promise<CryptoKey | null> {
  if (driveKeyV2) return driveKeyV2;
  if (v2Loading) return v2Loading;
  if (v2Attempted) return null;
  v2Loading = (async () => {
    try {
      const token = await authToken();
      if (!token) return null;
      const sub = subFromToken(token);
      if (!sub) return null;

      const cacheName = `drive_dek_v2:${sub}`;
      const cached = await readCachedKey(cacheName);
      if (cached) return cached;

      const { prfCapability, unlockUserHalf } = await import('../sync/passkeyHalf');
      // The Word taskpane cannot reach an authenticator at all, and the desktop
      // Drive path runs there. A blocked frame with no cached key is not a
      // failure to report, it is a user who has to unlock in a window first.
      if (prfCapability() !== 'available') return null;

      const res = await fetch(apiUrl('/api/user/key-wraps'), {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) return null;
      const data = await res.json();
      if (!Array.isArray(data?.wraps) || !data.wraps.length) return null;

      const rpId = typeof window !== 'undefined' ? window.location.hostname : '';
      const unlocked = await unlockUserHalf(data.wraps, rpId);
      if (unlocked.status !== 'ok') return null;

      const base = await crypto.subtle.importKey(
        'raw', unlocked.userHalf as BufferSource, 'HKDF', false, ['deriveBits'],
      );
      const bits = await crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: new TextEncoder().encode(sub) as BufferSource,
          info: new TextEncoder().encode('ic-drive-dek-v2') as BufferSource,
        },
        base,
        256,
      );
      unlocked.userHalf.fill(0);
      const key = await crypto.subtle.importKey(
        'raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
      );
      await writeCachedKey(cacheName, key);
      return key;
    } catch {
      return null;
    } finally {
      v2Loading = null;
      v2Attempted = true;
    }
  })();
  const k = await v2Loading;
  driveKeyV2 = k;
  return k;
}

/**
 * Can this device encrypt Drive content at all?
 *
 * Deliberately routed through `ensureV2Key`, the very function the write path
 * calls, rather than re-deriving the answer from the passkey layer. A gate that
 * probed independently could say yes while `encryptForDrive` says no, and the
 * user would meet a thrown error after doing the work, which is the failure the
 * gate exists to prevent.
 */
export async function hasDriveKey(): Promise<boolean> {
  return (await ensureV2Key()) !== null;
}

export async function encryptForDrive(plaintext: string): Promise<string> {
  // The only key there is. It comes from the user's own authenticator, so
  // there is no longer a branch here where inchambers could read the record.
  const key = await ensureV2Key();
  if (!key) {
    // The only honest outcome now that the weaker key is gone. Throwing with a
    // message the UI can show beats writing something we could read.
    throw new Error(
      'No security key is set up on this device, so records cannot be encrypted. '
      + 'Open InChambers in a browser window and set one up under Settings.',
    );
  }
  return sealWith(key, DRIVE_PAYLOAD_PREFIX_V2, plaintext);
}

function sealWith(key: CryptoKey, prefix: string, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle
    .encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext))
    .then((ct) => {
      const combined = new Uint8Array(iv.length + ct.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(ct), iv.length);
      let binary = '';
      const CHUNK = 8192;
      for (let i = 0; i < combined.length; i += CHUNK) {
        binary += String.fromCharCode.apply(
          null,
          combined.subarray(i, Math.min(i + CHUNK, combined.length)) as unknown as number[],
        );
      }
      return prefix + btoa(binary);
    });
}

export async function decryptFromDrive(ciphertext: string): Promise<string> {
  // Dispatch on the envelope the row ARRIVED in, never on what this device
  // would write. Only dcv2 is recognised: dcv1 rows are not readable by
  // anyone, including us, and were wiped as part of the v3 deploy rather than
  // silently failing here.
  if (!ciphertext.startsWith(DRIVE_PAYLOAD_PREFIX_V2)) {
    throw new Error('unrecognized drive payload');
  }
  const prefix = DRIVE_PAYLOAD_PREFIX_V2;
  const key = await ensureV2Key();
  if (!key) {
    // Throwing, not returning null: the caller reads `data` straight into the
    // record store, and a device that simply cannot unlock yet must pause
    // rather than present an empty matter as though it were an empty matter.
    throw new Error('drive content key not available: this device is not unlocked');
  }
  const raw = Uint8Array.from(atob(ciphertext.slice(prefix.length)), c => c.charCodeAt(0));
  const iv = raw.slice(0, 12);
  const data = raw.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(pt);
}
