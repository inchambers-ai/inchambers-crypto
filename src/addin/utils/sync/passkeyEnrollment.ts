/**
 * Enrolling an authenticator against the user's half of the encryption key.
 *
 * ## The rule this file exists to enforce
 *
 * NEVER MINT A SECOND HALF FOR A USER WHO ALREADY HAS ONE. Doing so is silent
 * and irreversible: the new half derives a different key, everything written
 * under the old one becomes unreadable, and nothing surfaces an error because
 * both halves are perfectly valid. Every path here therefore establishes the
 * existing half FIRST and only generates one when the store says there is
 * genuinely nothing enrolled.
 *
 * That is also why `fetchKeyWraps` distinguishes a failed call from an empty
 * one. "The gateway did not answer" must never be read as "this user has
 * enrolled nothing", because the two lead to opposite and unequal actions.
 *
 * ## Two stores, one shape
 *
 * A user with a firm gateway keeps their wraps there. A solo practitioner has
 * no gateway, so theirs sit on the inchambers backend. Both are inert without
 * the authenticator, so neither holder can open them, and the only real
 * difference is the URL. `WrapStore` is that difference.
 *
 * ## Break-glass escrow
 *
 * Firm users also seal their half to the firm's escrow public key, so a partner
 * who loses every authenticator is a support call rather than a lost practice.
 * The private half of that key was generated in an admin's browser and never
 * sent to the gateway, so a stolen database cannot open the escrow copies.
 *
 * Solo users have nobody to escrow to. They are told, once, plainly: their
 * security keys are the only way in. Inventing an escrow we hold would be
 * exactly the custody this whole exercise removes.
 */

import {
  enrollAuthenticator, unlockUserHalf, prfCapability, generateUserHalf,
  type KeyWrap,
} from './passkeyHalf';
import { sealTo, fingerprintSpki } from './ecies';

/**
 * Domain separation for the escrow envelope. Shared content uses a different
 * label through the same primitive, so an escrow blob can never be opened as an
 * org-secret wrap even by a holder of both keys.
 */
const ESCROW_INFO = 'ic-half-escrow-v1';

export type EnrollOutcome =
  | { status: 'enrolled'; wrapId: string; first: boolean }
  /** Word taskpane. The answer is a popout, not a retry. */
  | { status: 'blocked-in-frame' }
  | { status: 'unsupported' }
  /** The authenticator works but has no PRF, so it cannot hold a key. */
  | { status: 'no-prf' }
  /**
   * Wraps exist but this device could not open one, so we cannot re-wrap the
   * SAME half. Enrolling anyway would orphan everything already synced, so it
   * is refused and the user is asked for a key they already have.
   */
  | { status: 'needs-existing-authenticator' }
  | { status: 'failed'; reason: string };

/** Where a given user's wraps live. The only difference between the two paths. */
export interface WrapStore {
  list(): Promise<
    | {
        status: 'ok';
        wraps: KeyWrap[];
        escrowKey?: { publicSpki: string; fingerprint: string } | null;
        /** Which escrow key this user's half is already sealed to, if any. */
        escrowedFingerprint?: string | null;
      }
    | { status: 'unsupported' }
    | { status: 'error' }
  >;
  store(wrap: KeyWrap, escrow?: { sealed: string; fingerprint: string }): Promise<{ id: string }>;
}

/**
 * Seal the half to the firm's break-glass public key.
 *
 * Ephemeral-static ECDH over P-256, HKDF to an AES-GCM key, and the ephemeral
 * public key carried alongside the ciphertext so the holder of the private key
 * can reconstruct the shared secret. WebCrypto implements every piece, which is
 * what allows the keypair to be generated in an admin's browser and the private
 * half never to reach the gateway.
 */
export function sealToEscrowKey(
  userHalf: Uint8Array,
  publicSpkiB64: string,
): Promise<string> {
  return sealTo(userHalf, publicSpkiB64, ESCROW_INFO);
}

/** SHA-256 of the SPKI, so a blob records which escrow key it needs. */
export function escrowFingerprint(publicSpkiB64: string): Promise<string> {
  return fingerprintSpki(publicSpkiB64);
}

/**
 * Enrol this device's authenticator, creating the user's half only if they
 * genuinely have none.
 *
 * Returns the half so the caller can derive keys from it immediately; the
 * caller is responsible for zeroing it. Nothing here writes it anywhere except
 * as a wrap.
 */
export async function enrollDevice(opts: {
  store: WrapStore;
  userName: string;
  label?: string;
  /** Called with the half once established, before this returns. */
  onHalf: (half: Uint8Array) => Promise<void>;
}): Promise<EnrollOutcome> {
  const cap = prfCapability();
  if (cap === 'unsupported') return { status: 'unsupported' };
  if (cap === 'blocked-in-frame') return { status: 'blocked-in-frame' };

  const listed = await opts.store.list();
  if (listed.status === 'unsupported') {
    // Nowhere to put a wrap. Enrolling would produce a half that vanishes with
    // the tab, so this is not a partial success.
    return { status: 'failed', reason: 'This gateway does not support security keys yet.' };
  }
  if (listed.status === 'error') {
    // THE DANGEROUS CASE. Treating an unreachable store as "no wraps" would
    // mint a second half and orphan everything already encrypted.
    return {
      status: 'failed',
      reason: 'Could not check your existing security keys, so enrolling now could lock you out of your own records. Try again in a moment.',
    };
  }

  const rpId = typeof window !== 'undefined' ? window.location.hostname : '';
  let existingHalf: Uint8Array | undefined;
  const first = listed.wraps.length === 0;

  if (!first) {
    const unlocked = await unlockUserHalf(listed.wraps, rpId);
    if (unlocked.status !== 'ok') {
      // Refuse rather than mint. The user has a key somewhere; asking for it is
      // an inconvenience, and the alternative is silent, permanent data loss.
      return { status: 'needs-existing-authenticator' };
    }
    existingHalf = unlocked.userHalf;
  }

  const enrolled = await enrollAuthenticator({
    userName: opts.userName,
    rpId,
    existingHalf,
    label: opts.label,
  });
  if (enrolled.status !== 'ok') {
    existingHalf?.fill(0);
    return enrolled.status === 'failed'
      ? { status: 'failed', reason: enrolled.reason }
      : { status: enrolled.status };
  }

  try {
    let escrow: { sealed: string; fingerprint: string } | undefined;
    const escrowKey = listed.escrowKey;
    if (first && escrowKey) {
      escrow = {
        sealed: await sealToEscrowKey(enrolled.userHalf, escrowKey.publicSpki),
        fingerprint: escrowKey.fingerprint,
      };
    }
    const { id } = await opts.store.store(enrolled.wrap, escrow);
    await opts.onHalf(enrolled.userHalf);
    return { status: 'enrolled', wrapId: id, first };
  } catch (e: unknown) {
    return {
      status: 'failed',
      reason: (e as Error)?.message || 'The security key was set up but could not be saved. Try again.',
    };
  } finally {
    enrolled.userHalf.fill(0);
    existingHalf?.fill(0);
  }
}

/** Exposed so a first-run flow can show what it is about to create. */
export { generateUserHalf };
