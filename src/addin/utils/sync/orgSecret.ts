/**
 * The firm-wide secret behind shared content, and how a member comes to hold it.
 *
 * ## Why shared content cannot use the personal key
 *
 * Personal rows key on the user's own half, which is exactly right: nobody else
 * should read them. Shared content is the opposite requirement. A template one
 * lawyer publishes has to open for the whole firm, so keying it on anyone's
 * personal half would make it readable by its author alone. The v2 answer mixed
 * an inchambers-served org half with the gateway's, which worked and left us
 * holding a piece.
 *
 * ## The shape
 *
 *     org_secret     32 random bytes, generated in the FIRST member's browser
 *     member keypair P-256 ECDH, private half wrapped under that member's
 *                    passkey-held user half
 *     wrap_m         ECIES(org_secret) to member m's public key
 *
 *     org DEK = HKDF(org_secret || firm_org_half, salt = org_id,
 *                    info = "ic-sync-org-dek-v3")
 *
 * The gateway stores public keys, wrapped private keys and ECIES wraps. None of
 * those is openable without a member's passkey, so it distributes the firm's
 * shared key while being unable to read a byte of what that key protects.
 *
 * ## Why asymmetric, when everything else here is symmetric
 *
 * A new member has to be given the secret by someone who already holds it. With
 * symmetric wrapping both people must be online at once, which for a firm
 * onboarding a lawyer on a Monday morning is not a workable rule. Public keys
 * remove the rendezvous: any existing member can wrap for a newcomer who is
 * asleep, and the newcomer opens it when they next sign in.
 *
 * ## The failure this file is careful about
 *
 * Creating a SECOND org secret would split the firm in half: content written
 * under each would be unreadable by holders of the other, and neither would
 * error. So a secret is only ever created when the gateway positively reports
 * that no member holds one. Anything else, including a failed call, waits.
 */

import { sealTo, openSealed, eciesB64 } from './ecies';

const MEMBER_KEY_INFO = 'ic-member-key-v1';
const ORG_WRAP_INFO = 'ic-org-secret-v1';
const CURVE = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface MemberKeyPair {
  privateKey: CryptoKey;
  publicSpki: string;
}

export type OrgSecretResult =
  | { status: 'ok'; secret: Uint8Array; created: boolean }
  /** No wrap yet, and the firm already has a secret. A colleague must share it. */
  | { status: 'awaiting-colleague' }
  /** Could not establish state. Never treated as "no secret exists". */
  | { status: 'unavailable' };

/** AES key that protects this member's private key, from their own half. */
async function memberWrapKey(userHalf: Uint8Array, sub: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', userHalf as BufferSource, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(sub) as BufferSource,
      info: new TextEncoder().encode(MEMBER_KEY_INFO) as BufferSource,
    },
    base,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function wrapPrivateKey(privateKey: CryptoKey, wrapKey: CryptoKey): Promise<string> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, pkcs8 as BufferSource);
  pkcs8.fill(0);
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), iv.length);
  return eciesB64.encode(out);
}

async function unwrapPrivateKey(wrapped: string, wrapKey: CryptoKey): Promise<CryptoKey> {
  const raw = eciesB64.decode(wrapped);
  const pkcs8 = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.slice(0, 12) }, wrapKey, raw.slice(12) as BufferSource,
  );
  // Non-extractable on the way back in: it only ever needs to derive bits, and
  // a key that cannot be exported cannot be exfiltrated by injected script.
  return crypto.subtle.importKey('pkcs8', pkcs8, CURVE, false, ['deriveBits']);
}

/**
 * This member's keypair, recovered or created.
 *
 * The private half is stored on the gateway wrapped under the member's own
 * passkey-held secret, so a second device recovers it after unlocking rather
 * than generating a new one. Generating a new one would drop every org-secret
 * wrap addressed to the old public key, which the gateway handles correctly but
 * which costs the member a round trip through a colleague for no reason.
 */
export async function ensureMemberKey(
  stored: { publicSpki: string; wrappedPrivate: string } | null,
  userHalf: Uint8Array,
  sub: string,
  publish: (publicSpki: string, wrappedPrivate: string) => Promise<void>,
): Promise<MemberKeyPair> {
  const wrapKey = await memberWrapKey(userHalf, sub);
  if (stored) {
    try {
      return {
        privateKey: await unwrapPrivateKey(stored.wrappedPrivate, wrapKey),
        publicSpki: stored.publicSpki,
      };
    } catch {
      // The stored private key does not open under this half. That means the
      // half changed, which should be impossible, so replacing the keypair is
      // the only way forward -- and it is safe, because the gateway drops the
      // now-unopenable org wraps when the public key changes.
      console.warn('IC-ORG-MEMBERKEY-REPLACED', { sub });
    }
  }
  const pair = (await crypto.subtle.generateKey(CURVE, true, ['deriveBits'])) as CryptoKeyPair;
  const publicSpki = eciesB64.encode(new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey)));
  const wrappedPrivate = await wrapPrivateKey(pair.privateKey, wrapKey);
  await publish(publicSpki, wrappedPrivate);
  // Re-import non-extractable, so the in-memory handle cannot be exported even
  // though the one we just generated could be.
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  return {
    privateKey: await crypto.subtle.importKey('pkcs8', pkcs8, CURVE, false, ['deriveBits']),
    publicSpki,
  };
}

/**
 * Resolve the firm secret for this member.
 *
 * Creates one ONLY when the gateway positively reports that no member holds
 * one. A second secret would split the firm: content written under each would
 * be unreadable by holders of the other and nothing would error.
 */
export async function resolveOrgSecret(opts: {
  wrap: { sealed: string; generation: number } | null;
  established: boolean;
  memberKey: MemberKeyPair;
  publishWraps: (wraps: Array<{ ownerSub: string; sealed: string }>) => Promise<void>;
  selfSub: string;
}): Promise<OrgSecretResult> {
  if (opts.wrap) {
    try {
      const secret = await openSealed(opts.wrap.sealed, opts.memberKey.privateKey, ORG_WRAP_INFO);
      return { status: 'ok', secret, created: false };
    } catch {
      // A wrap that will not open is addressed to a key we no longer hold. It
      // is not evidence that the firm has no secret, so this must not fall
      // through to creating one.
      console.error('IC-ORG-SECRET-UNOPENABLE');
      return { status: 'awaiting-colleague' };
    }
  }
  if (opts.established) return { status: 'awaiting-colleague' };

  // Genuinely first: nobody in the firm holds a secret.
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const sealed = await sealTo(secret, opts.memberKey.publicSpki, ORG_WRAP_INFO);
  await opts.publishWraps([{ ownerSub: opts.selfSub, sealed }]);
  return { status: 'ok', secret, created: true };
}

/**
 * Share the secret with members who have a public key but no wrap.
 *
 * Any member holding the secret can do this. That is not a weakening: they
 * already have the plaintext, and nothing could stop them sharing it anyway.
 * What the gateway enforces is that a wrap can only be addressed to a public
 * key it has seen, so one cannot be planted for an identity that is not
 * really a member.
 */
export async function shareWithPendingMembers(
  secret: Uint8Array,
  pending: Array<{ ownerSub: string; publicSpki: string }>,
  publishWraps: (wraps: Array<{ ownerSub: string; sealed: string }>) => Promise<void>,
): Promise<number> {
  if (!pending.length) return 0;
  const wraps = await Promise.all(
    pending.map(async (m) => ({
      ownerSub: m.ownerSub,
      sealed: await sealTo(secret, m.publicSpki, ORG_WRAP_INFO),
    })),
  );
  await publishWraps(wraps);
  return wraps.length;
}
