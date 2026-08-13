/**
 * Sealing a small secret to someone's public key.
 *
 * Used twice, for the same reason both times: a secret has to reach a holder
 * who is not present. The firm's break-glass escrow seals a user's half to a
 * key whose private half is offline in a recovery bundle. Shared content seals
 * the firm secret to a colleague who may be asleep. Neither can wait for a
 * rendezvous, which is what rules out the symmetric wrapping used everywhere
 * else in this layer.
 *
 * Ephemeral-static ECDH over P-256, HKDF-SHA256 to an AES-GCM key, ephemeral
 * public key carried alongside the ciphertext. Every piece is in WebCrypto on
 * every browser we support, which is what allows the keypairs to be generated
 * in a browser and the private halves never to reach a server.
 *
 *     sealed = b64( len(ephSPKI) as u16 be || ephSPKI || IV(12) || AES-GCM ct )
 *
 * The length prefix is not decoration. P-256 SPKI is a fixed 91 bytes today, and
 * a reader that assumes so would break silently rather than loudly the day a
 * different curve appears. These blobs are meant to be openable years from now
 * by code that does not exist yet.
 *
 * Deliberately dependency-free: part of the surface intended for the public
 * audit repo.
 */

const CURVE = { name: 'ECDH', namedCurve: 'P-256' } as const;

function b64encode(bytes: Uint8Array): string {
  let binary = '';
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, Math.min(i + CHUNK, bytes.length)) as unknown as number[],
    );
  }
  return btoa(binary);
}

function b64decode(text: string): Uint8Array {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}

/**
 * The AES key both sides reach: one from (ephemeral private, static public),
 * the other from (ephemeral public, static private). `info` domain-separates
 * the two uses so an escrow blob can never be opened as an org-secret wrap.
 */
async function sharedKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  info: string,
  usage: KeyUsage[],
): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: new TextEncoder().encode(info) as BufferSource,
    },
    base,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, usage);
}

/** Seal `plaintext` to a P-256 public key given as base64 SPKI. */
export async function sealTo(
  plaintext: Uint8Array,
  publicSpkiB64: string,
  info: string,
): Promise<string> {
  const recipient = await crypto.subtle.importKey(
    'spki', b64decode(publicSpkiB64) as BufferSource, CURVE, false, [],
  );
  const ephemeral = (await crypto.subtle.generateKey(CURVE, true, ['deriveBits'])) as CryptoKeyPair;
  const key = await sharedKey(ephemeral.privateKey, recipient, info, ['encrypt']);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext as BufferSource);
  const ephPub = new Uint8Array(await crypto.subtle.exportKey('spki', ephemeral.publicKey));

  const out = new Uint8Array(2 + ephPub.length + iv.length + ct.byteLength);
  out[0] = (ephPub.length >> 8) & 0xff;
  out[1] = ephPub.length & 0xff;
  out.set(ephPub, 2);
  out.set(iv, 2 + ephPub.length);
  out.set(new Uint8Array(ct), 2 + ephPub.length + iv.length);
  return b64encode(out);
}

/**
 * Open a sealed blob with the matching private key.
 *
 * Throws rather than returning null on a wrong key or a damaged blob, because
 * AES-GCM authenticates: a failure means these are not the bytes that were
 * sealed, and treating that as "no secret yet" would send the caller down a
 * path that mints a replacement.
 */
export async function openSealed(
  sealedB64: string,
  privateKey: CryptoKey,
  info: string,
): Promise<Uint8Array> {
  const raw = b64decode(sealedB64);
  if (raw.length < 2) throw new Error('sealed blob is truncated');
  const ephLen = (raw[0] << 8) | raw[1];
  if (raw.length < 2 + ephLen + 12) throw new Error('sealed blob is truncated');

  const ephemeral = await crypto.subtle.importKey(
    'spki', raw.slice(2, 2 + ephLen) as BufferSource, CURVE, false, [],
  );
  const key = await sharedKey(privateKey, ephemeral, info, ['decrypt']);
  const iv = raw.slice(2 + ephLen, 2 + ephLen + 12);
  const ct = raw.slice(2 + ephLen + 12);
  const opened = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct as BufferSource);
  return new Uint8Array(opened);
}

/** SHA-256 of an SPKI, so a blob can record which key it needs. */
export async function fingerprintSpki(publicSpkiB64: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', b64decode(publicSpkiB64) as BufferSource);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export const eciesB64 = { encode: b64encode, decode: b64decode };
