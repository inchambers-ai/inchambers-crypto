/**
 * The signature format, exercised with REAL Ed25519 rather than a mock.
 *
 * `bundle.test.ts` mocks the signing module so it can assert on VERIFY.md text.
 * That is the right call there, but it means nothing in the suite checked that the
 * bytes we sign are the bytes we verify. This does, because the failure mode is
 * silent and total: `buildBundle` self-verifies and, on a mismatch, rewrites the
 * outcome to unsigned with a generic "signing failed". So getting the material
 * wrong would stop the product signing anything while reporting a signing error.
 *
 * Format 2 exists because format 1 signed the root digest ALONE, leaving `signedAt`
 * beside the signature as editable JSON. Revocation is evaluated by comparing the
 * signing date against the revocation date, so a bundle holder could move a
 * signature to either side of a revocation at will.
 */

import { signedMaterial, verifySignatureLocally, type EvidenceSignature } from '../signing';

const ROOT = 'a'.repeat(64);
const SIGNED_AT = 1_700_000_000_000;

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * A real key pair. THROWS if the runtime cannot do Ed25519.
 *
 * This used to return `null` on failure, and every test below opened with
 * `const pair = await keyPair(); if (!pair) return;`. A bare `return` is not a
 * skip: the test reports as PASSING having asserted nothing. So on a runtime
 * without Ed25519 all six tests here went green, including the one proving that a
 * tampered timestamp breaks verification, which is the entire reason format 2
 * exists.
 *
 * Same silent-pass shape as the corpus gates and the jsdom `window.confirm` gap:
 * a check that cannot fail, whose green tick gets spent as evidence. Node 20's
 * WebCrypto has Ed25519, so the honest contract is a hard requirement, asserted
 * once below, rather than a per-test escape hatch.
 */
async function keyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}

async function signature(
  pair: CryptoKeyPair,
  material: ArrayBuffer,
  overrides: Partial<EvidenceSignature> = {},
): Promise<EvidenceSignature> {
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, material);
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  return {
    anchor: 'user-device',
    algorithm: 'Ed25519',
    signature: toBase64(new Uint8Array(sig)),
    keyId: 'k1_' + '0'.repeat(32),
    publicKeyUrl: 'https://example.test/key',
    publicKeySpki: toBase64(new Uint8Array(spki)),
    signedAt: SIGNED_AT,
    formatVersion: 2,
    timeSource: 'signing-device',
    ...overrides,
  };
}

describe('the runtime can do what these tests need', () => {
  it('has Ed25519, so nothing below can pass by silently skipping', async () => {
    await expect(keyPair()).resolves.toBeDefined();
  });
});

describe('the signed material', () => {
  it('is the root, a newline, then the timestamp', () => {
    const bytes = new Uint8Array(signedMaterial(ROOT, SIGNED_AT));
    expect(Buffer.from(bytes).toString('utf8')).toBe(`${ROOT}\n${SIGNED_AT}`);
  });

  it('has no trailing newline, because the published procedure has none', () => {
    const text = Buffer.from(new Uint8Array(signedMaterial(ROOT, SIGNED_AT))).toString('utf8');
    expect(text.endsWith('\n')).toBe(false);
  });

  it('changes when the timestamp changes, which is the whole point', () => {
    const a = Buffer.from(new Uint8Array(signedMaterial(ROOT, SIGNED_AT))).toString('utf8');
    const b = Buffer.from(new Uint8Array(signedMaterial(ROOT, SIGNED_AT + 1))).toString('utf8');
    expect(a).not.toBe(b);
  });
});

describe('verification agrees with signing', () => {
  it('accepts a v2 signature over v2 material', async () => {
    const pair = await keyPair();
    const sig = await signature(pair, signedMaterial(ROOT, SIGNED_AT));
    await expect(verifySignatureLocally(sig, ROOT)).resolves.toBe(true);
  });

  it('REJECTS a v2 signature whose timestamp was edited afterwards', async () => {
    // The attack format 1 allowed: move a signature across a revocation date.
    const pair = await keyPair();
    const sig = await signature(pair, signedMaterial(ROOT, SIGNED_AT));
    const tampered = { ...sig, signedAt: SIGNED_AT - 60_000 };
    await expect(verifySignatureLocally(tampered, ROOT)).resolves.toBe(false);
  });

  it('rejects a v2 signature against a different manifest', async () => {
    const pair = await keyPair();
    const sig = await signature(pair, signedMaterial(ROOT, SIGNED_AT));
    await expect(verifySignatureLocally(sig, 'b'.repeat(64))).resolves.toBe(false);
  });

  it('still verifies a FORMAT 1 signature, so older bundles keep working', async () => {
    // v1 signed the root alone. Dropping support would invalidate any bundle already
    // issued, which is the opposite of what an evidence format is for.
    const pair = await keyPair();
    const material = new TextEncoder().encode(ROOT).buffer as ArrayBuffer;
    const sig = await signature(pair, material, { formatVersion: 1 });
    await expect(verifySignatureLocally(sig, ROOT)).resolves.toBe(true);
  });

  it('does not accept v1 material under a v2 claim, or the reverse', async () => {
    const pair = await keyPair();
    const v1Material = new TextEncoder().encode(ROOT).buffer as ArrayBuffer;

    // Signed v1, labelled v2.
    const mislabelled = await signature(pair, v1Material, { formatVersion: 2 });
    await expect(verifySignatureLocally(mislabelled, ROOT)).resolves.toBe(false);

    // Signed v2, labelled v1.
    const alsoWrong = await signature(pair, signedMaterial(ROOT, SIGNED_AT), {
      formatVersion: 1,
    });
    await expect(verifySignatureLocally(alsoWrong, ROOT)).resolves.toBe(false);
  });

  it('returns false rather than throwing on a junk public key', async () => {
    const pair = await keyPair();
    const sig = await signature(pair, signedMaterial(ROOT, SIGNED_AT));
    await expect(
      verifySignatureLocally({ ...sig, publicKeySpki: 'not base64 at all !!' }, ROOT),
    ).resolves.toBe(false);
  });
});
