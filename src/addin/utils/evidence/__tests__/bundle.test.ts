/**
 * Bundle assembly. Signing is mocked: the real module reaches IndexedDB and the
 * network, neither of which exists in the node test environment, and what matters
 * here is that the zip is assembled correctly and that an unsigned outcome is
 * reported honestly rather than papered over.
 */

const mockSign = jest.fn();
// `verifySignatureLocally` is mocked too, because the bundle now self-verifies
// before it will label itself signed. Default true so the signed cases exercise
// assembly; one test overrides it to false to prove the downgrade.
const mockVerify = jest.fn(async () => true);
jest.mock('../signing', () => ({
  signManifestRoot: (root: string) => mockSign(root),
  verifySignatureLocally: (...args: unknown[]) => mockVerify(...(args as [])),
}));

import { buildEvidenceBundle } from '../bundle';
import { sha256Text, type EvidenceItem } from '../manifest';

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

const item = (path: string, content: string): EvidenceItem => ({
  path,
  bytes: bytes(content),
  provenance: { kind: 'local-file', fileId: `id-${path}`, version: 2 },
});

const SIGNED = {
  anchor: 'firm-gateway' as const,
  algorithm: 'Ed25519' as const,
  signature: 'c2ln',
  keyId: 'firm-key-1',
  publicKeyUrl: 'https://gateway.example.com/api/evidence/pubkey?key_id=firm-key-1',
  publicKeySpki: 'cHVi',
  signedAt: 1_700_000_000_000,
  signerLabel: 'Example LLP',
};

async function readZip(blob: Blob): Promise<Record<string, string>> {
  const JSZip = (await import('jszip')).default;
  const zip = await JSZip.loadAsync(await blob.arrayBuffer());
  const out: Record<string, string> = {};
  await Promise.all(
    Object.keys(zip.files).map(async name => {
      if (!zip.files[name].dir) out[name] = await zip.files[name].async('string');
    }),
  );
  return out;
}

const OPTS = {
  title: 'Project Atlas',
  items: [item('documents/a.txt', 'alpha'), item('documents/b.txt', 'beta')],
  createdAt: 1_700_000_000_000,
};

beforeEach(() => {
  mockSign.mockReset();
  mockVerify.mockReset();
  mockVerify.mockResolvedValue(true);
});

describe('evidence bundle — signed', () => {
  beforeEach(() => mockSign.mockResolvedValue(SIGNED));

  it('contains the documents, both manifest forms, the signature and VERIFY.md', async () => {
    const built = await buildEvidenceBundle(OPTS);
    const files = await readZip(built.blob);
    expect(Object.keys(files).sort()).toEqual([
      'MANIFEST.txt',
      'VERIFY.md',
      'documents/a.txt',
      'documents/b.txt',
      'manifest-canonical.txt',
      'manifest.json',
      'signature.json',
    ]);
    expect(files['documents/a.txt']).toBe('alpha');
  });

  it('signs the manifest root, not the manifest JSON', async () => {
    const built = await buildEvidenceBundle(OPTS);
    expect(mockSign).toHaveBeenCalledWith(built.manifest.rootSha256);
  });

  it('ships the exact canonical bytes the root was taken over', async () => {
    // VERIFY.md tells a verifier to recompute the root. Shipping the canonical
    // text means they never have to reimplement our escaping to do it.
    const built = await buildEvidenceBundle(OPTS);
    const files = await readZip(built.blob);
    expect(await sha256Text(files['manifest-canonical.txt'])).toBe(built.manifest.rootSha256);
  });

  it('records the root inside signature.json so the two cannot drift', async () => {
    const built = await buildEvidenceBundle(OPTS);
    const files = await readZip(built.blob);
    expect(JSON.parse(files['signature.json']).rootSha256).toBe(built.manifest.rootSha256);
  });

  it('names the file without an unsigned marker', async () => {
    const built = await buildEvidenceBundle(OPTS);
    expect(built.suggestedFileName).toBe('project-atlas-evidence-20231114-221320.zip');
  });

  it('documents the verification steps including the signature step', async () => {
    const files = await readZip((await buildEvidenceBundle(OPTS)).blob);
    expect(files['VERIFY.md']).toContain('sha256sum -c MANIFEST.txt');
    expect(files['VERIFY.md']).toContain('The bundle was signed by the claimed signer');
    expect(files['VERIFY.md']).toContain(SIGNED.publicKeyUrl);
    // The distinction that stops a reader over-reading a local check.
    expect(files['VERIFY.md']).toContain('It does NOT prove who holds the key');
  });
});

describe('evidence bundle — unsigned', () => {
  it('omits signature.json and marks the filename when signing is unavailable', async () => {
    mockSign.mockResolvedValue({ anchor: 'unsigned', reason: 'ed25519-unsupported' });
    const built = await buildEvidenceBundle(OPTS);
    const files = await readZip(built.blob);
    expect(files['signature.json']).toBeUndefined();
    expect(built.suggestedFileName).toContain('-unsigned.zip');
  });

  it('explains WHY it is unsigned rather than staying silent', async () => {
    mockSign.mockResolvedValue({ anchor: 'unsigned', reason: 'ed25519-unsupported' });
    const files = await readZip((await buildEvidenceBundle(OPTS)).blob);
    expect(files['VERIFY.md']).toContain('Why this bundle is unsigned');
    expect(files['VERIFY.md']).toContain('does not support Ed25519');
    // Integrity still stands, and the doc must say so.
    expect(files['VERIFY.md']).toContain('Steps 1 and 2 still hold');
  });

  it('still produces a full integrity record', async () => {
    mockSign.mockResolvedValue({ anchor: 'unsigned', reason: 'no-session' });
    const built = await buildEvidenceBundle(OPTS);
    const files = await readZip(built.blob);
    expect(files['MANIFEST.txt'].trimEnd().split('\n')).toHaveLength(2);
    expect(built.manifest.rootSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('downgrades to unsigned when the signature does not verify against this manifest', async () => {
    // The firm-gateway path trusts whatever the gateway returns, so a
    // misconfigured gateway could hand back a signature that does not check out.
    // Shipping it would put a VERIFY.md in a court's hands telling them the
    // signature proves authorship, next to an openssl command that fails.
    mockSign.mockResolvedValue(SIGNED);
    mockVerify.mockResolvedValue(false);
    const built = await buildEvidenceBundle(OPTS);
    const files = await readZip(built.blob);
    expect(built.signing.anchor).toBe('unsigned');
    expect(files['signature.json']).toBeUndefined();
    expect(built.suggestedFileName).toContain('-unsigned.zip');
    expect(files['VERIFY.md']).toContain('did not verify against this manifest');
  });

  it('never calls the signer when signing was explicitly skipped', async () => {
    const built = await buildEvidenceBundle({ ...OPTS, unsigned: true });
    expect(mockSign).not.toHaveBeenCalled();
    expect(built.signing.anchor).toBe('unsigned');
  });
});
