import {
  buildManifest,
  canonicalManifestBody,
  sha256Bytes,
  sha256Text,
  toSha256SumFile,
  verifyManifestRoot,
  type EvidenceItem,
} from '../manifest';

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

const item = (path: string, content: string, extra?: Partial<EvidenceItem>): EvidenceItem => ({
  path,
  bytes: bytes(content),
  provenance: { kind: 'local-file', fileId: `id-${path}`, version: 1 },
  capturedAt: 1_700_000_000_000,
  ...extra,
});

const META = { title: 'Project Atlas diligence', createdAt: 1_700_000_000_000 };

describe('evidence manifest — digests', () => {
  it('matches the SHA-256 the rest of the world computes', async () => {
    // Well-known vector: sha256("abc").
    expect(await sha256Text('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('hashes only the view, not a larger backing buffer', async () => {
    // A Uint8Array view over a bigger ArrayBuffer must hash as its own 3 bytes.
    const backing = new Uint8Array(64);
    backing.set(bytes('abc'), 0);
    const view = backing.subarray(0, 3);
    expect(await sha256Bytes(view)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('evidence manifest — reproducibility of the root', () => {
  it('is independent of the order items were supplied in', async () => {
    const a = await buildManifest([item('documents/a.txt', 'alpha'), item('documents/b.txt', 'beta')], META);
    const b = await buildManifest([item('documents/b.txt', 'beta'), item('documents/a.txt', 'alpha')], META);
    expect(a.rootSha256).toBe(b.rootSha256);
    // And the stored entries are sorted, so manifest.json is stable too.
    expect(a.entries.map(e => e.path)).toEqual(['documents/a.txt', 'documents/b.txt']);
  });

  it('changes when a single byte of content changes', async () => {
    const a = await buildManifest([item('documents/a.txt', 'alpha')], META);
    const b = await buildManifest([item('documents/a.txt', 'alphb')], META);
    expect(a.rootSha256).not.toBe(b.rootSha256);
  });

  it('changes when a file is renamed but content is identical', async () => {
    const a = await buildManifest([item('documents/a.txt', 'alpha')], META);
    const b = await buildManifest([item('documents/renamed.txt', 'alpha')], META);
    expect(a.entries[0].sha256).toBe(b.entries[0].sha256);
    expect(a.rootSha256).not.toBe(b.rootSha256);
  });

  it('changes when provenance changes, even with identical bytes', async () => {
    const a = await buildManifest([item('documents/a.txt', 'alpha')], META);
    const b = await buildManifest(
      [item('documents/a.txt', 'alpha', { provenance: { kind: 'matter-doc', documentId: 'doc-9' } })],
      META,
    );
    expect(a.rootSha256).not.toBe(b.rootSha256);
  });

  it('changes when the extracted text changes but the stored bytes do not', async () => {
    // The point of textSha256: a converter or OCR change alters what the model
    // actually read, and that must be visible even though the file is identical.
    const a = await buildManifest([item('documents/a.pdf', 'PDFBYTES', { extractedText: 'Clause 1' })], META);
    const b = await buildManifest([item('documents/a.pdf', 'PDFBYTES', { extractedText: 'Clause 2' })], META);
    expect(a.entries[0].sha256).toBe(b.entries[0].sha256);
    expect(a.rootSha256).not.toBe(b.rootSha256);
  });

  it('changes when the note or title changes', async () => {
    const base = [item('documents/a.txt', 'alpha')];
    const a = await buildManifest(base, META);
    const b = await buildManifest(base, { ...META, note: 'produced under protocol 4' });
    const c = await buildManifest(base, { ...META, title: 'Something else' });
    expect(new Set([a.rootSha256, b.rootSha256, c.rootSha256]).size).toBe(3);
  });

  it('is not fooled by a tab or newline smuggled into a path', async () => {
    // Without escaping, a crafted name could inject an extra manifest line and
    // make the root agree with a different entry list.
    const a = await buildManifest(
      [item('documents/a.txt\t99\tdeadbeef', 'alpha'), item('documents/b.txt', 'beta')],
      META,
    );
    const b = await buildManifest(
      [item('documents/a.txt', 'alpha'), item('documents/b.txt', 'beta')],
      META,
    );
    expect(a.rootSha256).not.toBe(b.rootSha256);
    const body = canonicalManifestBody(a.entries, a.title, a.note);
    // Header + 2 entries + trailing newline: exactly 3 lines of content.
    expect(body.trimEnd().split('\n')).toHaveLength(3);
  });

  it('rejects duplicate paths rather than producing an ambiguous bundle', async () => {
    await expect(
      buildManifest([item('documents/a.txt', 'one'), item('documents/a.txt', 'two')], META),
    ).rejects.toThrow(/Duplicate path/);
  });
});

describe('evidence manifest — verification', () => {
  it('accepts an untouched manifest', async () => {
    const m = await buildManifest([item('documents/a.txt', 'alpha')], META);
    expect(await verifyManifestRoot(m)).toBe(true);
  });

  it('rejects a manifest whose entries were edited without recomputing the root', async () => {
    const m = await buildManifest([item('documents/a.txt', 'alpha')], META);
    m.entries[0].sizeBytes = 999;
    expect(await verifyManifestRoot(m)).toBe(false);
  });

  it('rejects a manifest with an entry appended', async () => {
    const m = await buildManifest([item('documents/a.txt', 'alpha')], META);
    m.entries.push({
      path: 'documents/smuggled.txt',
      sizeBytes: 3,
      sha256: await sha256Text('bad'),
      provenance: { kind: 'derived', producedBy: 'attacker' },
      capturedAt: META.createdAt,
    });
    expect(await verifyManifestRoot(m)).toBe(false);
  });

  it('recomputes the documented root from manifest.json alone', async () => {
    // A third-party verifier only has manifest.json, so the root must be a pure
    // function of its contents. This is step 2 of VERIFY.md.
    const m = await buildManifest(
      [item('documents/a.txt', 'alpha'), item('documents/b.txt', 'beta')],
      { ...META, note: 'n' },
    );
    expect(await sha256Text(canonicalManifestBody(m.entries, m.title, m.note))).toBe(m.rootSha256);
  });
});

describe('evidence manifest — sha256sum compatibility', () => {
  it('emits GNU coreutils format: hex, two spaces, path', async () => {
    const m = await buildManifest(
      [item('documents/a.txt', 'alpha'), item('documents/b.txt', 'beta')],
      META,
    );
    const text = toSha256SumFile(m);
    const lines = text.trimEnd().split('\n');
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(line).toMatch(/^[0-9a-f]{64} {2}\S/);
    }
    expect(text.endsWith('\n')).toBe(true);
  });

  it('lists digests that actually match the bytes', async () => {
    const m = await buildManifest([item('documents/a.txt', 'alpha')], META);
    const [line] = toSha256SumFile(m).trimEnd().split('\n');
    const [hex, path] = line.split('  ');
    expect(path).toBe('documents/a.txt');
    expect(hex).toBe(await sha256Text('alpha'));
  });

  it('escapes a path with a backslash the way coreutils expects', async () => {
    const m = await buildManifest([item('documents/we\\ird.txt', 'x')], META);
    const [line] = toSha256SumFile(m).trimEnd().split('\n');
    expect(line.startsWith('\\')).toBe(true);
    expect(line).toContain('we\\\\ird.txt');
  });
});
