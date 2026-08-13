/**
 * Evidence manifest — the integrity half of a tamper-evident export.
 *
 * An evidence bundle answers one question for a third party who does not trust
 * us: "are these the exact bytes that were exported, and where did each one come
 * from?" The manifest is the answer, and it is deliberately verifiable with
 * nothing but `sha256sum`. No inchambers software, no network call, no account.
 *
 * Everything here is pure and runs in the browser. Bytes never leave the device
 * to be hashed: `crypto.subtle.digest` is local, so building a manifest over a
 * client's documents does not weaken the zero-knowledge promise the way a
 * server-side hashing service would (see docs/architecture/privacy.mdx).
 *
 * REPRODUCIBILITY IS THE WHOLE POINT. Two people with the same files must
 * compute the same root digest, so:
 *  - entries are sorted by path before the root is computed, and the root is
 *    therefore independent of the order the caller passed them in;
 *  - the hashed representation is a canonical one-line-per-entry text form, not
 *    `JSON.stringify` of an object (key order in JS objects is an implementation
 *    detail we refuse to depend on);
 *  - the root covers path + size + content digest, so a rename, a truncation and
 *    a content edit are each detectable.
 */

/** Where a bundled item came from. Provenance is part of the signed material. */
export type EvidenceProvenance =
  | { kind: 'local-file'; fileId: string; version?: number }
  | { kind: 'matter-doc'; documentId: string; matterId?: string }
  | { kind: 'connector'; provider: string; path: string }
  | { kind: 'word'; documentName?: string }
  | { kind: 'derived'; producedBy: string };

/** One item in the bundle, as the caller supplies it. */
export interface EvidenceItem {
  /** Path inside the bundle, e.g. `documents/lease-01.pdf`. Must be unique. */
  path: string;
  bytes: Uint8Array;
  provenance: EvidenceProvenance;
  /**
   * The text we extracted from this item, when the export is accompanied by
   * analysis derived from that text. Hashing it pins WHAT WAS READ, not just
   * what was stored — an OCR or converter change would otherwise be invisible.
   */
  extractedText?: string;
  /** When this copy was captured, epoch ms. Defaults to the bundle timestamp. */
  capturedAt?: number;
}

/** One item as it appears in the manifest. */
export interface ManifestEntry {
  path: string;
  sizeBytes: number;
  /** Lowercase hex SHA-256 of the exact bytes at `path`. */
  sha256: string;
  /** Lowercase hex SHA-256 of the extracted text, when text was extracted. */
  textSha256?: string;
  provenance: EvidenceProvenance;
  capturedAt: number;
}

export interface EvidenceManifest {
  /** Manifest format version. Bump only on a breaking shape change. */
  formatVersion: 1;
  /** Human label for the bundle (matter name, grid name, ...). */
  title: string;
  /** Who exported it, as the client knows them. Not proof of identity on its own. */
  exportedBy?: { email?: string; name?: string; organization?: string };
  createdAt: number;
  entries: ManifestEntry[];
  /**
   * SHA-256 over the canonical entry lines (see `canonicalManifestBody`). This
   * is the value a signature covers, so a signature over the root transitively
   * covers every byte of every document.
   */
  rootSha256: string;
  /** Free-form note the exporter typed, included in the hashed material. */
  note?: string;
}

const HEX = '0123456789abcdef';

function toHex(buf: ArrayBuffer): string {
  const view = new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < view.length; i++) {
    out += HEX[view[i] >> 4] + HEX[view[i] & 15];
  }
  return out;
}

/** Lowercase hex SHA-256 of raw bytes. */
export async function sha256Bytes(bytes: Uint8Array): Promise<string> {
  // Copy into a fresh, exactly-sized buffer. A Uint8Array view over a larger
  // pooled ArrayBuffer would otherwise hash the whole backing store.
  const exact = new Uint8Array(bytes.byteLength);
  exact.set(bytes);
  return toHex(await crypto.subtle.digest('SHA-256', exact));
}

/** Lowercase hex SHA-256 of a UTF-8 string. */
export async function sha256Text(text: string): Promise<string> {
  return sha256Bytes(new TextEncoder().encode(text));
}

/**
 * Escape a field for the canonical line form. Tabs separate fields and newlines
 * separate entries, so neither may appear inside a field. Without this a
 * crafted filename could forge an extra manifest line.
 */
function field(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\t/g, '\\t')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

/**
 * Provenance flattened to a stable string. Key order is fixed here, by hand.
 *
 * Fields are joined with `:` and therefore have to ESCAPE `:`, or the flattening
 * is not injective and two different provenances collapse to one string:
 * `{provider:'sharepoint', path:'clients:acme/lease.pdf'}` and
 * `{provider:'sharepoint:clients', path:'acme/lease.pdf'}` would produce an
 * identical canonical body, an identical root digest, and therefore an identical
 * signature. Provenance is part of the signed material, so that would let a
 * bundle's chain of custody be relabelled and still verify.
 */
function canonicalProvenance(p: EvidenceProvenance): string {
  switch (p.kind) {
    case 'local-file':
      return `local-file:${part(p.fileId)}:${p.version ?? ''}`;
    case 'matter-doc':
      return `matter-doc:${part(p.documentId)}:${part(p.matterId ?? '')}`;
    case 'connector':
      return `connector:${part(p.provider)}:${part(p.path)}`;
    case 'word':
      return `word:${part(p.documentName ?? '')}`;
    case 'derived':
      return `derived:${part(p.producedBy)}`;
  }
}

/**
 * Escape a provenance FIELD. Everything `field()` does, plus the `:` separator
 * that joins provenance fields to each other. The escape character is handled
 * first (inside `field`), so the encoding stays injective.
 */
function part(value: string): string {
  return field(value).replace(/:/g, '\\c');
}

/**
 * The exact text the root digest is taken over. Sorted by path, one line per
 * entry, tab-separated. Kept separate from `buildManifest` so a verifier
 * implementation (ours or anyone else's) can recompute the root from a
 * `manifest.json` alone.
 */
export function canonicalManifestBody(entries: ManifestEntry[], title: string, note?: string): string {
  const sorted = [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const header = `inchambers-evidence-manifest\tv1\t${field(title)}\t${field(note ?? '')}`;
  const lines = sorted.map(e =>
    [
      field(e.path),
      String(e.sizeBytes),
      e.sha256,
      e.textSha256 ?? '',
      canonicalProvenance(e.provenance),
    ].join('\t'),
  );
  // Trailing newline so appending a line changes the digest rather than
  // producing a body that is a prefix of the longer one.
  return `${[header, ...lines].join('\n')}\n`;
}

/** Hash every item, then compute the root. Rejects duplicate paths. */
export async function buildManifest(
  items: EvidenceItem[],
  meta: {
    title: string;
    exportedBy?: EvidenceManifest['exportedBy'];
    note?: string;
    /** Injected in tests; defaults to now. */
    createdAt?: number;
  },
): Promise<EvidenceManifest> {
  const seen = new Set<string>();
  for (const item of items) {
    if (seen.has(item.path)) {
      // A duplicate path would make the bundle ambiguous about which bytes a
      // digest refers to, which is exactly the property we are selling.
      throw new Error(`Duplicate path in evidence bundle: ${item.path}`);
    }
    seen.add(item.path);
  }

  const createdAt = meta.createdAt ?? Date.now();

  const entries: ManifestEntry[] = [];
  for (const item of items) {
    entries.push({
      path: item.path,
      sizeBytes: item.bytes.byteLength,
      sha256: await sha256Bytes(item.bytes),
      textSha256: item.extractedText != null ? await sha256Text(item.extractedText) : undefined,
      provenance: item.provenance,
      capturedAt: item.capturedAt ?? createdAt,
    });
  }

  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  return {
    formatVersion: 1,
    title: meta.title,
    exportedBy: meta.exportedBy,
    createdAt,
    entries,
    rootSha256: await sha256Text(canonicalManifestBody(entries, meta.title, meta.note)),
    note: meta.note,
  };
}

/**
 * Recompute the root from a manifest and report whether it matches the one
 * recorded. Catches a manifest whose entry list was edited without the root
 * being recomputed. It does NOT prove the documents match their digests — that
 * needs the bytes, which is what `sha256sum -c MANIFEST.txt` does.
 */
export async function verifyManifestRoot(manifest: EvidenceManifest): Promise<boolean> {
  const expected = await sha256Text(
    canonicalManifestBody(manifest.entries, manifest.title, manifest.note),
  );
  return expected === manifest.rootSha256;
}

/**
 * `sha256sum -c`-compatible checksum file. GNU coreutils format is
 * `<hex>  <path>` (two spaces), and a path containing a backslash or newline is
 * prefixed with `\` and escaped. Our paths are generated, so escaping is
 * belt-and-braces rather than expected to trigger.
 */
export function toSha256SumFile(manifest: EvidenceManifest): string {
  const lines = manifest.entries.map(e => {
    // GNU coreutils and the Perl `shasum` on macOS understand ONLY `\\` and `\n`
    // after the leading-backslash marker. Escaping `\r` produced a line no
    // checker could parse, and because the line was ALSO marked as escaped the
    // failure surfaced as "FAILED open or read", which in a court-facing bundle
    // reads as evidence of alteration. A literal CR passes through and verifies.
    const needsEscape = /[\\\n]/.test(e.path);
    const p = needsEscape
      ? e.path.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')
      : e.path;
    return `${needsEscape ? '\\' : ''}${e.sha256}  ${p}`;
  });
  return `${lines.join('\n')}\n`;
}
