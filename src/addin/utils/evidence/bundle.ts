/**
 * Evidence bundle — a zip a third party can verify without trusting us.
 *
 * Layout:
 *   documents/…            the exact bytes that were exported
 *   manifest.json          structured manifest (digests + provenance + root)
 *   MANIFEST.txt           the same digests in `sha256sum -c` format
 *   signature.json         present only when the bundle was actually signed
 *   VERIFY.md              the procedure, written for a sceptic with coreutils
 *
 * Built entirely in the browser. Nothing is uploaded, so producing chain-of-
 * custody material over a client's documents does not put those documents on
 * anyone's server (docs/architecture/privacy.mdx).
 */

import {
  buildManifest,
  toSha256SumFile,
  canonicalManifestBody,
  type EvidenceItem,
  type EvidenceManifest,
} from './manifest';
import {
  signManifestRoot,
  verifySignatureLocally,
  type SignOutcome,
  type EvidenceSignature,
} from './signing';

export interface BuildBundleOptions {
  title: string;
  items: EvidenceItem[];
  note?: string;
  exportedBy?: EvidenceManifest['exportedBy'];
  /** Skip signing entirely (integrity only). Default false. */
  unsigned?: boolean;
  /** Injected in tests. */
  createdAt?: number;
}

export interface BuiltBundle {
  blob: Blob;
  manifest: EvidenceManifest;
  /** How it ended up signed, including the reason when it did not. */
  signing: SignOutcome;
  suggestedFileName: string;
}

function slug(s: string): string {
  return (
    (s || 'evidence')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'evidence'
  );
}

function stampFor(ts: number): string {
  // Local-agnostic, filename-safe: 20260807-141530
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
}

/** The verification procedure. Deliberately assumes no software of ours. */
function verifyDoc(manifest: EvidenceManifest, signing: SignOutcome): string {
  const signed = signing.anchor !== 'unsigned';
  const sig = signed ? (signing as EvidenceSignature) : null;

  const lines: string[] = [];
  lines.push(`# How to verify this bundle`);
  lines.push('');
  lines.push(`Bundle: ${manifest.title}`);
  lines.push(`Created: ${new Date(manifest.createdAt).toISOString()}`);
  lines.push(`Documents: ${manifest.entries.length}`);
  lines.push(`Manifest root (SHA-256): ${manifest.rootSha256}`);
  lines.push(
    signed
      ? `Signature: ${sig!.algorithm}, anchored to ${sig!.anchor === 'firm-gateway' ? 'a firm signing key' : 'a per-user device key'}`
      : `Signature: none. See "Why this bundle is unsigned" below.`,
  );
  lines.push('');
  lines.push(`There are three separate things you can check, in increasing strength.`);
  lines.push('');

  lines.push(`## 1. The documents match their recorded digests`);
  lines.push('');
  lines.push(`This proves nothing in the bundle was altered after export.`);
  lines.push('');
  lines.push('```');
  lines.push(`unzip <this-bundle>.zip -d bundle`);
  lines.push(`cd bundle`);
  lines.push(`sha256sum -c MANIFEST.txt`);
  lines.push('```');
  lines.push('');
  lines.push(
    `Every line must report OK. On macOS use \`shasum -a 256 -c MANIFEST.txt\`. Any FAILED line means that document's bytes differ from what was exported.`,
  );
  lines.push('');

  lines.push(`## 2. The manifest itself was not edited`);
  lines.push('');
  lines.push(
    `\`MANIFEST.txt\` is derived from \`manifest.json\`, so an attacker who rewrites both would pass step 1. The root digest closes that: it is a SHA-256 over a canonical rendering of every manifest entry, so changing any digest, size, path or provenance changes the root.`,
  );
  lines.push('');
  lines.push(`The canonical rendering is, with fields separated by single tabs:`);
  lines.push('');
  lines.push('```');
  lines.push(`inchambers-evidence-manifest<TAB>v1<TAB><title><TAB><note>`);
  lines.push(`<path><TAB><sizeBytes><TAB><sha256><TAB><textSha256 or empty><TAB><provenance>`);
  lines.push(`... one line per entry, sorted by path, trailing newline`);
  lines.push('```');
  lines.push('');
  lines.push(
    `Provenance is flattened as \`local-file:<fileId>:<version>\`, \`matter-doc:<documentId>:<matterId>\`, \`connector:<provider>:<path>\`, \`word:<documentName>\`, or \`derived:<producedBy>\`.`,
  );
  lines.push('');
  lines.push(
    `Escaping, applied so that no two different entry sets can render as the same text: inside any field a backslash becomes \`\\\\\`, a tab \`\\t\`, a carriage return \`\\r\` and a line feed \`\\n\`. Inside a PROVENANCE field the \`:\` separator additionally becomes \`\\c\`, because provenance fields are joined with \`:\` and without that escape a path containing a colon could be re-read as a different provider. The SHA-256 of the resulting text must equal \`rootSha256\` in \`manifest.json\`.`,
  );
  lines.push('');

  if (signed) {
    lines.push(`## 3. The bundle was signed by the claimed signer`);
    lines.push('');
    const v2 = (sig!.formatVersion ?? 1) === 2;
    lines.push(
      v2
        ? `\`signature.json\` holds an ${sig!.algorithm} signature over the ASCII bytes of the root digest from step 2, a newline, then \`signedAt\` in unix milliseconds: \`<64 hex>\\n<millis>\`, with no trailing newline. The timestamp is INSIDE the signature, so it cannot be altered without breaking it.`
        : `\`signature.json\` holds an ${sig!.algorithm} signature over the ASCII bytes of the root digest string in step 2 alone (the 64 hex characters, with no trailing newline). Note that \`signedAt\` sits OUTSIDE this signature and is therefore not protected by it.`,
    );
    lines.push('');
    lines.push(`Key id: ${sig!.keyId}`);
    lines.push(`Public key: ${sig!.publicKeyUrl}`);
    if (sig!.signerLabel) lines.push(`Signer label (display only): ${sig!.signerLabel}`);
    lines.push('');
    lines.push(
      `The public key is also inlined in \`signature.json\` as base64 SPKI, so you can verify offline. Verifying against the inlined key proves the signature and the root agree. It does NOT prove who holds the key. To establish that, fetch the URL above over HTTPS and confirm the SPKI it returns is byte-identical to the inlined one.`,
    );
    lines.push('');
    lines.push(`With OpenSSL 3.0 or later:`);
    lines.push('');
    lines.push('```');
    lines.push(`# extract the inlined public key, the signature, and the signed text`);
    lines.push(
      v2
        ? `python3 -c "import json,base64,sys; d=json.load(open('signature.json')); open('pub.der','wb').write(base64.b64decode(d['publicKeySpki'])); open('sig.bin','wb').write(base64.b64decode(d['signature'])); sys.stdout.write(d['rootSha256'] + chr(10) + str(d['signedAt']))" > signed.txt`
        : `python3 -c "import json,base64,sys; d=json.load(open('signature.json')); open('pub.der','wb').write(base64.b64decode(d['publicKeySpki'])); open('sig.bin','wb').write(base64.b64decode(d['signature'])); sys.stdout.write(d['rootSha256'])" > signed.txt`,
    );
    lines.push(`openssl pkey -pubin -inform DER -in pub.der -out pub.pem`);
    lines.push(
      `openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in signed.txt -sigfile sig.bin`,
    );
    lines.push('```');
    lines.push('');
    lines.push(
      `\`Signature Verified Successfully\` means the holder of that private key signed this exact manifest.`,
    );
    lines.push('');
    lines.push(`### Check the key had not been revoked`);
    lines.push('');
    lines.push(
      `Fetch the public key URL above. The response carries \`revokedAt\`, which is null for a key still in use and otherwise the moment it was retired. A signature made BEFORE that moment remains valid, which is deliberate so historic evidence keeps verifying. A signature dated AFTER it should not be trusted.`,
    );
    lines.push('');
    lines.push(
      `This bundle reports \`signedAt\` as ${new Date(sig!.signedAt).toISOString()}.`,
    );
    if (sig!.timeSource === 'firm-gateway') {
      lines.push(
        `That timestamp was recorded by the firm's own gateway, not by the machine that requested the signature, so the signer did not choose it.`,
      );
    } else {
      lines.push(
        `That timestamp comes from the signing device's own clock. It is covered by the signature, so nobody can change it afterwards, but the device chose it in the first place. Weigh it accordingly.`,
      );
    }
    if (sig!.downgradedFrom) {
      lines.push('');
      lines.push(
        `NOTE: a firm key was expected for this bundle and was not used (${sig!.downgradedFrom.detail}). It is signed with the exporter's personal device key instead, so it attests to a person, not to the firm.`,
      );
    }
    if (sig!.anchor === 'user-device') {
      lines.push('');
      lines.push(
        `This key was generated inside the signer's browser and is non-extractable, meaning the private half cannot be read out of the device, exported, or reproduced by inchambers. inchambers holds only the public half, which is what the URL above serves.`,
      );
    } else {
      lines.push('');
      lines.push(
        `This key is held on the firm's own gateway, which is infrastructure the firm operates. inchambers does not hold it and cannot sign on the firm's behalf.`,
      );
    }
  } else {
    lines.push(`## 3. Why this bundle is unsigned`);
    lines.push('');
    const reason = (signing as { reason?: string }).reason;
    const detail = (signing as { detail?: string }).detail;
    const explain: Record<string, string> = {
      'ed25519-unsupported':
        'the browser that produced it does not support Ed25519 signing, so no signature could be produced',
      'no-session': 'the exporter was not signed in, so no signing identity could be established',
      'key-registration-failed':
        'the signing key could not be registered, so no verifiable public key exists for it',
      'gateway-refused': 'the signing service declined the request',
      'skipped-by-request': 'the person exporting it chose not to sign it',
      'local-key-invalid':
        'the signing key stored on the exporting device was unusable, so it was not used',
      'signing-failed': 'the signing operation itself failed',
    };
    lines.push(
      `No signature was produced because ${explain[reason ?? ''] ?? 'signing was not available'}${detail ? ` (${detail})` : ''}.`,
    );
    lines.push('');
    lines.push(
      `Steps 1 and 2 still hold: the digests prove the documents are unaltered relative to this manifest. What is missing is authorship. Treat this bundle as an integrity record, not as a signed attestation.`,
    );
  }

  lines.push('');
  lines.push(`## What this bundle does not prove`);
  lines.push('');
  lines.push(
    `It does not prove the documents are authentic originals, only that they are unchanged since export. It does not prove when they were created, only when they were exported. Where a signature is present, see step 3 for whose clock recorded the export time and whether that time is covered by the signature. Nothing here is a substitute for a custodian's declaration.`,
  );
  lines.push('');

  return `${lines.join('\n')}\n`;
}

/**
 * One sentence describing what a bundle's signature actually is, for the UI.
 *
 * Shared because there are two export surfaces (local files and the review grid)
 * and they previously each collapsed five distinct outcomes into one string, so a
 * firm whose gateway signing key was misconfigured read "Signed with your device
 * key" as normal. The reason a bundle is unsigned, and the fact that a firm key was
 * expected, are the two things a user needs and neither was ever shown.
 */
export function describeSigning(signing: SignOutcome): string {
  if (signing.anchor === 'unsigned') {
    const why: Record<string, string> = {
      'ed25519-unsupported': 'this browser cannot sign',
      'no-session': 'you were not signed in',
      'key-registration-failed': 'the signing key could not be registered',
      'gateway-refused': 'your firm gateway declined to sign',
      'skipped-by-request': 'you chose not to sign it',
      'local-key-invalid': 'the signing key on this device was unusable and was replaced',
      'signing-failed': 'signing failed',
    };
    const reason = why[signing.reason] ?? 'signing was unavailable';
    return `Digests only, not signed, because ${reason}. See VERIFY.md inside.`;
  }
  if (signing.anchor === 'firm-gateway') return 'Signed with your firm key.';
  if (signing.downgradedFrom) {
    // The case that was invisible. A firm believing its own key signs its evidence
    // needs to hear that it did not.
    return 'Signed with your device key, NOT your firm key. Your firm gateway did not sign this bundle, so it attests to you rather than to the firm. Ask your gateway administrator to check the evidence signing key.';
  }
  return 'Signed with your device key.';
}

/**
 * Build the bundle. Signing is attempted unless `unsigned` is set, and a signing
 * failure downgrades the bundle rather than aborting the export: an unsigned
 * integrity record is worth far more than a failed download.
 */
export async function buildEvidenceBundle(opts: BuildBundleOptions): Promise<BuiltBundle> {
  const JSZip = (await import('jszip')).default;

  const manifest = await buildManifest(opts.items, {
    title: opts.title,
    exportedBy: opts.exportedBy,
    note: opts.note,
    createdAt: opts.createdAt,
  });

  // `skipped-by-request`, not `signing-failed`. Reporting a deliberate choice as a
  // failure made VERIFY.md say "the signing operation itself failed (signing skipped
  // by request)", which reads as a defect to anyone holding the bundle.
  let signing: SignOutcome = opts.unsigned
    ? { anchor: 'unsigned', reason: 'skipped-by-request' }
    : await signManifestRoot(manifest.rootSha256);

  // SELF-VERIFY before claiming a signature. The firm-gateway path accepts
  // whatever the gateway returns, so a misconfigured gateway could hand back a
  // signature that does not check out and this bundle would still ship a
  // VERIFY.md telling a court that "Signature Verified Successfully means the
  // holder of that private key signed this exact manifest". Checking it here
  // means we never make a claim about the bundle we have not tested ourselves.
  if (signing.anchor !== 'unsigned') {
    const ok = await verifySignatureLocally(signing as EvidenceSignature, manifest.rootSha256);
    if (!ok) {
      signing = {
        anchor: 'unsigned',
        reason: 'signing-failed',
        detail: 'the signature returned did not verify against this manifest',
      };
    }
  }

  const zip = new JSZip();
  for (const item of opts.items) {
    // Copy into an exactly-sized buffer for the same reason manifest.ts does:
    // a view over a pooled buffer would zip the whole backing store.
    const exact = new Uint8Array(item.bytes.byteLength);
    exact.set(item.bytes);
    zip.file(item.path, exact);
  }

  zip.file('manifest.json', JSON.stringify(manifest, null, 2));
  zip.file('MANIFEST.txt', toSha256SumFile(manifest));
  // The exact bytes the root was taken over. Shipping it removes any ambiguity
  // about our canonicalisation, so a verifier never has to reverse-engineer it.
  zip.file('manifest-canonical.txt', canonicalManifestBody(manifest.entries, manifest.title, manifest.note));
  if (signing.anchor !== 'unsigned') {
    const sig = signing as EvidenceSignature;
    zip.file(
      'signature.json',
      JSON.stringify({ ...sig, rootSha256: manifest.rootSha256 }, null, 2),
    );
  }
  zip.file('VERIFY.md', verifyDoc(manifest, signing));

  const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
  const unsignedSuffix = signing.anchor === 'unsigned' ? '-unsigned' : '';

  return {
    blob,
    manifest,
    signing,
    suggestedFileName: `${slug(opts.title)}-evidence-${stampFor(manifest.createdAt)}${unsignedSuffix}.zip`,
  };
}

/** Build and hand to the browser as a download. */
export async function downloadEvidenceBundle(opts: BuildBundleOptions): Promise<BuiltBundle> {
  const built = await buildEvidenceBundle(opts);
  const { saveAs } = await import('file-saver');
  saveAs(built.blob, built.suggestedFileName);
  return built;
}
