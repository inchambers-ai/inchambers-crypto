/**
 * The TypeScript half of the cross-language manifest contract.
 *
 * `tests/fixtures/evidence-manifest-cases.json` is generated from THIS
 * implementation (it is the reference: it already signs bundles in production)
 * and is asserted by both sides:
 *
 *   this file
 *   gateway/services/relay/src/api_v1/manifest.rs :: matches_the_typescript_reference_byte_for_byte
 *
 * Why assert the fixture here too, when it came from here? Because otherwise the
 * fixture only pins Rust. If someone edits `canonicalManifestBody` without
 * regenerating, the Rust test keeps passing against a stale fixture while the
 * two implementations have silently diverged. This test is what makes the
 * fixture bidirectional: change either side without regenerating and one of the
 * two suites goes red.
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import {
  canonicalManifestBody,
  sha256Text,
  type ManifestEntry,
} from '../manifest';

interface FixtureCase {
  name: string;
  why: string;
  title: string;
  note?: string;
  entries: ManifestEntry[];
  expectedBody: string;
  expectedRoot: string;
}

const FIXTURE = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  'tests',
  'fixtures',
  'evidence-manifest-cases.json',
);

const cases: FixtureCase[] = JSON.parse(readFileSync(FIXTURE, 'utf8')).cases;

describe('evidence manifest cross-language fixture', () => {
  it('has cases, so the suite cannot pass vacuously', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases.map((c) => [c.name, c] as const))(
    'case %s still produces the committed canonical body',
    (_name, c) => {
      // A mismatch means this implementation changed without the fixture being
      // regenerated, so the gateway (which asserts the same file) is now
      // producing a different root for the same bundle.
      expect(canonicalManifestBody(c.entries, c.title, c.note)).toBe(c.expectedBody);
    },
  );

  it.each(cases.map((c) => [c.name, c] as const))(
    'case %s still produces the committed root digest',
    async (_name, c) => {
      expect(await sha256Text(c.expectedBody)).toBe(c.expectedRoot);
    },
  );

  it('pins the UTF-16 sort order the Rust port has to reproduce', () => {
    // Called out explicitly because it is the one case where a correct-looking
    // Rust implementation (`sort_by_key(|e| e.path.clone())`) silently disagrees:
    // a surrogate pair sorts below U+FFFD in UTF-16 and above it in UTF-8 bytes.
    const c = cases.find((x) => x.name === 'utf16-vs-utf8-sort');
    expect(c).toBeDefined();
    const paths = c!.expectedBody
      .split('\n')
      .slice(1)
      .filter(Boolean)
      .map((line) => line.split('\t')[0]);
    expect(paths).toEqual([
      'a-ascii',
      '\u{1F600}-emoji',
      '\u{E000}-private-use',
      '\u{FFFD}-replacement',
    ]);
  });
});
