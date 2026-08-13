/**
 * Per-user database naming, and the structural gate that keeps it that way.
 *
 * Behaviour first (two accounts cannot reach one database), then a source scan
 * that fails when a NEW IndexedDB database is opened under a fixed name without
 * a decision being recorded. The scan is the point: every leak in this codebase
 * came from a store that was written without anyone thinking about the second
 * account, so the gate has to fire at the moment the store is added.
 */

import 'fake-indexeddb/auto';
import * as fs from 'fs';
import * as path from 'path';
import {
  setScopedDbUser, getScopedDbUser, scopedDbName, SCOPED_DB_BASES,
} from '../userScopedDb';

const USER_A = 'user-aaaa-1111';
const USER_B = 'user-bbbb-2222';

afterEach(() => setScopedDbUser(null));

describe('scopedDbName', () => {
  it('gives each account a different database', () => {
    setScopedDbUser(USER_A);
    const a = scopedDbName('InChambersMemory');
    setScopedDbUser(USER_B);
    const b = scopedDbName('InChambersMemory');

    expect(a).not.toBe(b);
    expect(a).toContain(USER_A);
    expect(b).toContain(USER_B);
  });

  it('returns null when signed out instead of a shared fallback', () => {
    setScopedDbUser(null);
    // A fallback name is how the shared database gets rebuilt by accident, and
    // everything written to it leaks to whoever signs in next.
    for (const base of SCOPED_DB_BASES) {
      expect(scopedDbName(base)).toBeNull();
    }
  });

  it('is stable for the same user, so data is found again', () => {
    setScopedDbUser(USER_A);
    const first = scopedDbName('InChambersMemory');
    setScopedDbUser(USER_B);
    setScopedDbUser(USER_A);
    expect(scopedDbName('InChambersMemory')).toBe(first);
  });

  it('uses the full user id rather than a digest', () => {
    // A short hash risks a collision, and a collision means two accounts sharing
    // one database, which is the bug this exists to prevent.
    setScopedDbUser(USER_A);
    expect(scopedDbName('InChambersMemory')!.endsWith(USER_A)).toBe(true);
  });

  it('tracks the signed-in user', () => {
    setScopedDbUser(USER_A);
    expect(getScopedDbUser()).toBe(USER_A);
    setScopedDbUser(null);
    expect(getScopedDbUser()).toBeNull();
  });
});

describe('memory tool isolation (end to end)', () => {
  // The real store, driven through its public tools, against a real IndexedDB.
  //
  // Imported ONCE. jest.resetModules() here would re-import userScopedDb too,
  // giving memoryTools a fresh copy with no user set while the test kept the
  // original — so every database name resolved to null and the isolation
  // assertions passed for the wrong reason. memoryTools caches no connection
  // (openDB consults scopedDbName on every call), so one import is correct.
  const memoryMod = import('../../connectors/builtin/memoryTools');
  const memory = () => memoryMod;

  it('does not show one account the entities another remembered', async () => {
    setScopedDbUser(USER_A);
    const m1 = await memory();
    await m1.create_entities({ entities: [{ name: 'Falcon SPA', entityType: 'matter', observations: ['confidential'] }] });

    setScopedDbUser(USER_B);
    const m2 = await memory();
    const graph = await m2.read_graph();

    expect(JSON.stringify(graph)).not.toContain('Falcon SPA');
  });

  it('gives each account its own memory back', async () => {
    setScopedDbUser(USER_A);
    const m = await memory();
    await m.create_entities({ entities: [{ name: 'A entity', entityType: 'x', observations: [] }] });

    setScopedDbUser(USER_B);
    await (await memory()).create_entities({ entities: [{ name: 'B entity', entityType: 'x', observations: [] }] });

    setScopedDbUser(USER_A);
    expect(JSON.stringify(await (await memory()).read_graph())).toContain('A entity');

    setScopedDbUser(USER_B);
    expect(JSON.stringify(await (await memory()).read_graph())).toContain('B entity');
  });

  it('writes nothing at all while signed out', async () => {
    setScopedDbUser(null);
    const m = await memory();
    await m.create_entities({ entities: [{ name: 'Orphan', entityType: 'x', observations: [] }] });

    // Nowhere to put it beats somewhere shared.
    setScopedDbUser(USER_A);
    expect(JSON.stringify(await (await memory()).read_graph())).not.toContain('Orphan');
  });
});

describe('structural gate: no new unscoped databases', () => {
  const SRC = path.join(__dirname, '..', '..');

  /** Databases allowed a fixed name, each with the reason it is safe. */
  const INTENTIONALLY_SHARED: Record<string, string> = {
    InChambersAI: 'secureStorage: per-record userId scoping + its own contract test',
    inchambers_files: 'per-user encryption; rows unreadable without the user key',
    inchambers_open_docs: 'per-user encryption; cleared on explicit sign-out',
    inchambers_history: 'scopes every read by userId',
    InChambersVectors: 'scopes every read by userId',
    inchambers_matters: 'scopes every read by userId',
    inchambers_dockets: 'scopes every read by userId',
    inchambers_intakes: 'scopes every read by userId',
    inchambers_time_entries: 'scopes every read by userId',
    inchambers_clients: 'scopes every read by userId',
    'ic-stream-storage': 'scopes every read by userId',
    'inchambers-debug-logs': 'diagnostic log lines, no user records',
  };

  function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === '__tests__' || e.name === 'node_modules') continue;
        out.push(...sourceFiles(p));
      } else if (e.name.endsWith('.ts') || e.name.endsWith('.tsx')) {
        out.push(p);
      }
    }
    return out;
  }

  it('finds database declarations (guards against a vacuous pass)', () => {
    const found = sourceFiles(SRC).flatMap(f =>
      [...fs.readFileSync(f, 'utf8').matchAll(/DB_(?:NAME|BASE)\s*=\s*'([^']+)'/g)].map(m => m[1]));
    expect(found.length).toBeGreaterThan(8);
  });

  it('every fixed database name is either scoped or justified', () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(SRC)) {
      const src = fs.readFileSync(file, 'utf8');
      for (const m of src.matchAll(/DB_NAME\s*=\s*'([^']+)'/g)) {
        const name = m[1];
        // A DB_BASE is by definition fed through scopedDbName; a DB_NAME is a
        // fixed name and needs a reason.
        if (name in INTENTIONALLY_SHARED) continue;
        if ((SCOPED_DB_BASES as readonly string[]).includes(name)) continue;
        offenders.push(`${name} (${path.relative(SRC, file)})`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('every scoped base is reached through scopedDbName, never opened directly', () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(SRC)) {
      const src = fs.readFileSync(file, 'utf8');
      if (file.endsWith('userScopedDb.ts')) continue; // declares the list
      for (const base of SCOPED_DB_BASES) {
        // Opening a scoped base by literal would silently restore the shared DB.
        const opened = new RegExp(`(?:indexedDB\\.open|openDB)\\(\\s*['"\`]${base}`).test(src);
        if (opened) offenders.push(`${base} opened literally in ${path.relative(SRC, file)}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
