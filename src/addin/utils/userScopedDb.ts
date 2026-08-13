/**
 * Per-user IndexedDB naming: isolation the browser enforces.
 *
 * Every cross-account leak found in this codebase had the same shape. One
 * database, shared by every account that ever signed in on the profile, and a
 * read that was supposed to filter by user but did not. Filtering works right up
 * until somebody writes `getAll` without it, which is precisely what happened to
 * generations and the five org caches, and what `InChambersMemory` and
 * `InChambersAgenticLearning` still did afterwards.
 *
 * A predicate you must remember is a guardrail. A separate database per user is
 * an invariant: `InChambersMemory__u_<id>` cannot return another account's rows,
 * because those rows are in a different database that the code never opens. The
 * bug stops being tested-for and starts being unrepresentable.
 *
 * Two rules follow, and both are deliberate:
 *
 *  - **Signed out means no database.** `scopedDbName` returns null rather than
 *    falling back to a shared name. A fallback is how you rebuild the shared
 *    database by accident, and everything written to it leaks to whoever is next.
 *    Callers treat null as "no storage": reads return empty, writes no-op.
 *
 *  - **The full user id goes in the name, not a hash.** A short digest risks a
 *    collision, and a collision here means two accounts silently SHARING a
 *    database, which is the exact bug this exists to prevent. Someone reading
 *    database names in devtools already has the profile; enumerable ids are a far
 *    smaller problem than a collision.
 *
 * Legacy shared databases are deliberately NOT migrated into the per-user ones.
 * Their rows carry no owner, so any migration would be a guess about who they
 * belong to, and guessing is the bug. See clearLegacySharedDbs.
 */

/** Databases that hold per-user data and are therefore scoped. Keep in step with
 *  the sources; `userScopedDb.contract.test.ts` fails when a new one is added
 *  without a decision being recorded here. */
export const SCOPED_DB_BASES = [
  'InChambersMemory',            // AI memory: entities, relations, observations
  'InChambersAgenticLearning',   // per-action feedback and input hashes
  'inchambers-mcp-cache',        // cached MCP tool results
  'InChambersEmailCache',        // cached mail: messages and folders
] as const;

export type ScopedDbBase = (typeof SCOPED_DB_BASES)[number];

let currentUserId: string | null = null;

/** Set on sign-in, cleared on sign-out. Call BEFORE anything opens a database. */
export function setScopedDbUser(userId: string | null): void {
  currentUserId = userId || null;
}

export function getScopedDbUser(): string | null {
  return currentUserId;
}

/**
 * The database name for this user, or null when signed out.
 *
 * Null is a real answer, not an error case: it means "there is nowhere to put
 * this", and the caller should skip the read or write entirely.
 */
export function scopedDbName(base: ScopedDbBase): string | null {
  if (!currentUserId) return null;
  return `${base}__u_${currentUserId}`;
}

/**
 * Delete the pre-scoping shared databases.
 *
 * These hold rows from every account that used the device before scoping, with
 * nothing recording who wrote what. They can never be read again (nothing opens
 * the unscoped names now), so this is about not leaving the data sitting there.
 * Best-effort: a blocked delete (another tab holding the connection) is fine,
 * the data is already unreachable.
 */
export async function clearLegacySharedDbs(): Promise<void> {
  if (typeof indexedDB === 'undefined' || !indexedDB.deleteDatabase) return;
  await Promise.all(SCOPED_DB_BASES.map(base => new Promise<void>(resolve => {
    try {
      const req = indexedDB.deleteDatabase(base);
      req.onsuccess = () => resolve();
      req.onerror = () => resolve();
      req.onblocked = () => resolve(); // another tab has it open; unreachable anyway
    } catch {
      resolve();
    }
  })));
}
