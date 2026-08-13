/**
 * Where a device keeps a derived key so surfaces that cannot reach the
 * authenticator can still work.
 *
 * WHY A CACHE AT ALL. WebAuthn cannot run in the Word taskpane: it is a
 * cross-origin iframe Office owns, and the embedder never grants
 * `publickey-credentials-get`. Unlock therefore happens in a top-level context
 * (a browser tab, the desktop shell, or the Office Dialog popout) and leaves the
 * derived key here, as a non-extractable CryptoKey. The taskpane reads it and
 * never touches WebAuthn.
 *
 * WHY THAT IS NOT A WEAKENING. The passkey defends against inchambers, and
 * against whoever takes the firm gateway's database. It was never defending
 * against someone in possession of an unlocked device, which was equally true
 * of the server-fetched key it replaces. Storing a NON-EXTRACTABLE key means
 * script injection can use it while the tab is open but cannot exfiltrate it,
 * which is the same property the rest of the storage layer already relies on.
 *
 * WHY IT IS INJECTED. The real implementation is `secureStorage`'s
 * encryptionKeys store, and `secureStorage` is 3,411 lines with ~120 importers.
 * The key-handling modules are meant to be extractable into the public audit
 * repo, and importing that file would drag the entire app in behind them. So
 * they depend on this three-method interface and the app wires the real store
 * in at startup.
 */

/** What a cache slot holds. `at` exists only to make a stale entry legible. */
export interface CachedEntry {
  key: CryptoKey;
  at: number;
}

export interface DeviceKeyCache {
  get(key: string): Promise<CachedEntry | null>;
  set(key: string, value: CachedEntry): Promise<void>;
  remove?(key: string): Promise<void>;
}

let cache: DeviceKeyCache | null = null;

/** Wire the real store in. Called once, from the app's startup path. */
export function setDeviceKeyCache(next: DeviceKeyCache | null): void {
  cache = next;
}

/**
 * Read a cached CryptoKey.
 *
 * Returns null rather than throwing on anything unexpected: a device that
 * cannot read its cache still works in a top-level window, it just asks for the
 * authenticator again. Treating a corrupt entry as absent is what makes that
 * true, where returning it would throw somewhere much less obvious later.
 */
export async function readCachedKey(name: string): Promise<CryptoKey | null> {
  if (!cache) return null;
  try {
    const entry = await cache.get(name);
    const key = entry?.key;
    // Structured clone round-trips a CryptoKey through IndexedDB. Anything else
    // in this slot is corruption.
    return key && typeof key === 'object' && 'algorithm' in key ? key : null;
  } catch {
    return null;
  }
}

/**
 * Cache a derived key for this device.
 *
 * A failure here is reported, not swallowed. Without the cache the taskpane
 * silently never syncs, and a fallback nobody can observe is indistinguishable
 * from success (see .claude/SILENT_FAILURES.md).
 */
export async function writeCachedKey(name: string, key: CryptoKey): Promise<void> {
  if (!cache) return;
  try {
    await cache.set(name, { key, at: Date.now() });
  } catch (e) {
    console.error('IC-DEVICE-KEY-CACHE', name, e);
  }
}

/** Drop a cached key, e.g. when its wrap has been revoked. */
export async function clearCachedKey(name: string): Promise<void> {
  if (!cache?.remove) return;
  try {
    await cache.remove(name);
  } catch (e) {
    console.error('IC-DEVICE-KEY-CACHE-CLEAR', name, e);
  }
}
