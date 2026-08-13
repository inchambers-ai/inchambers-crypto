/**
 * The three things the evidence signer needs from the app, as an interface.
 *
 * WHY THIS EXISTS. `signing.ts` reached directly for `secureStorage` (3,411
 * lines, ~120 importers), `authClient` (1,590 lines), and `routeResolver` (549
 * lines, and the entry point to the whole proprietary `utils/ai/` module) -- the
 * last of those for exactly one call, `getFirmGatewayUrl()`.
 *
 * That is fine inside one application and fatal to publishing the file. The
 * key-handling code is meant to be readable by a firm's security reviewer
 * without shipping them the drafting engine, and three imports were dragging
 * essentially the entire app behind ~1,400 lines of crypto.
 *
 * Inverting them costs one indirection and buys a module whose whole dependency
 * surface is three functions a reader can see at a glance. It also makes the
 * signer testable without standing up an IndexedDB, an auth session and the
 * model router.
 *
 * The defaults are deliberately inert rather than clever: an unwired host
 * behaves like a signed-out device with no gateway, which the signer already
 * handles as `unsigned` with a stated reason. Nothing silently half-works.
 */

export interface EvidenceHost {
  /** Small key-value store for this device's signing key and its id. */
  store: {
    get(key: string): Promise<unknown>;
    set(key: string, value: unknown): Promise<void>;
    remove(key: string): Promise<void>;
  };
  /** The current bearer token, or null when signed out. Synchronous by design:
   *  the signer checks it on paths that must not await. */
  accessToken(): string | null;
  /** The full session, for the identity recorded alongside a signature. */
  session(): Promise<{ user?: { email?: string; id?: string } } | null>;
  /** The firm's gateway base URL, or null for a solo user. */
  firmGatewayUrl(): Promise<string | null>;
}

const inert: EvidenceHost = {
  store: {
    async get() { return undefined; },
    async set() { /* no host wired: nothing to persist to */ },
    async remove() { /* as above */ },
  },
  accessToken: () => null,
  session: async () => null,
  firmGatewayUrl: async () => null,
};

let host: EvidenceHost = inert;

/** Wire the app in. Called once, from the app's startup path. */
export function setEvidenceHost(next: EvidenceHost | null): void {
  host = next ?? inert;
}

export function evidenceHost(): EvidenceHost {
  return host;
}
