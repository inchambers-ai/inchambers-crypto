/**
 * Sync key service: which key encrypts cross-device sync, and who holds it.
 *
 * ## One generation, and why there is only one
 *
 *     personal  scv3:   HKDF(user_half || firm_half, salt = org_id,
 *                            info = "ic-sync-dek-v3:" + sub)
 *     shared    socv3:  HKDF(org_secret || firm_org_half, salt = org_id,
 *                            info = "ic-sync-org-dek-v3")
 *
 * `user_half` comes from the user's own passkey (see `passkeyHalf.ts`).
 * `firm_half` comes from the firm's own gateway. InChambers holds neither.
 *
 * Two earlier generations existed and are GONE, not deprecated:
 *
 *   v1  the whole key from `/api/user/sync-key`, which we derived from a server
 *       secret and could reproduce for any user on demand.
 *   v2  HKDF(our half || the firm's half). Neither party alone, but we were
 *       still one of the two, so a firm could not read its own files without us.
 *
 * They are deleted rather than kept readable because no production data was
 * ever encrypted under them. Keeping a dual-read path "just in case" would have
 * meant keeping `SYNC_DEK_SECRET` alive, and a key we still hold is a key we can
 * still be compelled to produce. The dead branches would also have been the
 * obvious place for a future downgrade bug to hide.
 *
 * The consequence is deliberate and worth stating plainly: THERE IS NO
 * FALLBACK. A user who has not enrolled an authenticator does not sync. That is
 * the hard requirement, chosen over a weaker path that would have quietly
 * reintroduced the custody this removes.
 *
 * Every key is a NON-extractable AES-GCM CryptoKey, so script injection can use
 * one while the tab is open but cannot exfiltrate it.
 *
 * Deliberately dependency-free apart from its three injected seams, because
 * this module is published for audit. See `deviceKeyCache.ts`,
 * `tokenProvider.ts` and `syncTransport.ts`.
 */

import { readCachedKey, writeCachedKey } from './deviceKeyCache';
import { authToken } from './tokenProvider';
import { syncTransport } from './syncTransport';

export type SyncKeyState = 'off' | 'ready';

type Listener = (state: SyncKeyState) => void;

const PAYLOAD_PREFIX_V3 = 'scv3:';
const ORG_PAYLOAD_PREFIX_V3 = 'socv3:';

/**
 * DEK = HKDF-SHA256(ikm = first || second, salt = org_id, info = label).
 *
 * All the secrecy is in the two halves. `org_id` and the user id go in
 * salt/info purely as domain separation, so one user's key cannot open
 * another's rows and one firm's cannot open another's. They are NOT secrets: a
 * gateway domain is public and inchambers stores the identifiers. An early
 * proposal to derive the firm half FROM those identifiers would have made the
 * key computable by anyone who knew an email address.
 */
async function deriveDekFromHalves(
  first: Uint8Array,
  second: Uint8Array,
  orgId: string,
  info: string,
): Promise<CryptoKey> {
  const ikm = new Uint8Array(first.length + second.length);
  ikm.set(first);
  ikm.set(second, first.length);
  try {
    const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode(orgId) as BufferSource,
        info: new TextEncoder().encode(info) as BufferSource,
      },
      base,
      256,
    );
    return await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally {
    ikm.fill(0);
  }
}

/**
 * What the passkey layer could establish on this device.
 *
 * `blocked` is not a failure and must not be treated as one: it is the Word
 * taskpane, permanently, and the answer is a popout rather than a retry.
 */
export type PasskeyState =
  | 'ready'
  /** Enrolled elsewhere, but this device cannot ask the authenticator. */
  | 'blocked'
  /** No wraps exist: this user has never enrolled, so sync cannot run. */
  | 'not-enrolled'
  /** Wraps exist and none opened here. */
  | 'locked'
  /** Gateway too old to serve key wraps. */
  | 'unsupported'
  | 'unknown';

/**
 * The `sub` and `org_id` the gateway used when deriving its half.
 *
 * Read from the JWT rather than app state so both sides agree by construction:
 * the relay derives from `claims.sub`, and a mismatch here would produce a key
 * that decrypts nothing, on every device, silently.
 */
function decodeIdentity(token: string): { sub: string; orgId: string } {
  try {
    const payload = token.split('.')[1];
    if (!payload) return { sub: '', orgId: '' };
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json);
    return { sub: String(claims?.sub || ''), orgId: String(claims?.org_id || '') };
  } catch {
    return { sub: '', orgId: '' };
  }
}

class SyncKeyService {
  private state: SyncKeyState = 'off';
  private listeners = new Set<Listener>();
  private loading: Promise<boolean> | null = null;

  /** This user's firm half (base64), and the org-wide one. From the gateway. */
  private firmHalfB64: string | null = null;
  private firmOrgHalfB64: string | null = null;

  private dekV3: CryptoKey | null = null;
  private orgDekV3: CryptoKey | null = null;
  private passkey: PasskeyState = 'unknown';

  /** Fetch the firm's halves. Idempotent / de-duped. */
  async init(): Promise<boolean> {
    if (this.firmHalfB64) return true;
    if (this.loading) return this.loading;
    this.loading = this.fetchFirmHalves().finally(() => { this.loading = null; });
    return this.loading;
  }

  /**
   * The gateway's halves. Nothing is fetched from inchambers, because there is
   * no inchambers half any more, which is the entire point of the design.
   */
  private async fetchFirmHalves(): Promise<boolean> {
    try {
      const result = await syncTransport().fetchFirmKeyHalf();
      if (result.status !== 'ok') {
        // 'unsupported' means a gateway too old to serve a half. There is
        // nothing to fall back TO now, so this is off rather than degraded.
        this.setState('off');
        return false;
      }
      this.firmHalfB64 = result.half;
      this.firmOrgHalfB64 = result.orgHalf;
      this.setState('ready');
      return true;
    } catch (err) {
      console.error('IC-SYNCKEY-FETCH', err);
      this.suspend();
      return false;
    }
  }

  /** Whether the personal key is derived and usable. */
  isPasskeyKey(): boolean {
    return this.passkey === 'ready' && this.dekV3 !== null;
  }

  getPasskeyState(): PasskeyState {
    return this.passkey;
  }

  /**
   * Establish the passkey-derived keys for this device.
   *
   * The DEVICE CACHE is tried first, and not as an optimisation: the Word
   * taskpane cannot call WebAuthn at all (cross-origin frame, and Office never
   * grants `publickey-credentials-get`), so a cached non-extractable key is the
   * only thing that lets it sync. Only when there is no cache does this reach
   * for the authenticator, which is also the only path that can populate it.
   *
   * Never mints a half. A first enrolment is an explicit, user-visible act in
   * the enrolment UI, because generating one here would silently create a
   * SECOND half for a user who already had one and orphan everything written
   * under the first.
   */
  async initPasskey(userId: string): Promise<PasskeyState> {
    if (this.dekV3) return (this.passkey = 'ready');
    if (!this.firmHalfB64) return this.passkey;

    const cached = await readCachedKey(this.cacheKey(userId));
    if (cached) {
      this.dekV3 = cached;
      const cachedOrg = await readCachedKey(this.orgCacheKey(userId));
      if (cachedOrg) {
        this.orgDekV3 = cachedOrg;
        return (this.passkey = 'ready');
      }
      // Personal key cached but no org key. Either this firm has no shared
      // secret yet, in which case there is nothing to derive, or this device
      // predates the org key and must unlock once to get it. Guessing the first
      // would leave the device permanently unable to read colleagues' shared
      // content, so ask.
      const orgState = await syncTransport().fetchOrgSecretState();
      if (orgState.status !== 'ok' || !orgState.established) {
        return (this.passkey = 'ready');
      }
      // Falls through to the unlock below, which derives and caches the org key.
    }

    const result = await syncTransport().fetchKeyWraps();
    if (result.status === 'unsupported') return (this.passkey = 'unsupported');
    if (result.status === 'error') return (this.passkey = 'unknown');
    if (!result.wraps.length) return (this.passkey = 'not-enrolled');

    const { unlockUserHalf, prfCapability } = await import('./passkeyHalf');
    if (prfCapability() !== 'available') return (this.passkey = 'blocked');

    const token = await authToken();
    const { sub, orgId } = decodeIdentity(token || '');
    if (!sub || !orgId) return (this.passkey = 'unknown');

    const rpId = typeof window !== 'undefined' ? window.location.hostname : '';
    const unlocked = await unlockUserHalf(result.wraps, rpId);
    if (unlocked.status !== 'ok') {
      return (this.passkey = unlocked.status === 'not-enrolled' ? 'not-enrolled' : 'locked');
    }

    await this.adoptUserHalf(unlocked.userHalf, userId, sub, orgId);
    // Shared content, resolved HERE because this is the only moment the user's
    // half is in memory: the member's private key is wrapped under it, and
    // everything downstream needs that key. Best-effort, because a member who
    // has not yet been given the firm secret must still get personal sync.
    try {
      await this.initOrgSecret(unlocked.userHalf, sub, orgId, userId);
    } catch (e) {
      console.error('IC-SYNCKEY-ORG-SECRET', e);
    }
    unlocked.userHalf.fill(0);
    return (this.passkey = 'ready');
  }

  /**
   * Derive and cache from a freshly unlocked (or freshly generated) half.
   *
   * Public because enrolment lives in the UI layer: it creates the half, stores
   * the wrap, and hands the bytes here. Keeping the derivation in one place is
   * what stops enrolment and unlock disagreeing about the info string.
   */
  async adoptUserHalf(
    userHalf: Uint8Array,
    userId: string,
    sub: string,
    orgId: string,
  ): Promise<void> {
    if (!this.firmHalfB64) throw new Error('firm half not resolved');
    const firmHalf = Uint8Array.from(atob(this.firmHalfB64), c => c.charCodeAt(0));
    try {
      this.dekV3 = await deriveDekFromHalves(userHalf, firmHalf, orgId, `ic-sync-dek-v3:${sub}`);
      this.passkey = 'ready';
      await writeCachedKey(this.cacheKey(userId), this.dekV3);
    } finally {
      firmHalf.fill(0);
    }
  }

  /**
   * Derive the shared-content key from the firm secret.
   *
   * Cached alongside the personal key, and for the same reason: a key the Word
   * taskpane cannot restore from cache is a key it will never have. Without
   * this, every device after its first session read `socv3:` rows it could not
   * open, and `applyRemote` stalls a kind rather than skipping, so one member
   * writing shared content froze every colleague's org sync.
   */
  async adoptOrgSecret(secret: Uint8Array, orgId: string, userId?: string): Promise<void> {
    if (!this.firmOrgHalfB64) throw new Error('firm org half not resolved');
    const firmOrgHalf = Uint8Array.from(atob(this.firmOrgHalfB64), c => c.charCodeAt(0));
    try {
      this.orgDekV3 = await deriveDekFromHalves(secret, firmOrgHalf, orgId, 'ic-sync-org-dek-v3');
      if (userId) await writeCachedKey(this.orgCacheKey(userId), this.orgDekV3);
    } finally {
      firmOrgHalf.fill(0);
    }
  }

  /** Whether shared content has a key. */
  isOrgPasskeyKey(): boolean {
    return this.orgDekV3 !== null;
  }

  /**
   * Establish the firm secret for shared content, and derive the org key.
   *
   * Creating a firm secret when one already exists would SPLIT THE FIRM --
   * content written under each unreadable by holders of the other, with nothing
   * erroring -- so `resolveOrgSecret` only creates when the gateway positively
   * reports that no member holds one.
   */
  private async initOrgSecret(
    userHalf: Uint8Array,
    sub: string,
    orgId: string,
    userId: string,
  ): Promise<void> {
    const t = syncTransport();
    const state = await t.fetchOrgSecretState();
    if (state.status !== 'ok') return;

    const { ensureMemberKey, resolveOrgSecret, shareWithPendingMembers } =
      await import('./orgSecret');

    const memberKey = await ensureMemberKey(
      state.memberKey, userHalf, sub,
      (publicSpki, wrappedPrivate) => t.putMemberKey(publicSpki, wrappedPrivate),
    );

    const resolved = await resolveOrgSecret({
      wrap: state.wrap,
      established: state.established,
      memberKey,
      publishWraps: (wraps) => t.putOrgSecretWraps(wraps),
      selfSub: sub,
    });
    if (resolved.status !== 'ok') return;

    try {
      await this.adoptOrgSecret(resolved.secret, orgId, userId);
      // Any colleague who has registered a public key but holds no wrap yet.
      // Doing this from every member who CAN means onboarding does not wait on
      // one particular person happening to sign in.
      const pending = await t.listMembersAwaitingSecret();
      const shared = await shareWithPendingMembers(
        resolved.secret,
        pending.filter(m => m.ownerSub !== sub),
        (wraps) => t.putOrgSecretWraps(wraps),
      );
      if (shared > 0) {
        console.warn('IC-SYNC-ORG-SHARED', { shared, detail: 'firm secret shared with new members' });
      }
    } finally {
      resolved.secret.fill(0);
    }
  }

  private cacheKey(userId: string): string {
    return `sync_dek_v3:${userId}`;
  }

  private orgCacheKey(userId: string): string {
    return `sync_org_dek_v3:${userId}`;
  }

  /** Drop everything on logout / user switch. Re-derived on next init. */
  suspend(): void {
    this.loading = null;
    this.firmHalfB64 = null;
    this.firmOrgHalfB64 = null;
    this.dekV3 = null;
    this.orgDekV3 = null;
    // Reset to 'unknown', never to a settled answer: the next user on this
    // device may be enrolled when this one was not, and a stale 'not-enrolled'
    // would send them into a first-enrolment flow that mints a SECOND half and
    // orphans everything they already have.
    this.passkey = 'unknown';
    this.setState('off');
  }

  /** Whether the engine may sync at all. */
  isReady(): boolean {
    return this.state === 'ready' && this.dekV3 !== null;
  }

  /** Whether the engine may push ORG kinds. */
  isOrgKeyReady(): boolean {
    return this.orgDekV3 !== null;
  }

  getState(): SyncKeyState {
    return this.state;
  }

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // --- Payload crypto (used by the sync engine) ------------------------------

  /**
   * Which key a WRITE must use.
   *
   * There is no branch here any more, and its absence IS the feature. The old
   * version had to choose between three generations and refuse to downgrade;
   * now the only key that exists is the one inchambers holds no part of, so
   * "write the weaker one" is not a state this code can reach.
   */
  private writeKey(org: boolean): { key: CryptoKey; prefix: string } {
    const key = org ? this.orgDekV3 : this.dekV3;
    if (!key) {
      throw new Error(
        org
          ? 'org sync key not ready: the firm secret has not reached this device'
          : `sync key not ready: passkey ${this.passkey}`,
      );
    }
    return { key, prefix: org ? ORG_PAYLOAD_PREFIX_V3 : PAYLOAD_PREFIX_V3 };
  }

  /**
   * Which key a READ needs.
   *
   * A missing key THROWS rather than skipping. `applyRemote` turns a throw into
   * a stalled kind that resumes once the device unlocks, where a skip would
   * advance the high-water mark past the row and lose it permanently.
   */
  private readKey(ciphertext: string, org: boolean): { key: CryptoKey; prefix: string } {
    const prefix = org ? ORG_PAYLOAD_PREFIX_V3 : PAYLOAD_PREFIX_V3;
    if (!ciphertext.startsWith(prefix)) {
      throw new Error(org ? 'unrecognized org sync payload' : 'unrecognized sync payload');
    }
    const key = org ? this.orgDekV3 : this.dekV3;
    if (!key) {
      throw new Error(
        org
          ? 'org sync key not ready: firm secret missing'
          : 'sync key not ready: passkey key missing',
      );
    }
    return { key, prefix };
  }

  private async seal(plaintext: string, org: boolean): Promise<string> {
    const { key, prefix } = this.writeKey(org);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    const combined = new Uint8Array(iv.length + ct.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ct), iv.length);
    let binary = '';
    const CHUNK = 8192;
    for (let i = 0; i < combined.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, combined.subarray(i, Math.min(i + CHUNK, combined.length)) as unknown as number[]);
    }
    return prefix + btoa(binary);
  }

  private async open(ciphertext: string, org: boolean): Promise<string> {
    const { key, prefix } = this.readKey(ciphertext, org);
    const raw = Uint8Array.from(atob(ciphertext.slice(prefix.length)), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12) as BufferSource,
    );
    return new TextDecoder().decode(pt);
  }

  encryptPayload(plaintext: string): Promise<string> { return this.seal(plaintext, false); }
  decryptPayload(ciphertext: string): Promise<string> { return this.open(ciphertext, false); }
  encryptOrgPayload(plaintext: string): Promise<string> { return this.seal(plaintext, true); }
  decryptOrgPayload(ciphertext: string): Promise<string> { return this.open(ciphertext, true); }

  private setState(state: SyncKeyState): void {
    if (this.state === state) return;
    this.state = state;
    for (const l of this.listeners) {
      try { l(state); } catch (e) { console.error('IC-SYNCKEY-LISTENER', e); }
    }
  }
}

export const syncKeyService = new SyncKeyService();
export default syncKeyService;
