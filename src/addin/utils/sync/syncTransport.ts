/**
 * How the key modules talk to a firm gateway.
 *
 * WHY THIS EXISTS, AND WHY ITS ABSENCE WAS A REAL HOLE.
 * `syncKeyService` dynamically imported `syncClient` for the firm half and the
 * key wraps. `syncClient` imports `connectors/pma/pmaGatewayClient` to resolve
 * the gateway base URL, which drags practice-management transport in behind the
 * crypto. The publishability gate was passing only because `./syncClient` had
 * been added to its allow-list -- a self-granted exception that would have
 * produced a public repo that could not build, which is precisely what that
 * gate is meant to prevent.
 *
 * So the transport is an interface, like the device cache and the token
 * provider before it. A reader of the published code sees exactly which calls
 * the crypto makes and what shapes come back, without the gateway-resolution
 * machinery.
 *
 * THE DEFAULT IS 'unsupported', NOT AN ERROR. With nothing wired, the key
 * modules behave as they do against a gateway that predates these endpoints,
 * which is a state they already handle correctly. Nothing half-works and
 * nothing throws from a module that was only imported.
 */

import type { KeyWrap } from './passkeyHalf';

/** Three-way on purpose. See the note in `fetchFirmKeyHalf` about downgrade. */
export type HalfResult =
  | { status: 'ok'; half: string; orgHalf: string }
  | { status: 'unsupported' }
  | { status: 'error' };

export type WrapsResult =
  | {
      status: 'ok';
      wraps: KeyWrap[];
      escrowKey: { publicSpki: string; fingerprint: string } | null;
      escrowedFingerprint: string | null;
    }
  | { status: 'unsupported' }
  | { status: 'error' };

/** This member's keypair and their wrap of the firm secret, if any. */
export type OrgSecretState =
  | {
      status: 'ok';
      memberKey: { publicSpki: string; wrappedPrivate: string } | null;
      wrap: { sealed: string; generation: number } | null;
      /** Whether ANY member holds the firm secret. Creating a second one when
       *  this is true would split the firm, so it is never inferred. */
      established: boolean;
    }
  | { status: 'unsupported' }
  | { status: 'error' };

export interface SyncTransport {
  fetchFirmKeyHalf(): Promise<HalfResult>;
  fetchKeyWraps(): Promise<WrapsResult>;
  fetchOrgSecretState(): Promise<OrgSecretState>;
  putMemberKey(publicSpki: string, wrappedPrivate: string): Promise<void>;
  putOrgSecretWraps(wraps: Array<{ ownerSub: string; sealed: string }>): Promise<void>;
  listMembersAwaitingSecret(): Promise<Array<{ ownerSub: string; publicSpki: string }>>;
}

const unwired: SyncTransport = {
  async fetchFirmKeyHalf() { return { status: 'unsupported' }; },
  async fetchKeyWraps() { return { status: 'unsupported' }; },
  async fetchOrgSecretState() { return { status: 'unsupported' }; },
  async putMemberKey() { /* nothing to talk to */ },
  async putOrgSecretWraps() { /* as above */ },
  async listMembersAwaitingSecret() { return []; },
};

let transport: SyncTransport = unwired;

/** Wire the real gateway client in. Called once, from the app's startup path. */
export function setSyncTransport(next: SyncTransport | null): void {
  transport = next ?? unwired;
}

export function syncTransport(): SyncTransport {
  return transport;
}
