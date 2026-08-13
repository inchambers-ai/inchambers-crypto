/**
 * @jest-environment jsdom
 */
/// <reference types="jest" />
/**
 * The firm-wide secret behind shared content.
 *
 * Two failures matter here and neither announces itself.
 *
 * SPLITTING THE FIRM. Creating a second org secret makes content written under
 * each unreadable by holders of the other, with no error anywhere. So a secret
 * is only ever created when the gateway positively reports that no member holds
 * one, and `waits rather than creating` covers the realistic ways that goes
 * wrong: an existing secret we cannot open, and a firm that already has one.
 *
 * ONBOARDING WITHOUT A RENDEZVOUS. The whole reason this layer is asymmetric is
 * that a new member has to be given the secret by someone who may be asleep.
 * `a colleague can share with a member who is not present` is that property, and
 * it is what justifies the extra machinery over the symmetric wrapping used
 * everywhere else.
 */

import { webcrypto } from 'crypto';

if (!(globalThis as { crypto?: Crypto }).crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto as unknown as Crypto,
    configurable: true,
  });
}

import { ensureMemberKey, resolveOrgSecret, shareWithPendingMembers } from '../orgSecret';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const HALF_A = new Uint8Array(32).fill(3);
const HALF_B = new Uint8Array(32).fill(4);

/** A member: their own half, and whatever the gateway has stored for them. */
async function member(sub: string, half: Uint8Array) {
  let stored: { publicSpki: string; wrappedPrivate: string } | null = null;
  const key = await ensureMemberKey(stored, half, sub, async (publicSpki, wrappedPrivate) => {
    stored = { publicSpki, wrappedPrivate };
  });
  return { sub, half, key, get stored() { return stored; } };
}

describe('member keypair', () => {
  /**
   * A second device must recover the SAME keypair, or every org-secret wrap
   * addressed to the old public key is orphaned and the member has to go back
   * through a colleague for no reason.
   */
  it('recovers the same key on another device from the stored wrap', async () => {
    const first = await member('user-1', HALF_A);
    const stored = first.stored!;

    const publish = jest.fn();
    const second = await ensureMemberKey(stored, HALF_A, 'user-1', publish);

    expect(second.publicSpki).toBe(stored.publicSpki);
    expect(publish).not.toHaveBeenCalled();
  });

  /**
   * The stored private key is wrapped under the member's own half, so another
   * user's half must not open it. If it did, the gateway holding both rows
   * would be holding a usable key.
   */
  it('cannot be recovered with a different half', async () => {
    const first = await member('user-1', HALF_A);
    const publish = jest.fn();
    // A wrong half fails to unwrap, so a NEW keypair is generated and published
    // rather than the wrong one being returned.
    const other = await ensureMemberKey(first.stored, HALF_B, 'user-1', publish);
    expect(publish).toHaveBeenCalled();
    expect(other.publicSpki).not.toBe(first.stored!.publicSpki);
  });
});

describe('resolving the firm secret', () => {
  it('creates one when the firm genuinely has none', async () => {
    const m = await member('user-1', HALF_A);
    const publishWraps = jest.fn(async () => {});
    const res = await resolveOrgSecret({
      wrap: null, established: false, memberKey: m.key,
      publishWraps, selfSub: 'user-1',
    });

    expect(res.status).toBe('ok');
    if (res.status !== 'ok') return;
    expect(res.created).toBe(true);
    expect(res.secret.length).toBe(32);
    expect(publishWraps).toHaveBeenCalledTimes(1);
  });

  /**
   * THE SPLIT. A firm that already has a secret must never get a second one,
   * even from a member who holds no wrap yet. Both would be valid and content
   * written under each would be invisible to the other half of the firm.
   */
  it('waits rather than creating when the firm already has a secret', async () => {
    const m = await member('user-2', HALF_B);
    const publishWraps = jest.fn(async () => {});
    const res = await resolveOrgSecret({
      wrap: null, established: true, memberKey: m.key,
      publishWraps, selfSub: 'user-2',
    });

    expect(res.status).toBe('awaiting-colleague');
    expect(publishWraps).not.toHaveBeenCalled();
  });

  /**
   * A wrap that will not open is addressed to a key we no longer hold. That is
   * not evidence the firm has no secret, so it must not fall through to
   * creating one.
   */
  it('waits rather than creating when its own wrap will not open', async () => {
    const mine = await member('user-1', HALF_A);
    const theirs = await member('user-2', HALF_B);
    // Sealed to the OTHER member, so it cannot open with our private key.
    const { sealTo } = await import('../ecies');
    const sealed = await sealTo(
      new Uint8Array(32).fill(9), theirs.key.publicSpki, 'ic-org-secret-v1',
    );

    const publishWraps = jest.fn(async () => {});
    const res = await resolveOrgSecret({
      wrap: { sealed, generation: 1 }, established: true, memberKey: mine.key,
      publishWraps, selfSub: 'user-1',
    });

    expect(res.status).toBe('awaiting-colleague');
    expect(publishWraps).not.toHaveBeenCalled();
  });

  it('opens its own wrap and reports the same secret', async () => {
    const m = await member('user-1', HALF_A);
    const secret = new Uint8Array(32).fill(17);
    const { sealTo } = await import('../ecies');
    const sealed = await sealTo(secret, m.key.publicSpki, 'ic-org-secret-v1');

    const res = await resolveOrgSecret({
      wrap: { sealed, generation: 1 }, established: true, memberKey: m.key,
      publishWraps: async () => {}, selfSub: 'user-1',
    });

    expect(res.status).toBe('ok');
    if (res.status !== 'ok') return;
    expect(hex(res.secret)).toBe(hex(secret));
    expect(res.created).toBe(false);
  });
});

describe('sharing with colleagues', () => {
  /**
   * THE REASON THIS LAYER IS ASYMMETRIC. The newcomer is not online, holds no
   * shared state, and still ends up with the firm's secret.
   */
  it('a colleague can share with a member who is not present', async () => {
    const existing = await member('partner', HALF_A);
    const newcomer = await member('associate', HALF_B);
    const secret = new Uint8Array(32).fill(21);

    let published: Array<{ ownerSub: string; sealed: string }> = [];
    const count = await shareWithPendingMembers(
      secret,
      [{ ownerSub: 'associate', publicSpki: newcomer.key.publicSpki }],
      async (w) => { published = w; },
    );
    expect(count).toBe(1);

    // The newcomer, later, alone.
    const res = await resolveOrgSecret({
      wrap: { sealed: published[0].sealed, generation: 1 },
      established: true, memberKey: newcomer.key,
      publishWraps: async () => {}, selfSub: 'associate',
    });
    expect(res.status).toBe('ok');
    if (res.status !== 'ok') return;
    expect(hex(res.secret)).toBe(hex(secret));

    // ...and it is genuinely addressed: the partner cannot open it either.
    await expect(resolveOrgSecret({
      wrap: { sealed: published[0].sealed, generation: 1 },
      established: true, memberKey: existing.key,
      publishWraps: async () => {}, selfSub: 'partner',
    })).resolves.toEqual({ status: 'awaiting-colleague' });
  });

  it('does nothing when there is nobody waiting', async () => {
    const publish = jest.fn(async () => {});
    expect(await shareWithPendingMembers(new Uint8Array(32), [], publish)).toBe(0);
    expect(publish).not.toHaveBeenCalled();
  });
});
