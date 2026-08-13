# InChambers key handling

This is the cryptography and key-handling code from
[InChambers](https://inchambers.ai), a privacy-first assistant for law firms,
published so the claims we make about it can be checked rather than taken on
trust.

It is a mirror. The authoritative source is the private product repository, and
this is pushed automatically on every change, gated on a test that proves these
files import nothing proprietary.

## The claim this code is meant to support

> Your encryption key is derived from your own security key and, for firms, your
> firm's own gateway. InChambers holds no part of it and cannot read your work
> product, including under legal compulsion.

The interesting files:

| File | What to read it for |
|---|---|
| `sync/passkeyHalf.ts` | The user's half: 32 random bytes, wrapped once per authenticator under a WebAuthn PRF secret. Why it is a wrapped random secret rather than the PRF output itself. |
| `sync/passkeyEnrollment.ts` | When a half is created, and the rule that it must never be created twice. |
| `sync/syncKeyService.ts` | The three key generations, and why the newest always wins a write. |
| `sync/orgSecret.ts` | How a firm shares one key across its members without either us or the gateway seeing it. |
| `sync/ecies.ts` | The envelope used for escrow and for sharing. |
| `content/contentCrypto.ts` | Solo practitioners' Drive-backed records. |
| `evidence/` | Tamper-evident export bundles. |

The tests are included, and several of them ARE the argument rather than a
check on it: `a stored wrap alone does not reveal the half`, `the inchambers
half alone cannot decrypt`, `a second authenticator opens the SAME half`.

## What this does not prove

Reading this proves the key handling is honest. It does not prove the code
running in your browser is this code. That is a separate mechanism: every
client release is published as a signed digest of every file, recorded in the
public Sigstore transparency log, and checkable against a live deployment with

```
node scripts/verify-client-release.js --origin https://app.inchambers.ai
```

A firm's own gateway performs the same check continuously and refuses to release
its half of the encryption key to a client build that is not the published
release.

`PRIVACY.mdx` describes the whole architecture, including a "what this does not
cover" section that we would rather write ourselves than have found.

## Reporting a problem

Security issues: security@inchambers.ai. If you find something here that
contradicts what we say publicly, we want to know before your clients do.

Licensed under Apache 2.0. See `LICENSE`.
