/**
 * How the key modules obtain a bearer token.
 *
 * WHY IT IS NOT JUST `authClient`. `syncKeyService` and `contentCrypto` reached
 * for `customAuthClient` (1,590 lines) to get a token, falling back to the
 * `ic_access_token` mirror when it was unavailable. Inside one application that
 * is unremarkable. For code published so a firm's security reviewer can read
 * what handles their keys, it drags the entire auth layer along behind ~1,400
 * lines of crypto.
 *
 * The inversion is nearly free here, because the FALLBACK was already the
 * dependency-free path. `customAuthClient` mirrors every session change into
 * `localStorage['ic_access_token']` precisely so callers that cannot import it
 * still have a source. So the default below is that mirror, and it works with
 * nothing wired at all; the app overrides it with the live client, which is
 * fresher because it can refresh an expired token rather than reading a stale
 * one.
 *
 * A published reader therefore sees exactly how a token is obtained, and can
 * see that it is a string read from local storage rather than something the
 * crypto reaches into the application for.
 */

export type TokenProvider = () => Promise<string | null>;

/**
 * The mirror `customAuthClient` maintains on every session change. Correct on
 * its own, merely not self-refreshing.
 */
const fromMirror: TokenProvider = async () => {
  try {
    return localStorage.getItem('ic_access_token');
  } catch {
    return null;
  }
};

let provider: TokenProvider = fromMirror;

/** Wire the live auth client in. Called once, from the app's startup path. */
export function setTokenProvider(next: TokenProvider | null): void {
  provider = next ?? fromMirror;
}

export function authToken(): Promise<string | null> {
  return provider();
}
