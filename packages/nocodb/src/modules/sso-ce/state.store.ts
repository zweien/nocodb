import { randomTokenString } from '~/helpers/stringHelpers';

interface StateEntry {
  codeVerifier: string;
  createdAt: number;
}

const STORE = new Map<string, StateEntry>();
const TTL_MS = 60_000;

/**
 * In-process OAuth2 `state` nonce store (CSRF protection).
 *
 * Each entry also carries the PKCE code_verifier so the callback can complete
 * the authorization code exchange. Single-instance only — see spec §8.
 */
export function issueState(codeVerifier: string): string {
  const state = randomTokenString();
  STORE.set(state, { codeVerifier, createdAt: Date.now() });
  return state;
}

export function consumeState(state: string): { codeVerifier: string } | null {
  const entry = STORE.get(state);
  if (!entry) return null;
  STORE.delete(state); // single-use
  if (Date.now() - entry.createdAt > TTL_MS) return null;
  return { codeVerifier: entry.codeVerifier };
}

/** Test-only helper to reset the store between tests. */
export function __clearStateStoreForTests(): void {
  STORE.clear();
}
