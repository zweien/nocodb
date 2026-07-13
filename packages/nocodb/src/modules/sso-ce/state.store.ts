import { randomTokenString } from '~/helpers/stringHelpers';

const STORE = new Map<string, number>(); // state -> createdAt ms
const TTL_MS = 60_000;

/**
 * In-process OAuth2 `state` nonce store (CSRF protection).
 *
 * Single-instance only — see spec §8. If NocoDB is ever scaled horizontally,
 * swap this for Redis.
 */
export function issueState(): string {
  const state = randomTokenString();
  STORE.set(state, Date.now());
  return state;
}

export function consumeState(state: string): boolean {
  const createdAt = STORE.get(state);
  if (createdAt === undefined) return false;
  STORE.delete(state); // single-use
  if (Date.now() - createdAt > TTL_MS) return false;
  return true;
}

/** Test-only helper to reset the store between tests. */
export function __clearStateStoreForTests(): void {
  STORE.clear();
}
