import { randomTokenString } from '~/helpers/stringHelpers';

interface Entry {
  user: any;
  createdAt: number;
}

const STORE = new Map<string, Entry>();
const TTL_MS = 60_000;

/**
 * In-process short-lived token store.
 *
 * Bridges the backend OIDC callback (which runs server-side and cannot set
 * the frontend's auth cookie directly) to the frontend's
 * `tryShortTokenAuth` flow. The frontend POSTs /auth/long-lived-token with
 * the short token in the `xc-short-token` header, and this store redeems it
 * for the authenticated user object.
 *
 * Single-instance only — see spec §8.
 */
export function issueShortToken(user: any): string {
  const token = randomTokenString();
  STORE.set(token, { user, createdAt: Date.now() });
  return token;
}

export function consumeShortToken(token: string): any | null {
  const entry = STORE.get(token);
  if (!entry) return null;
  STORE.delete(token); // single-use — matches upstream commit 5265a83312
  if (Date.now() - entry.createdAt > TTL_MS) return null;
  return entry.user;
}

/** Test-only helper. */
export function __clearShortTokenStoreForTests(): void {
  STORE.clear();
}
