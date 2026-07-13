# OIDC SSO for NocoDB CE — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Authentik OIDC SSO login to NocoDB Community Edition by filling in the SSO route controllers and IdP client that EE ships but CE omits — without diverging from upstream.

**Architecture:** A new isolated NestJS module `sso-ce` under `packages/nocodb/src/modules/sso-ce/` exposes three HTTP routes (`GET /auth/oidc`, `GET /auth/oidc/callback`, `POST /auth/long-lived-token`) that the existing `nc-gui` frontend already calls. It uses `openid-client` directly (no Passport OIDC wrapper, to avoid the `express-session` dependency). Configuration is via environment variables. The only existing file touched is `auth.module.ts`, with an append-only edit. A short-lived in-process token store bridges the backend callback to the frontend's existing `tryShortTokenAuth` flow.

**Tech Stack:** NestJS, `openid-client` v6, TypeScript, jest. Reuses `UsersService.registerNewUserIfAllowed`, `genJwt`, `sanitiseUserObj`, `randomTokenString`.

**Spec:** `docs/superpowers/specs/2026-07-13-oidc-sso-ce-design.md`

## Global Constraints

- All new code lives under `packages/nocodb/src/modules/sso-ce/`.
- The only existing file modified is `packages/nocodb/src/modules/auth/auth.module.ts` (append-only: add one import line, one controller entry, one provider entry).
- `package.json` is modified only to add `openid-client` as a direct dependency.
- No new DB migrations. No use of the `nc_sso_client` table.
- No frontend changes.
- Env vars: `NC_SSO=oidc` (CE already reads), `NC_OIDC_PROVIDER_NAME` (CE already reads), `NC_OIDC_ISSUER`, `NC_OIDC_CLIENT_ID`, `NC_OIDC_CLIENT_SECRET`, `NC_OIDC_SCOPES` (default `openid profile email`), `NC_OIDC_SSO_CLIENT_ID` (default `oidc`).
- `NC_CLOUD=true` must never be set.
- Test files must end in `Source.spec.ts` or `Integration.spec.ts` to be picked up by jest (see `jest.config.js:8` `testRegex`).
- Git commits go on branch `develop-sso-ce` (already created). Each task ends with a commit.
- Existing helpers to reuse: `randomTokenString` from `~/helpers/stringHelpers`, `sanitiseUserObj` from `~/utils`, `genJwt`/`setAuthCookie` from `~/services/users/helpers`, `ncSiteUrl` from `~/utils/envs`.

---

## File Structure

```
packages/nocodb/src/modules/sso-ce/
├── sso-ce.module.ts              # NestJS Module declaration
├── sso-ce.controller.ts          # 3 HTTP routes
├── oidc.client.ts                # @Injectable — openid-client wrapper + user resolver
├── oidc.config.ts                # env-reading helper (pure functions)
├── short-lived-token.store.ts    # in-process Map, 60s TTL, single-use
├── state.store.ts                # in-process Map for OAuth2 state nonces, 60s TTL
├── oidc.config.Source.spec.ts    # unit tests for config helper
├── short-lived-token.store.Source.spec.ts  # unit tests for token store
└── state.store.Source.spec.ts    # unit tests for state store
```

Modified existing files:
- `packages/nocodb/src/modules/auth/auth.module.ts` — register `SsoCeController` + `OidcClient`.
- `packages/nocodb/package.json` — add `openid-client` dependency.

---

## Task 1: Add `openid-client` dependency

**Files:**
- Modify: `packages/nocodb/package.json`

**Interfaces:**
- Produces: `openid-client` importable from `packages/nocodb/src/`.

- [ ] **Step 1: Check NocoDB's package manager**

Run: `head -5 /home/z/codebase/nocodb/package.json`
Expected: see `"packageManager": "pnpm@..."` or similar. NocoDB uses pnpm workspaces.

- [ ] **Step 2: Add openid-client to packages/nocodb/package.json**

Run from repo root:
```bash
cd /home/z/codebase/nocodb/packages/nocodb && pnpm add openid-client@^6
```
Expected: `openid-client` added to `dependencies` in `packages/nocodb/package.json` with version `^6.x.x`.

- [ ] **Step 3: Verify the import resolves with SWC/rspack**

Run:
```bash
cd /home/z/codebase/nocodb/packages/nocodb && node -e "import('openid-client').then(m => console.log(Object.keys(m).slice(0,5))).catch(e => { console.error('IMPORT FAILED:', e.message); process.exit(1)})"
```
Expected: prints an array of exported names like `[ 'allowInsecureRequests', 'custom', 'generators', 'Issuer', 'errors' ]` (exact order may vary). If it fails with an ESM/CJS error, fall back to `openid-client@^4` (last CommonJS version): `pnpm add openid-client@^4` and re-run.

- [ ] **Step 4: Commit**

```bash
cd /home/z/codebase/nocodb
git add packages/nocodb/package.json pnpm-lock.yaml
git commit -m "feat(sso-ce): add openid-client dependency"
```

---

## Task 2: `oidc.config.ts` — env-reading helper

**Files:**
- Create: `packages/nocodb/src/modules/sso-ce/oidc.config.ts`
- Create: `packages/nocodb/src/modules/sso-ce/oidc.config.Source.spec.ts`

**Interfaces:**
- Produces: `readOidcConfig(): OidcConfig | null` — returns `null` when `NC_SSO` is not `oidc`/`openid` or when required vars are missing (so the app still boots without crashing).
- Produces: `OidcConfig` type: `{ issuer, clientId, clientSecret, scopes, ssoClientId, redirectUri }`.

- [ ] **Step 1: Write the failing test**

Create `packages/nocodb/src/modules/sso-ce/oidc.config.Source.spec.ts`:

```typescript
import { readOidcConfig } from './oidc.config';

describe('readOidcConfig', () => {
  const originalEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns null when NC_SSO is not set', () => {
    delete process.env.NC_SSO;
    expect(readOidcConfig()).toBeNull();
  });

  it('returns null when NC_SSO is saml', () => {
    process.env.NC_SSO = 'saml';
    expect(readOidcConfig()).toBeNull();
  });

  it('returns null when NC_SSO is oidc but issuer is missing', () => {
    process.env.NC_SSO = 'oidc';
    process.env.NC_OIDC_CLIENT_ID = 'cid';
    process.env.NC_OIDC_CLIENT_SECRET = 'sec';
    delete process.env.NC_OIDC_ISSUER;
    expect(readOidcConfig()).toBeNull();
  });

  it('returns null when client id is missing', () => {
    process.env.NC_SSO = 'oidc';
    process.env.NC_OIDC_ISSUER = 'https://auth.example.com/application/o/nocodb/';
    process.env.NC_OIDC_CLIENT_SECRET = 'sec';
    delete process.env.NC_OIDC_CLIENT_ID;
    expect(readOidcConfig()).toBeNull();
  });

  it('returns config with defaults when required vars are present', () => {
    process.env.NC_SSO = 'openid'; // alternate spelling
    process.env.NC_OIDC_ISSUER = 'https://auth.example.com/application/o/nocodb/';
    process.env.NC_OIDC_CLIENT_ID = 'cid';
    process.env.NC_OIDC_CLIENT_SECRET = 'sec';
    delete process.env.NC_OIDC_SCOPES;
    delete process.env.NC_OIDC_SSO_CLIENT_ID;

    const cfg = readOidcConfig('https://noco.example.com');
    expect(cfg).not.toBeNull();
    expect(cfg!.issuer).toBe('https://auth.example.com/application/o/nocodb/');
    expect(cfg!.clientId).toBe('cid');
    expect(cfg!.clientSecret).toBe('sec');
    expect(cfg!.scopes).toBe('openid profile email');
    expect(cfg!.ssoClientId).toBe('oidc');
    expect(cfg!.redirectUri).toBe('https://noco.example.com/auth/oidc/callback');
  });

  it('honours custom scopes and sso client id', () => {
    process.env.NC_SSO = 'oidc';
    process.env.NC_OIDC_ISSUER = 'https://auth.example.com/application/o/nocodb/';
    process.env.NC_OIDC_CLIENT_ID = 'cid';
    process.env.NC_OIDC_CLIENT_SECRET = 'sec';
    process.env.NC_OIDC_SCOPES = 'openid email groups';
    process.env.NC_OIDC_SSO_CLIENT_ID = 'authentik-prod';

    const cfg = readOidcConfig('https://noco.example.com');
    expect(cfg!.scopes).toBe('openid email groups');
    expect(cfg!.ssoClientId).toBe('authentik-prod');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx jest src/modules/sso-ce/oidc.config.Source.spec.ts`
Expected: FAIL — `Cannot find module './oidc.config'`.

- [ ] **Step 3: Write the implementation**

Create `packages/nocodb/src/modules/sso-ce/oidc.config.ts`:

```typescript
export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  scopes: string;
  ssoClientId: string;
  redirectUri: string;
}

/**
 * Read OIDC IdP configuration from environment variables.
 *
 * Returns null when SSO is not enabled (NC_SSO not oidc/openid) or when any
 * required variable is missing — so a CE deployment that does not use SSO
 * still boots cleanly. The controller surfaces a 400 only when a user
 * actually hits /auth/oidc without config.
 */
export function readOidcConfig(siteUrl?: string): OidcConfig | null {
  const sso = (process.env.NC_SSO || '').toLowerCase();
  if (sso !== 'oidc' && sso !== 'openid') {
    return null;
  }

  const issuer = process.env.NC_OIDC_ISSUER;
  const clientId = process.env.NC_OIDC_CLIENT_ID;
  const clientSecret = process.env.NC_OIDC_CLIENT_SECRET;

  if (!issuer || !clientId || !clientSecret) {
    return null;
  }

  const base = (siteUrl || process.env.NC_SITE_URL || '').replace(/\/+$/, '');
  if (!base) {
    return null;
  }

  return {
    issuer,
    clientId,
    clientSecret,
    scopes: process.env.NC_OIDC_SCOPES || 'openid profile email',
    ssoClientId: process.env.NC_OIDC_SSO_CLIENT_ID || 'oidc',
    redirectUri: `${base}/auth/oidc/callback`,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx jest src/modules/sso-ce/oidc.config.Source.spec.ts`
Expected: PASS — all 7 tests green.

- [ ] **Step 5: Commit**

```bash
cd /home/z/codebase/nocodb
git add packages/nocodb/src/modules/sso-ce/oidc.config.ts packages/nocodb/src/modules/sso-ce/oidc.config.Source.spec.ts
git commit -m "feat(sso-ce): add oidc.config env-reading helper"
```

---

## Task 3: `state.store.ts` — OAuth2 state nonce store

**Files:**
- Create: `packages/nocodb/src/modules/sso-ce/state.store.ts`
- Create: `packages/nocodb/src/modules/sso-ce/state.store.Source.spec.ts`

**Interfaces:**
- Produces: `issueState(): string` — generates a random state, stores it, returns it.
- Produces: `consumeState(state: string): boolean` — returns true and deletes the entry if the state is valid and not expired; returns false otherwise. Single-use.

- [ ] **Step 1: Write the failing test**

Create `packages/nocodb/src/modules/sso-ce/state.store.Source.spec.ts`:

```typescript
import { issueState, consumeState, __clearStateStoreForTests } from './state.store';

describe('state store', () => {
  beforeEach(() => {
    __clearStateStoreForTests();
  });

  it('issueState returns a non-empty string', () => {
    const s = issueState();
    expect(typeof s).toBe('string');
    expect(s.length).toBeGreaterThan(0);
  });

  it('consumeState returns true for a freshly issued state', () => {
    const s = issueState();
    expect(consumeState(s)).toBe(true);
  });

  it('consumeState is single-use — second call returns false', () => {
    const s = issueState();
    expect(consumeState(s)).toBe(true);
    expect(consumeState(s)).toBe(false);
  });

  it('consumeState returns false for an unknown state', () => {
    expect(consumeState('never-issued')).toBe(false);
  });

  it('consumeState returns false for an expired state', () => {
    const s = issueState();
    // Manually backdate the entry by rewriting its createdAt.
    // We rely on the internal TTL check; simulate by injecting an old entry
    // through the public issueState and then advancing Date.now via mock.
    const originalNow = Date.now;
    Date.now = () => originalNow() + 61_000; // 61s later
    try {
      expect(consumeState(s)).toBe(false);
    } finally {
      Date.now = originalNow;
    }
  });

  it('two issued states are different', () => {
    expect(issueState()).not.toBe(issueState());
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx jest src/modules/sso-ce/state.store.Source.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `packages/nocodb/src/modules/sso-ce/state.store.ts`:

```typescript
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx jest src/modules/sso-ce/state.store.Source.spec.ts`
Expected: PASS — all 6 tests green.

- [ ] **Step 5: Commit**

```bash
cd /home/z/codebase/nocodb
git add packages/nocodb/src/modules/sso-ce/state.store.ts packages/nocodb/src/modules/sso-ce/state.store.Source.spec.ts
git commit -m "feat(sso-ce): add OAuth2 state nonce store"
```

---

## Task 4: `short-lived-token.store.ts` — single-use short token store

**Files:**
- Create: `packages/nocodb/src/modules/sso-ce/short-lived-token.store.ts`
- Create: `packages/nocodb/src/modules/sso-ce/short-lived-token.store.Source.spec.ts`

**Interfaces:**
- Produces: `issueShortToken(user: any): string` — stores `{ user, createdAt }`, returns a random token.
- Produces: `consumeShortToken(token: string): any | null` — returns the stored user if valid+fresh, deletes the entry (single-use); returns null otherwise.

- [ ] **Step 1: Write the failing test**

Create `packages/nocodb/src/modules/sso-ce/short-lived-token.store.Source.spec.ts`:

```typescript
import {
  issueShortToken,
  consumeShortToken,
  __clearShortTokenStoreForTests,
} from './short-lived-token.store';

describe('short-lived token store', () => {
  beforeEach(() => {
    __clearShortTokenStoreForTests();
  });

  it('issueShortToken returns a non-empty string', () => {
    const t = issueShortToken({ id: 'u1', email: 'a@b.c' });
    expect(typeof t).toBe('string');
    expect(t.length).toBeGreaterThan(0);
  });

  it('consumeShortToken returns the user for a fresh token', () => {
    const user = { id: 'u1', email: 'a@b.c' };
    const t = issueShortToken(user);
    expect(consumeShortToken(t)).toEqual(user);
  });

  it('consumeShortToken is single-use', () => {
    const user = { id: 'u1', email: 'a@b.c' };
    const t = issueShortToken(user);
    expect(consumeShortToken(t)).toEqual(user);
    expect(consumeShortToken(t)).toBeNull();
  });

  it('consumeShortToken returns null for unknown token', () => {
    expect(consumeShortToken('never-issued')).toBeNull();
  });

  it('consumeShortToken returns null for an expired token', () => {
    const t = issueShortToken({ id: 'u1', email: 'a@b.c' });
    const originalNow = Date.now;
    Date.now = () => originalNow() + 61_000;
    try {
      expect(consumeShortToken(t)).toBeNull();
    } finally {
      Date.now = originalNow;
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx jest src/modules/sso-ce/short-lived-token.store.Source.spec.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation**

Create `packages/nocodb/src/modules/sso-ce/short-lived-token.store.ts`:

```typescript
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx jest src/modules/sso-ce/short-lived-token.store.Source.spec.ts`
Expected: PASS — all 5 tests green.

- [ ] **Step 5: Commit**

```bash
cd /home/z/codebase/nocodb
git add packages/nocodb/src/modules/sso-ce/short-lived-token.store.ts packages/nocodb/src/modules/sso-ce/short-lived-token.store.Source.spec.ts
git commit -m "feat(sso-ce): add single-use short-lived token store"
```

---

## Task 5: `oidc.client.ts` — openid-client wrapper + user resolver

This is the largest task. It wraps `openid-client` discovery and callback handling, and resolves/creates the NocoDB user from the IdP profile. It is an `@Injectable()` so the controller can depend on it.

**Files:**
- Create: `packages/nocodb/src/modules/sso-ce/oidc.client.ts`

**Interfaces:**
- Consumes: `readOidcConfig` from Task 2, `UsersService`, `AppHooksService`, `User` model, `sanitiseUserObj`, `ncSiteUrl`, `BaseUser` (for base-level roles).
- Produces: `OidcClient` injectable with methods:
  - `isConfigured(): boolean`
  - `getAuthorizationUrl(state: string): Promise<string>`
  - `handleCallback(code: string, state: string): Promise<{ user: any; ssoClientId: string }>` — exchanges code, fetches profile, resolves/creates user, attaches `user.extra = { sso_client_id }`, returns it.

- [ ] **Step 1: Write the implementation**

Create `packages/nocodb/src/modules/sso-ce/oidc.client.ts`:

```typescript
import { Injectable } from '@nestjs/common';
import { Issuer, type Client } from 'openid-client';
import bcrypt from 'bcryptjs';
import { promisify } from 'util';
import { AppEvents } from 'nocodb-sdk';
import type { NcRequest } from '~/interface/config';
import { UsersService } from '~/services/users/users.service';
import { AppHooksService } from '~/services/app-hooks/app-hooks.service';
import { BaseUser, User } from '~/models';
import { sanitiseUserObj } from '~/utils';
import { ncSiteUrl } from '~/utils/envs';
import { readOidcConfig } from './oidc.config';

let cachedClient: { client: Client; issuerUrl: string; fetchedAt: number } | null = null;
const CLIENT_TTL_MS = 10 * 60 * 1000; // re-discover every 10 min

@Injectable()
export class OidcClient {
  constructor(
    private readonly usersService: UsersService,
    private readonly appHooksService: AppHooksService,
  ) {}

  isConfigured(): boolean {
    return readOidcConfig(ncSiteUrl) !== null;
  }

  private async getClient(): Promise<{ client: Client; config: NonNullable<ReturnType<typeof readOidcConfig>> }> {
    const config = readOidcConfig(ncSiteUrl);
    if (!config) {
      throw new Error('OIDC is not configured. Set NC_SSO=oidc and NC_OIDC_* env vars.');
    }

    // Re-use cached client if fresh and issuer unchanged.
    if (
      cachedClient &&
      cachedClient.issuerUrl === config.issuer &&
      Date.now() - cachedClient.fetchedAt < CLIENT_TTL_MS
    ) {
      return { client: cachedClient.client, config };
    }

    const issuer = await Issuer.discover(config.issuer);
    const client = new issuer.Client({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      redirect_uris: [config.redirectUri],
      response_types: ['code'],
    });

    cachedClient = { client, issuerUrl: config.issuer, fetchedAt: Date.now() };
    return { client, config };
  }

  async getAuthorizationUrl(state: string): Promise<string> {
    const { client, config } = await this.getClient();
    return client.authorizationUrl({
      scope: config.scopes,
      state,
    });
  }

  /**
   * Exchange the authorization code for tokens, fetch the userinfo profile,
   * and resolve or create the NocoDB user.
   *
   * Returns the user object with `user.extra = { sso_client_id }` set so that
   * genJwt spreads it into the JWT payload.
   */
  async handleCallback(
    code: string,
    state: string,
    req: NcRequest,
  ): Promise<{ user: any; ssoClientId: string }> {
    const { client, config } = await this.getClient();

    const tokenSet = await client.callback(config.redirectUri, { code, state });

    const profile: any = await client.userinfo(tokenSet.access_token as string);

    const email =
      profile.email ||
      profile._json?.email ||
      profile.preferred_username ||
      profile._json?.preferred_username;

    if (!email) {
      throw new Error('OIDC userinfo did not return an email or preferred_username.');
    }

    const user = await this.resolveOrCreateUser(email, req);

    // Stamp the SSO client id so genJwt spreads it into the JWT payload.
    // api-tokens.service.ts reads req.user.extra.sso_client_id to tag tokens.
    (user as any).extra = { sso_client_id: config.ssoClientId };

    return { user, ssoClientId: config.ssoClientId };
  }

  private async resolveOrCreateUser(email: string, req: NcRequest): Promise<any> {
    try {
      const existing = await User.getByEmail(email);
      if (existing) {
        // If a base id is set on the request, surface base-level roles —
        // mirrors google.strategy.ts:40-51.
        if (req.ncBaseId) {
          const baseUser = await BaseUser.get(req.context, req.ncBaseId, existing.id);
          existing.roles = baseUser?.roles || existing.roles;
        }
        return sanitiseUserObj(existing);
      }

      // New user — auto-provision with blank password + random salt, matching
      // the Google strategy convention (google.strategy.ts:55-63).
      const salt = await promisify(bcrypt.genSalt)(10);
      const created = await this.usersService.registerNewUserIfAllowed({
        email,
        password: '',
        salt,
        email_verification_token: null,
        req,
      } as any);
      return sanitiseUserObj(created);
    } catch (err: any) {
      this.appHooksService.emit(AppEvents.USER_SIGNIN_FAILED, {
        email,
        provider: 'oidc',
        reason: err?.message || 'Authentication failed',
        req,
      });
      throw err;
    }
  }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/z/codebase/nocodb/packages/nocodb && npx tsc --noEmit -p tsconfig.json 2>&1 | grep -E "sso-ce|error" | head -20`
Expected: no errors mentioning `sso-ce/oidc.client.ts`. (Other pre-existing tsc errors in the repo are fine — NocoDB uses SWC, not tsc, for builds; this is just a smoke check.)

If `openid-client` import fails with a type error, add a `// @ts-ignore` above the import line — `openid-client` v6 ships its own types but SWC handles the runtime import regardless.

- [ ] **Step 3: Commit**

```bash
cd /home/z/codebase/nocodb
git add packages/nocodb/src/modules/sso-ce/oidc.client.ts
git commit -m "feat(sso-ce): add OidcClient wrapper + user resolver"
```

Note: this task has no unit test because `OidcClient` depends on `UsersService`, `AppHooksService`, `User` model, and a live IdP. The integration test in Task 7 covers the route end-to-end. The two pure helpers it depends on (`readOidcConfig`, the stores) are unit-tested in Tasks 2–4.

---

## Task 6: `sso-ce.controller.ts` + `sso-ce.module.ts` — routes and module wiring

**Files:**
- Create: `packages/nocodb/src/modules/sso-ce/sso-ce.controller.ts`
- Create: `packages/nocodb/src/modules/sso-ce/sso-ce.module.ts`
- Modify: `packages/nocodb/src/modules/auth/auth.module.ts` (append-only)

**Interfaces:**
- Consumes: `OidcClient` (Task 5), `issueState`/`consumeState` (Task 3), `issueShortToken`/`consumeShortToken` (Task 4), `UsersService`, `setAuthCookie`, `ncSiteUrl`, `NcError`.
- Produces: three HTTP routes wired into the Nest app.

- [ ] **Step 1: Write the controller**

Create `packages/nocodb/src/modules/sso-ce/sso-ce.controller.ts`:

```typescript
import { Controller, Get, Post, Req, Res, HttpCode } from '@nestjs/common';
import type { Response } from 'express';
import { UsersService } from '~/services/users/users.service';
import { setAuthCookie } from '~/services/users/helpers';
import { NcError } from '~/helpers/catchError';
import { ncSiteUrl } from '~/utils/envs';
import { PublicApiLimiterGuard } from '~/guards/public-api-limiter.guard';
import { UseGuards } from '@nestjs/common';
import type { NcRequest } from '~/interface/config';
import { OidcClient } from './oidc.client';
import { issueState, consumeState } from './state.store';
import { issueShortToken, consumeShortToken } from './short-lived-token.store';

@Controller()
export class SsoCeController {
  constructor(
    private readonly oidcClient: OidcClient,
    private readonly usersService: UsersService,
  ) {}

  /** GET /auth/oidc — redirect to the IdP authorization endpoint. */
  @Get('/auth/oidc')
  @UseGuards(PublicApiLimiterGuard)
  async oidcRedirect(@Req() req: NcRequest, @Res() res: Response) {
    if (!this.oidcClient.isConfigured()) {
      NcError.badRequest('OIDC SSO is not configured. Set NC_SSO=oidc and NC_OIDC_* env vars.');
    }
    const state = issueState();
    const url = await this.oidcClient.getAuthorizationUrl(state);
    return res.redirect(url);
  }

  /** GET /auth/oidc/callback — IdP redirects here with ?code=&state=. */
  @Get('/auth/oidc/callback')
  @UseGuards(PublicApiLimiterGuard)
  async oidcCallback(@Req() req: NcRequest, @Res() res: Response) {
    const { code, state } = req.query as { code?: string; state?: string };
    if (!code || !state) {
      NcError.badRequest('Missing code or state in OIDC callback.');
    }
    if (!consumeState(state)) {
      NcError.badRequest('Invalid or expired OIDC state.');
    }

    const { user, ssoClientId } = await this.oidcClient.handleCallback(code, state, req);

    // Bridge to the frontend's tryShortTokenAuth flow: the frontend POSTs
    // /auth/long-lived-token with this token in the xc-short-token header.
    const shortToken = issueShortToken(user);
    const base = (ncSiteUrl || '').replace(/\/+$/, '');
    return res.redirect(`${base}/?short-token=${shortToken}`);
  }

  /** POST /auth/long-lived-token — redeem a short-token for a JWT. */
  @Post('/auth/long-lived-token')
  @UseGuards(PublicApiLimiterGuard)
  @HttpCode(200)
  async longLivedToken(@Req() req: NcRequest, @Res() res: Response) {
    const shortToken = req.headers['xc-short-token'] as string | undefined;
    if (!shortToken) {
      NcError.unauthorized('Missing xc-short-token header.');
    }
    const user = consumeShortToken(shortToken);
    if (!user) {
      NcError.unauthorized('Invalid, expired, or already-used short token.');
    }

    // Mirror req.user so usersService.setRefreshToken (called inside login
    // via the controller flow) sees token_version. We don't call
    // setRefreshToken here because the short-token flow is browser-only and
    // the frontend's signIn() handles the access token; refresh is handled
    // by the existing /auth/token/refresh endpoint via the refresh_token
    // cookie. However we DO need to set the refresh token cookie so the
    // session persists — mirror what AuthController.signin does.
    await this.usersService.setRefreshToken({ req: { ...req, user } as any, res });
    const result = await this.usersService.login(user, req);
    setAuthCookie(res, result.token);

    res.json({
      token: result.token,
      extra: { sso_client_id: (user as any).extra?.sso_client_id },
    });
  }
}
```

- [ ] **Step 2: Write the module**

Create `packages/nocodb/src/modules/sso-ce/sso-ce.module.ts`:

```typescript
import { Module } from '@nestjs/common';
import { NocoModule } from '~/modules/noco.module';
import { SsoCeController } from './sso-ce.controller';
import { OidcClient } from './oidc.client';

@Module({
  imports: [NocoModule],
  controllers: [SsoCeController],
  providers: [OidcClient],
  exports: [OidcClient],
})
export class SsoCeModule {}
```

- [ ] **Step 3: Wire into auth.module.ts (the only existing-file edit)**

Read the current `packages/nocodb/src/modules/auth/auth.module.ts` (it is 34 lines). Apply this append-only edit:

Add imports after the existing `GoogleStrategyProvider` import (line 11):
```typescript
import { OidcClient } from '~/modules/sso-ce/oidc.client';
import { SsoCeController } from '~/modules/sso-ce/sso-ce.controller';
```

Add `SsoCeController` to the controllers array (after `AuthController`):
```typescript
  controllers: [
    ...(process.env.NC_WORKER_CONTAINER !== 'true' ? [AuthController, SsoCeController] : []),
  ],
```

Add `OidcClient` to the providers array (after `GoogleStrategyProvider`):
```typescript
  providers: [
    AuthService,
    LocalStrategy,
    AuthTokenStrategy,
    OAuthTokenStrategy,
    BaseViewStrategy,
    BasicStrategy,
    GoogleStrategyProvider,
    OidcClient,
  ],
```

- [ ] **Step 4: Verify the Nest app boots**

Run:
```bash
cd /home/z/codebase/nocodb/packages/nocodb && npx tsc --noEmit -p tsconfig.json 2>&1 | grep -E "sso-ce|auth\.module" | head -20
```
Expected: no output (no errors in our files).

- [ ] **Step 5: Commit**

```bash
cd /home/z/codebase/nocodb
git add packages/nocodb/src/modules/sso-ce/sso-ce.controller.ts packages/nocodb/src/modules/sso-ce/sso-ce.module.ts packages/nocodb/src/modules/auth/auth.module.ts
git commit -m "feat(sso-ce): add OIDC routes and wire into auth module"
```

---

## Task 7: Integration smoke test — boot the app and hit the routes

This task verifies the wiring end-to-end without a real IdP. It confirms: (a) the Nest container boots with the new module, (b) `/auth/oidc` returns 400 when unconfigured, (c) `/auth/long-lived-token` returns 401 without a token. A full IdP round-trip requires a running Authentik instance and is documented as a manual checklist in Task 8.

**Files:**
- No new files. This is a run-and-observe task.

- [ ] **Step 1: Boot NocoDB without SSO env vars**

Run in one terminal:
```bash
cd /home/z/codebase/nocodb/packages/nocodb && NC_DB="sqlite:///tmp/nocodb-sso-test.db" NC_AUTH_JWT_SECRET=test-secret PORT=8080 node -e "
  const { Noco } = require('./dist/src/Noco');
  Noco.init().then(() => console.log('BOOTED')).catch(e => { console.error('BOOT FAILED', e); process.exit(1); });
" 2>&1 | tail -20
```

If `dist/src/Noco` does not exist (no build yet), use the dev bootstrap instead:
```bash
cd /home/z/codebase/nocodb/packages/nocodb && NC_DB="sqlite:///tmp/nocodb-sso-test.db" NC_AUTH_JWT_SECRET=test-secret PORT=8080 pnpm run start
```
Watch the console. Expected: app boots without errors mentioning `sso-ce` or `OidcClient`. Press Ctrl+C once you see "NocoDB started" or equivalent.

- [ ] **Step 2: Hit /auth/oidc without config — expect 400**

With the app running (Step 1, in background or another terminal):
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/auth/oidc
```
Expected: `400` (because `NC_SSO` is not set, `isConfigured()` returns false, controller calls `NcError.badRequest`).

- [ ] **Step 3: Hit /auth/long-lived-token without header — expect 401**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/auth/long-lived-token
```
Expected: `401`.

- [ ] **Step 4: Hit /auth/long-lived-token with a bogus token — expect 401**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "xc-short-token: bogus" http://localhost:8080/auth/long-lived-token
```
Expected: `401`.

- [ ] **Step 5: Stop the server and clean up**

```bash
pkill -f "nocodb" 2>/dev/null; rm -f /tmp/nocodb-sso-test.db
```

- [ ] **Step 6: Commit any cleanup** (likely nothing to commit — this task only ran the app)

```bash
cd /home/z/codebase/nocodb
git status --porcelain
# If empty, skip commit. If there are changes (e.g. a log file), add to .gitignore instead of committing.
```

---

## Task 8: Manual end-to-end verification with Authentik

This task is a human-run checklist (spec §12). It requires a running Authentik instance and cannot be automated here.

- [ ] **Step 1: Configure Authentik**

In the Authentik admin UI:
1. Create an OAuth2/OpenID Connect Provider.
   - Redirect URI: `https://<nocodb-host>/auth/oidc/callback`
   - Signing key: default Authentik self-signed RSA key.
2. Bind the provider to an Application.
3. Note the Client ID, Client Secret, and Issuer URL (`https://auth.example.com/application/o/<app-slug>/`).

- [ ] **Step 2: Configure NocoDB env vars**

```bash
export NC_SSO=oidc
export NC_OIDC_PROVIDER_NAME=Authentik
export NC_OIDC_ISSUER=https://auth.example.com/application/o/nocodb/
export NC_OIDC_CLIENT_ID=<from authentik>
export NC_OIDC_CLIENT_SECRET=<from authentik>
export NC_OIDC_SCOPES="openid profile email"
export NC_OIDC_SSO_CLIENT_ID=oidc
```

- [ ] **Step 3: Boot NocoDB and verify appInfo**

```bash
curl -s http://localhost:8080/api/v1/appInfo | python3 -m json.tool | grep -E "oidcAuthEnabled|oidcProviderName"
```
Expected: `"oidcAuthEnabled": true`, `"oidcProviderName": "Authentik"`.

- [ ] **Step 4: Browser test — signin button renders**

Visit `http://localhost:8080/signin`. Expected: a "Sign in with Authentik" button is visible.

- [ ] **Step 5: Full login round-trip**

Click the button → redirected to Authentik → log in → returned to NocoDB signed in. Verify the top-right avatar menu shows the user.

- [ ] **Step 6: First-user provisioning check**

In a fresh DB (or with a never-before-seen email), log in via SSO. Then:
```bash
sqlite3 /tmp/nocodb-sso-test.db "SELECT email, password, roles FROM nc_users WHERE email='<that-email>';"
```
Expected: `password` is empty, `roles` is `viewer` (or `creator,super` if it was the first user in an empty DB).

- [ ] **Step 7: SSO user indicator**

While signed in as an SSO user, check the JWT payload (browser devtools → Application → cookies → decode `nc_token` at jwt.io). Expected: the payload contains `sso_client_id: "oidc"`.

- [ ] **Step 8: API token isolation side effect**

As the SSO user, create an API token. Then sign in as an email/password user and view the token list. Expected: the SSO-created token is NOT visible to the email user (and vice versa).

- [ ] **Step 9: Short-token single-use**

Capture the `short-token` from the redirect URL during a login. Replay it:
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "xc-short-token: <captured>" http://localhost:8080/auth/long-lived-token
```
Expected: `401` (already consumed by the browser).

- [ ] **Step 10: Disable SSO and verify email login still works**

Unset `NC_SSO` and restart. Visit `/signin`. Expected: no OIDC button, email/password login works as before.

- [ ] **Step 11: No commit needed** — this task is pure verification.

---

## Task 9: Update the spec's Open Questions if implementation surfaced answers

**Files:**
- Modify: `docs/superpowers/specs/2026-07-13-oidc-sso-ce-design.md` (only if Tasks 5–8 revealed anything).

- [ ] **Step 1: Review what was learned during implementation**

Specifically check:
- The exact `profile` shape from Authentik's userinfo (did `profile.email` work, or did you need `profile._json.email`?).
- Whether `openid-client` v6 worked with SWC/rspack, or you had to fall back to v4.
- Whether `NODE_EXTRA_CA_CERTS` was needed for Authentik's private CA.

- [ ] **Step 2: If anything was learned, update spec §13**

Edit `docs/superpowers/specs/2026-07-13-oidc-sso-ce-design.md` §13 to record the resolved answers. If nothing was learned (e.g. you did not run the Authentik test yet), skip this task.

- [ ] **Step 3: Commit if changed**

```bash
cd /home/z/codebase/nocodb
git add docs/superpowers/specs/2026-07-13-oidc-sso-ce-design.md
git diff --cached --quiet || git commit -m "docs(spec): resolve OIDC open questions from implementation"
```

---

## Self-Review Notes

**Spec coverage check:**
- §1–§3 (approach): covered by Global Constraints + Task 6 module wiring.
- §4 (env vars): Task 2 `readOidcConfig` reads all 7 vars.
- §5 (file layout): Tasks 2–6 create all 6 source files + 3 test files.
- §6 (routes & data flow): Task 6 controller implements all 3 routes; flow matches the spec's diagram.
- §7 (OIDC client, no Passport): Task 5 uses `openid-client` directly, no `express-session`.
- §8 (short-token store): Task 4 implements 60s TTL + single-use.
- §9 (API token isolation side effect): automatic via `user.extra.sso_client_id` set in Task 5; verified in Task 8 Step 8.
- §10 (fork maintenance): Global Constraints enforce single-file edit; branch is `develop-sso-ce`.
- §11 (operating notes): Task 8 documents Authentik + NocoDB config and constraints.
- §12 (verification checklist): Task 8 covers all 11 acceptance tests.
- §13 (open questions): Task 9 resolves them if implementation surfaces answers.

**Type consistency check:**
- `readOidcConfig(siteUrl?)` returns `OidcConfig | null` — consistent across Task 2 (definition), Task 5 (consumer).
- `issueState()` / `consumeState(state)` — consistent across Task 3.
- `issueShortToken(user)` / `consumeShortToken(token)` — consistent across Task 4, Task 6.
- `OidcClient.isConfigured()` / `getAuthorizationUrl(state)` / `handleCallback(code, state, req)` — consistent across Task 5 (definition), Task 6 (consumer).
- `user.extra = { sso_client_id }` — set in Task 5 `handleCallback`, read in Task 6 `longLivedToken` via `(user as any).extra?.sso_client_id`. Consistent.

**Placeholder scan:** none found — every step has concrete code or commands.
