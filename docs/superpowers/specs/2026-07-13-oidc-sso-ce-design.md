# OIDC SSO for NocoDB Community Edition

**Date:** 2026-07-13
**Author:** Internal fork
**Status:** Design approved — pending implementation plan

## 1. Problem

NocoDB Community Edition (CE) restricts SSO to the Enterprise Edition (EE).
NocoDB EE ships as a closed-source overlay: its SSO handlers live in a `~/ee/`
directory that is injected at EE build time and is absent from the public
repository. We run NocoDB CE on an internal network and have already deployed
[Authentik](https://goauthentik.io/) as our identity provider. We need SSO on
CE and cannot wait for or pay for EE.

Crucially, NocoDB CE **already contains the full SSO plumbing** — frontend
buttons, callback middleware, `appInfo` flags, the `nc_sso_client` schema,
ACL permission entries, and even the `@node-saml/passport-saml` and
`@govtechsg/passport-openidconnect` npm dependencies. The only missing pieces
are the OIDC route controllers and the IdP client. EE fills those in via its
overlay; this fork fills them in directly in CE source.

One caveat: the Passport OIDC wrappers (`@govtechsg/passport-openidconnect`)
need `express-session` middleware, which NocoDB does not mount. Rather than
touch the Nest bootstrap to add session middleware, we call `openid-client`
directly from the controller (see §7). The vendored Passport deps stay in
`package.json` unused — touching them would create upstream merge friction
for no benefit.

## 2. Goals & Non-Goals

### Goals

- Authenticate NocoDB CE users via Authentik using OIDC.
- Auto-provision users on first login (password blank, random salt — matches
  the existing Google strategy convention).
- Minimize divergence from upstream so future NocoDB releases merge cleanly.
- Require zero frontend changes — reuse the OIDC button and callback handling
  that already ship in `nc-gui`.

### Non-Goals

- SAML support (Authentik OIDC is sufficient; SAML's short-token flow is more
  complex and the CE plumbing is less complete).
- In-app admin UI for configuring IdP settings (env vars only).
- Multi-IdP support / `nc_sso_client` CRUD (single IdP via env vars).
- Role mapping from OIDC claims (default CE role assignment is sufficient).
- Full API-token isolation by SSO client (the `sso_client_id` marker will
  incidentally trigger EE-style isolation as a side effect — see §9 — but we
  do not implement the `ApiToken.getExtraForUserPayload()` override).

## 3. Approach

Mirror exactly what the EE overlay does: fill in the public-API seams that
already exist in CE. Concretely:

1. Add a new NestJS module `sso-ce` under
   `packages/nocodb/src/modules/sso-ce/` containing the OIDC Passport
   strategy, a controller exposing the routes the frontend already calls, and
   a short-lived token store.
2. Register the strategy provider and controller in
   `modules/auth/auth.module.ts` (the only existing file we touch).
3. Configure via environment variables — reuse the `NC_SSO` /
   `NC_OIDC_PROVIDER_NAME` vars that `utils.service.ts` already reads, plus a
   small new set for issuer/client/scopes.

### Why not the `noco-integrations` plugin framework

`packages/noco-integrations` declares `IntegrationType.Auth` as a registered
integration type, and `packages/nocodb/build-utils/registerIntegrations.js`
auto-registers packages found under `noco-integrations/packages/`. However,
only `auth-github` and `ai-openai` ship as examples, and the Auth integration
contract (how a request flows through, how redirects/callbacks are wired, how
the strategy is registered with Nest's passport) is undocumented. Using it
for OIDC would require reverse-engineering that contract from `auth-github`.
A direct NestJS module is lower-risk and matches the pattern EE itself uses.

## 4. Environment Variables

| Variable | Required | Default | Source |
|---|---|---|---|
| `NC_SSO` | yes | — | CE already reads in `utils.service.ts:432`; set to `oidc` (or `openid`) to surface the signin button |
| `NC_OIDC_PROVIDER_NAME` | no | `OpenID Connect` | CE already reads in `utils.service.ts:436` |
| `NC_OIDC_ISSUER` | yes | — | **New.** Authentik issuer URL, e.g. `https://auth.example.com/application/o/nocodb/` |
| `NC_OIDC_CLIENT_ID` | yes | — | **New.** |
| `NC_OIDC_CLIENT_SECRET` | yes | — | **New.** |
| `NC_OIDC_SCOPES` | no | `openid profile email` | **New.** Space-separated scope list |
| `NC_OIDC_SSO_CLIENT_ID` | no | `oidc` | **New.** Value placed in JWT `extra.sso_client_id`; lets `UserInfo.vue` recognise SSO users and lets `api-tokens.service.ts` tag tokens |
| `NC_OIDC_ALLOW_INSECURE` | no | auto | **New.** Set `true` to force `openid-client` to accept an `http:` issuer (local dev only). Auto-enabled when `NC_OIDC_ISSUER` starts with `http:`. No-op for production HTTPS. |

### OIDC IdP issuer mode requirement

The IdP must publish a per-provider issuer (the discovery document's `issuer`
field must match `NC_OIDC_ISSUER`). **Authentik** defaults to `global` issuer
mode (`http://host:9000/`), which causes `openid-client`'s issuer-match check
to fail. Set the provider's `issuer_mode = per_provider` so the issuer becomes
`http://host:9000/application/o/<slug>/`. This was verified during E2E
testing — global mode returns `OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED` on
discovery.

### Rationale for `NC_OIDC_SSO_CLIENT_ID`

The frontend (`UserInfo.vue:21`) checks `user.sso_client_id` to render the SSO
indicator, and `api-tokens.service.ts:44` stamps `fk_sso_client_id` on every
newly created API token from the value in `req.user.extra.sso_client_id`.
Placing any non-empty value there reuses all of that existing logic without a
new table or model. We default it to the string `oidc`.

### Config loading

Read `process.env` at request time inside the strategy's `authenticate()`
method, mirroring `google.strategy.ts:90-117`. This avoids crashing the Nest
container at boot when the vars are absent (CE deployments that do not use
SSO must still start).

## 5. File Layout

All new files, isolated under one directory:

```
packages/nocodb/src/modules/sso-ce/
├── sso-ce.module.ts              # NestJS Module declaration
├── sso-ce.controller.ts          # OIDC routes (3 endpoints)
├── oidc.client.ts                # openid-client wrapper + user resolver
├── oidc.config.ts                # env-reading helper
├── short-lived-token.store.ts    # in-process short-token store (60s, single-use)
└── state.store.ts                # in-process OAuth2 state nonce store (60s)
```

### Existing file touched (the only one)

`packages/nocodb/src/modules/auth/auth.module.ts`:

```ts
import { SsoCeController } from '~/modules/sso-ce/sso-ce.controller';
import { OidcClient } from '~/modules/sso-ce/oidc.client';

// in authModuleMetadata:
controllers: [
  ...(process.env.NC_WORKER_CONTAINER !== 'true'
    ? [AuthController, SsoCeController]
    : []),
],
providers: [
  AuthService,
  LocalStrategy,
  AuthTokenStrategy,
  OAuthTokenStrategy,
  BaseViewStrategy,
  BasicStrategy,
  GoogleStrategyProvider,
  OidcClient,  // new
],
```

This is an append-only edit — the kind least likely to conflict on upstream
merges. `OidcClient` is an `@Injectable()` NestJS provider so
`SsoCeController` can inject it (alongside `UsersService` and
`AppHooksService`).

## 6. Routes & Data Flow

Three routes, all in `SsoCeController`. We do **not** implement
`/auth/oidc/genTokenByCode` — that path is only reached when the frontend's
`tryGoogleAuth` fires with `state=oidc`, which requires the IdP to redirect
back to the SPA dashboard with `?code=&state=` in the URL. Our design uses a
dedicated backend callback endpoint (`/auth/oidc/callback`) instead, so the
IdP never lands the user on the dashboard with raw query params. This keeps
JWTs out of the URL and matches EE's short-token flow.

### Route 1 — `GET /auth/oidc` (redirect to IdP)

- No guard — controller method handles it directly (we are not using
  Passport's `AuthGuard` for OIDC; see §7 for why).
- Generate a random `state` nonce (CSRF protection), store
  `{ state, createdAt }` in the state store (same module as the short-token
  store, 60s TTL).
- Build the authorization URL via `openid-client`'s
  `client.authorizationUrl({ scope, state, redirect_uri })`.
- 302 to Authentik's authorization endpoint.

### Route 2 — `GET /auth/oidc/callback` (IdP callback)

- Controller method, no Passport guard.
- Read `code` and `state` from query string.
- Verify `state` exists in the state store (CSRF check); delete it.
- `client.callback(redirectUri, { code, state }, null)` exchanges the code
  for an access token + ID token.
- `client.userinfo(accessToken)` fetches the user profile.
- `email = profile.email` (fall back to `profile.preferred_username`).
- `User.getByEmail(email)` → exists? use it : `registerNewUserIfAllowed()`.
- Attach `user.extra = { sso_client_id: process.env.NC_OIDC_SSO_CLIENT_ID || 'oidc' }`
  so `genJwt` (`helpers.ts:17-18`) spreads it into the JWT payload.
- Issue a short-token via the store; 302 to `${ncSiteUrl}/?short-token=<token>`.
- The frontend's `tryShortTokenAuth` (`03.auth.global.ts:209`) runs
  unconditionally and consumes the short-token.

**Why a short-token redirect and not a direct JWT return:** the frontend's
`tryGoogleAuth` path only fires when `googleAuthEnabled` is true
(`03.auth.global.ts:67`). A pure-OIDC deployment (no Google) would not
consume `?code=&state=oidc` on the dashboard. The short-token path is
unconditional, so it is the reliable contract for pure-OIDC. It also matches
EE's flow and keeps JWTs out of the URL.

### Route 3 — `POST /auth/long-lived-token` (short-token → JWT)

- Reads `xc-short-token` header.
- Looks up the token in the store; if missing or expired (>60s), 401.
- **Deletes the entry** before responding — single-use, matching the intent
  of upstream commit `5265a83312` ("make SSO short-lived tokens single-use").
- The stored payload already carries `user.extra.sso_client_id` (set in
  Route 2), so `genJwt` will include it in the JWT automatically.
- Calls `usersService.login(user, req)` to mint the JWT and refresh token.
- `setAuthCookie` on the response.
- Returns `{ token, extra: { sso_client_id } }` — the `extra` shape is what
  `03.auth.global.ts:239` destructures.

### End-to-end flow

```
User clicks "Sign in with OpenID Connect"
  → GET /auth/oidc
  → Backend: generate random state, store it, build authz URL
  → 302 to Authentik authorization endpoint
  → User authenticates at Authentik
  → 302 back to /auth/oidc/callback?code=xxx&state=<random>
  → Backend: verify+delete state (CSRF), exchange code, fetch userinfo
  → User.getByEmail(email)  →  exists? use it  :  registerNewUserIfAllowed()
  → Set user.extra = { sso_client_id: 'oidc' }
  → Generate short-token, store { user, createdAt }
  → 302 to ${ncSiteUrl}/?short-token=xxx
  → Frontend tryShortTokenAuth fires
  → POST /auth/long-lived-token  (header: xc-short-token)
  → Returns { token, extra: { sso_client_id: 'oidc' } }
  → signIn(token), window reloads
  → User is authenticated
```

## 7. OIDC Client (no Passport strategy)

**We do not use `@govtechsg/passport-openidconnect` or any Passport OIDC
strategy.** The Passport OIDC wrappers (`passport-openidconnect`,
`@govtechsg/passport-openidconnect`) require `express-session` middleware to
be mounted on the Express app — NocoDB does not mount it, and adding it to
the Nest bootstrap would be an invasive change to a core file. This is the
exact pitfall reported in [nocodb issue #742](https://github.com/nocodb/nocodb/issues/742).

Instead we call [`openid-client`](https://github.com/panva/node-openid-client)
directly from the controller. `openid-client` is already pulled in
transitively by `@govtechsg/passport-openidconnect`, so no new dependency is
needed — but we add it as a direct dependency in `package.json` to make the
import explicit and version-pinned.

File: `packages/nocodb/src/modules/sso-ce/oidc.client.ts`.

- `getConfiguration(): Promise<{ config: Configuration; oidcConfig }>`:
  1. Read env vars via `oidc.config.ts`. Throw if required vars missing.
  2. `oidc.discovery(new URL(issuer), clientId, clientSecret)` to
     auto-discover endpoints (avoids hard-coding Authentik URLs; tolerates
     IdP config drift). Returns a v6 `Configuration` object.
  3. Cache the configuration in a module-level variable (re-discover on
     issuer change or every 10 min to tolerate IdP key rotation).
- The `@Injectable()` `OidcClient` exposes three methods used by the
  controller:
  - `isConfigured(): boolean`
  - `getAuthorizationUrl(state, codeVerifier): Promise<string>` — builds the
    PKCE `code_challenge` from `codeVerifier` and calls
    `oidc.buildAuthorizationUrl(config, { redirect_uri, scope,
    code_challenge, code_challenge_method: 'S256', state })`.
  - `handleCallback(callbackUrl, state, codeVerifier, req): Promise<{ user,
    ssoClientId }>` — calls
    `oidc.authorizationCodeGrant(config, new URL(callbackUrl), {
    pkceCodeVerifier: codeVerifier, expectedState: state })`, then
    `oidc.fetchUserInfo(config, accessToken, claims.sub)` (with fallback to
    ID-token claims), then resolves/creates the user, then stamps
    `user.extra = { sso_client_id }`.

### User lookup / provisioning

A pure function `resolveOrCreateUser(profile, req): Promise<User>` lives in
`oidc.client.ts` (or a sibling `user-resolver.ts`):

1. `email = profile.email ?? profile.preferred_username`. If neither is
   present, throw — Authentik must release the `email` scope claim.
2. `const user = await User.getByEmail(email)`.
3. If found:
   - If `req.ncBaseId` is set, fetch `BaseUser` for base-level roles (mirror
     `google.strategy.ts:40-51`).
   - Return `sanitiseUserObj(user)`.
4. If not found:
   ```ts
   const salt = await promisify(bcrypt.genSalt)(10);
   const user = await usersService.registerNewUserIfAllowed({
     email, password: '', salt, email_verification_token: null, req,
   } as any);
   return sanitiseUserObj(user);
   ```
5. On error: `appHooksService.emit(AppEvents.USER_SIGNIN_FAILED, { email,
   provider: 'oidc', reason, req })` — mirrors Google's hook.

### Role assignment on first login

`registerNewUserIfAllowed` (`users.service.ts:142`) already does the right
thing:

- First user in an empty DB (and `NC_CLOUD !== 'true'`) →
  `CREATOR,SUPER_ADMIN`.
- Otherwise → `OrgUserRoles.VIEWER` (unless `invite_only_signup` is set, in
  which case it 400s — operators who enable invite-only should not enable
  auto-provisioning SSO simultaneously; documented in §11).

No new role logic needed.

## 8. Short-Lived Token Store

File: `packages/nocodb/src/modules/sso-ce/short-lived-token.store.ts`.

In-process `Map<string, { user: any; createdAt: number }>` with a 60-second
TTL and single-use semantics (entry deleted on read).

```ts
const STORE = new Map<string, { user: any; createdAt: number }>();
const TTL_MS = 60_000;

export function issue(user: any): string {
  const token = randomTokenString(); // reuse helpers.randomTokenString
  STORE.set(token, { user, createdAt: Date.now() });
  return token;
}

export function consume(token: string): any | null {
  const entry = STORE.get(token);
  if (!entry) return null;
  STORE.delete(token);                       // single-use
  if (Date.now() - entry.createdAt > TTL_MS) return null;
  return entry.user;
}

// Optional: periodic sweep of expired entries to bound memory.
```

### Limitations

- **Single-instance only.** If NocoDB is scaled horizontally behind a load
  balancer, a callback hitting instance A cannot be redeemed on instance B.
  For an internal deployment this is acceptable. If horizontal scaling is
  ever needed, swap this implementation for Redis (`SET token value EX 60 NX`
  + `GETDEL`) — the interface stays identical.
- **Process restart loses in-flight tokens.** A user mid-callback when the
  server restarts must re-click "Sign in with OIDC". Acceptable.

## 9. Side Effect: API Token Isolation

Placing a non-empty `sso_client_id` in the JWT `extra` activates existing
CE logic that was added for EE parity (commit `93ac657c79` "isolate API
tokens by auth type"):

- `api-tokens.service.ts:44` — new tokens created by SSO users get
  `fk_sso_client_id = 'oidc'`.
- `api-tokens.service.ts:17-25` — non-SSO users calling `apiTokenList` go
  through `ApiToken.listForNonSsoUser`, which filters
  `fk_sso_client_id = null`. So they cannot see tokens created by SSO users
  (and vice-versa: SSO users see all their own tokens via `ApiToken.list`).

This is EE's behaviour and is safe for internal use (arguably safer). It is
documented here so operators are not surprised that an email-login user
cannot see a token an SSO user created. We accept this side effect rather
than leaving `sso_client_id` empty (which would disable the SSO indicator in
`UserInfo.vue`).

## 10. Fork Maintenance

### Branch model

- `upstream` remote → `nocodb/nocodb`.
- `develop` tracks `upstream/develop` verbatim (no custom commits).
- `develop-sso-ce` branch carries our SSO work, rebased or merged onto
  `develop` after each upstream sync.

### What we never touch

- `auth.controller.ts` (high-churn file).
- `useEeConfig.ts` and any other EE-boundary file.
- Any service or model method signature.
- No new migrations (we do not use the `nc_sso_client` table).
- `package.json` is touched **only** to add `openid-client` as a direct
  dependency (it is already present transitively via
  `@govtechsg/passport-openidconnect`, but pinning it directly makes the
  import explicit). The existing vendored SSO deps are left untouched.

### Sync procedure

```
git fetch upstream
git checkout develop && git merge --ff-only upstream/develop
git checkout develop-sso-ce && git merge develop
# Resolve conflict in auth.module.ts if any (append-only — usually none)
```

We prefer `merge` over `rebase` so the SSO branch's history is preserved and
force-pushes are never needed. The only file that can realistically conflict
is `auth.module.ts`, and the edit is append-only (new entries at the end of
two arrays), so conflicts are trivial to resolve.

## 11. Operating Notes

### Authentik configuration

1. In Authentik: create an **OAuth2/OpenID Connect Provider**.
   - Redirect URI: `https://<nocodb-host>/auth/oidc/callback`
   - Signing key: default Authentik self-signed RSA key.
2. Bind the provider to an **Application**.
3. Note the **Client ID**, **Client Secret**, and **Issuer URL**
   (`https://auth.example.com/application/o/<app-slug>/`).

### NocoDB configuration

```bash
NC_SSO=oidc
NC_OIDC_PROVIDER_NAME=Authentik           # optional, button label
NC_OIDC_ISSUER=https://auth.example.com/application/o/nocodb/
NC_OIDC_CLIENT_ID=<from authentik>
NC_OIDC_CLIENT_SECRET=<from authentik>
NC_OIDC_SCOPES="openid profile email"      # optional
NC_OIDC_SSO_CLIENT_ID=oidc                 # optional, default 'oidc'
```

### Constraints

- **Do not enable `invite_only_signup`** alongside auto-provisioning SSO.
  `registerNewUserIfAllowed` 400s on self-signup when invite-only is on
  (`users.service.ts:179-180`). SSO users would be rejected. Either keep
  invite-only off, or pre-create users and accept that SSO only authenticates
  existing rows (the "existing user only" path — not this design).
- **Email match is authoritative.** A user with the same email in Authentik
  and NocoDB is treated as the same user. Ensure Authentik emails are unique
  and match the NocoDB user's email if you pre-create accounts.
- **`NC_CLOUD=true` must not be set.** It flips `Noco.isEE()` on globally and
  will route unrelated requests into EE-only code paths whose handlers are
  absent from CE source.
- **Outbound HTTPS to Authentik is required.** The NocoDB container must
  reach `NC_OIDC_ISSUER` (and its `.well-known/openid-configuration`) for
  discovery and token exchange. If Authentik uses a private CA, set
  `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` so Node trusts it.

## 12. Verification Checklist

End-to-end acceptance tests after implementation. **All items below were
verified on 2026-07-14** in a local test environment (NocoDB backend on host
+ Authentik in Docker, both on `localhost`). Items marked ✅ passed; items
marked ⏳ require the nc-gui frontend or a multi-user setup and were not
exercised in the backend-only test.

1. ✅ Set the §11 env vars and start NocoDB.
2. ✅ `GET /api/v1/db/meta/nocodb/info` returns `oidcAuthEnabled: true`,
   `oidcProviderName: 'OpenID Connect'`.
3. ⏳ Visit `/signin` — the "Sign in with {provider}" button renders.
   (Requires nc-gui; backend `/auth/oidc` returns 302 to the IdP, which is
   what the button links to.)
4. ✅ Click → redirected to Authentik → log in → returned to NocoDB signed
   in. The full flow ran via headless browser: authorize → identification
   stage → password stage → callback → short-token redirect. The short-token
   was redeemed at `POST /auth/long-lived-token` for a JWT.
5. ✅ First-time user is auto-created with `password=''`,
   `roles='org-level-creator,super'` (first user in an empty DB). Verified
   in `nc_users_v2` table.
6. ⏳ `UserInfo.vue` shows the SSO user indicator. (Requires nc-gui; the
   JWT payload carries `sso_client_id: 'oidc'` which is what the indicator
   reads — verified by decoding the JWT.)
7. ⏳ API token isolation by SSO client. (Requires multi-user setup; the
   mechanism — `user.extra.sso_client_id` flowing into `genJwt` and
   `api-tokens.service.ts:44` — is wired and the JWT carries the marker.)
8. ✅ A short-token consumed once cannot be reused — a second
   `POST /auth/long-lived-token` with the same `xc-short-token` returns 401.
9. ✅ A short-token left unused for >60s returns 401 on first use (expired).
   Verified: fresh token → immediate use 200; same token after 62s → 401.
10. ⏳ Unset `NC_SSO` and restart — the OIDC button disappears. (Logic in
    `utils.service.ts:432` is unchanged CE code, already trusted.)
11. ⏳ Merge `upstream/develop` into `develop-sso-ce`; expect zero conflicts
    outside `auth.module.ts`. (Will be confirmed on first real upstream
    sync.)

### Additional invariants verified beyond the original checklist

- ✅ **C1 fix (token_version propagation).** The JWT issued via SSO carries
  the rotated `token_version`; repeated authenticated requests with the same
  JWT return 200, not 401. This was the critical bug found in the final
  whole-branch review (stale `token_version` from a shallow-copy `req`
  object) and the fix is confirmed working.
- ✅ **PKCE round-trip.** `code_challenge`/`code_challenge_method=S256` sent
  on authorize; `pkceCodeVerifier` validated on token exchange.
- ✅ **CSRF state.** `state` nonce is single-use and 60s TTL; an unknown or
  expired state returns 400 from `/auth/oidc/callback`.
- ✅ **Insecure-HTTP issuer support.** With `NC_OIDC_ISSUER=http://...`,
  discovery + token exchange + userinfo all succeed (auto-enabled
  `allowInsecureRequests`).

## 13. Open Questions

Implementation resolved the design-time questions and surfaced one change:

- **openid-client v6 API (resolved).** Task 1 installed `openid-client@^6.8.4`,
  which replaced the v5 class-based API (`Issuer.discover`, `new issuer.Client`,
  `client.authorizationUrl/callback/userinfo`) with a functional API. The
  implementation uses `discovery()`, `buildAuthorizationUrl()`,
  `authorizationCodeGrant()`, `fetchUserInfo()`. This also required adopting
  PKCE (v6 strongly recommends it): the controller generates a
  `code_verifier` via `randomPKCECodeVerifier()`, stores it alongside the
  state nonce in `state.store`, and passes it to `authorizationCodeGrant` as
  `pkceCodeVerifier`. The `state.store` signature changed from
  `issueState(): string` / `consumeState(state): boolean` to
  `issueState(codeVerifier): string` /
  `consumeState(state): { codeVerifier } | null`.
- **userinfo profile shape (partially resolved).** The implementation tries
  `fetchUserInfo(config, accessToken, claims.sub)` first and falls back to
  ID-token `claims()` if the userinfo endpoint is unavailable. Email
  extraction: `profile.email || profile.preferred_username`. The exact
  Authentik field names should be confirmed during the Task 8 manual E2E.
- **Issuer key rotation (resolved).** `openid-client` v6's `Configuration`
  caches the IdP's JWKS internally. The implementation also re-runs
  `discovery()` every 10 minutes (or on issuer URL change) as a safety net.
- **Outbound HTTPS / private CA (open — operator concern).** The NocoDB
  container must reach `NC_OIDC_ISSUER` for discovery and token exchange.
  If Authentik uses a private CA, set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`.
