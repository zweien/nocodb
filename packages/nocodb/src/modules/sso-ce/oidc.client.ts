import { Injectable } from '@nestjs/common';
import * as oidc from 'openid-client';
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

let cachedConfig: {
  config: oidc.Configuration;
  issuerUrl: string;
  fetchedAt: number;
} | null = null;
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

  private async getConfiguration(): Promise<{
    config: oidc.Configuration;
    oidcConfig: NonNullable<ReturnType<typeof readOidcConfig>>;
  }> {
    const oidcConfig = readOidcConfig(ncSiteUrl);
    if (!oidcConfig) {
      throw new Error(
        'OIDC is not configured. Set NC_SSO=oidc and NC_OIDC_* env vars.',
      );
    }

    // Re-use cached configuration if fresh and issuer unchanged.
    if (
      cachedConfig &&
      cachedConfig.issuerUrl === oidcConfig.issuer &&
      Date.now() - cachedConfig.fetchedAt < CLIENT_TTL_MS
    ) {
      return { config: cachedConfig.config, oidcConfig };
    }

    // openid-client v6 blocks non-HTTPS issuers by default. For local dev
    // (http://localhost IdPs like Authentik), allow insecure requests via
    // the execute option on discovery — it propagates to all subsequent
    // requests made with this Configuration. Automatic when issuer is http:,
    // or set NC_OIDC_ALLOW_INSECURE=true to force-enable.
    const isInsecure =
      new URL(oidcConfig.issuer).protocol === 'http:' ||
      process.env.NC_OIDC_ALLOW_INSECURE === 'true';

    const config = await oidc.discovery(
      new URL(oidcConfig.issuer),
      oidcConfig.clientId,
      oidcConfig.clientSecret,
      undefined,
      isInsecure ? { execute: [oidc.allowInsecureRequests] } : undefined,
    );

    cachedConfig = {
      config,
      issuerUrl: oidcConfig.issuer,
      fetchedAt: Date.now(),
    };
    return { config, oidcConfig };
  }

  /** Options object passed to openid-client v6 grant/userinfo calls when
   * insecure HTTP is allowed. The discovery-time execute option propagates
   * to the Configuration, but grant/userinfo accept their own options too. */
  private insecureOptions(): any {
    const oidcConfig = readOidcConfig(ncSiteUrl);
    const isInsecure =
      oidcConfig &&
      (new URL(oidcConfig.issuer).protocol === 'http:' ||
        process.env.NC_OIDC_ALLOW_INSECURE === 'true');
    return isInsecure
      ? { execute: [oidc.allowInsecureRequests] }
      : undefined;
  }

  /**
   * Build the IdP authorization URL. The caller (controller) generates the
   * PKCE code_verifier, stores it via the state store, and passes both here.
   * Returns the full authorization URL to redirect the user to.
   */
  async getAuthorizationUrl(
    state: string,
    codeVerifier: string,
  ): Promise<string> {
    const { config, oidcConfig } = await this.getConfiguration();

    const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);

    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: oidcConfig.redirectUri,
      scope: oidcConfig.scopes,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });
    return url.href;
  }

  /**
   * Exchange the authorization code for tokens, fetch the userinfo profile,
   * and resolve or create the NocoDB user.
   *
   * `callbackUrl` is the full URL the IdP redirected to (with ?code=&state=).
   * `codeVerifier` is the PKCE verifier stored alongside the state.
   *
   * Returns the user object with `user.extra = { sso_client_id }` set so that
   * genJwt spreads it into the JWT payload.
   */
  async handleCallback(
    callbackUrl: string,
    state: string,
    codeVerifier: string,
    req: NcRequest,
  ): Promise<{ user: any; ssoClientId: string }> {
    const { config, oidcConfig } = await this.getConfiguration();

    const tokenSet = await oidc.authorizationCodeGrant(
      config,
      new URL(callbackUrl),
      {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        ...this.insecureOptions(),
      },
    );

    // Prefer userinfo endpoint for the email; fall back to ID token claims.
    let profile: any;
    const claims = tokenSet.claims();
    if (claims?.sub && tokenSet.access_token) {
      try {
        profile = await oidc.fetchUserInfo(
          config,
          tokenSet.access_token,
          claims.sub,
          this.insecureOptions(),
        );
      } catch {
        // userinfo endpoint may be unavailable; fall back to ID token claims
        profile = claims;
      }
    } else {
      profile = claims || {};
    }

    const email = profile.email || profile.preferred_username;

    if (!email) {
      throw new Error(
        'OIDC userinfo did not return an email or preferred_username.',
      );
    }

    const user = await this.resolveOrCreateUser(email, req);

    // Stamp the SSO client id so genJwt spreads it into the JWT payload.
    // api-tokens.service.ts reads req.user.extra.sso_client_id to tag tokens.
    (user as any).extra = { sso_client_id: oidcConfig.ssoClientId };

    return { user, ssoClientId: oidcConfig.ssoClientId };
  }

  private async resolveOrCreateUser(
    email: string,
    req: NcRequest,
  ): Promise<any> {
    try {
      const existing = await User.getByEmail(email);
      if (existing) {
        // If a base id is set on the request, surface base-level roles —
        // mirrors google.strategy.ts:40-51.
        if (req.ncBaseId) {
          const baseUser = await BaseUser.get(
            req.context,
            req.ncBaseId,
            existing.id,
          );
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
