import {
  Controller,
  Get,
  Post,
  Req,
  Res,
  HttpCode,
  UseGuards,
} from '@nestjs/common';
import type { Response } from 'express';
import { randomPKCECodeVerifier } from 'openid-client';
import { UsersService } from '~/services/users/users.service';
import { setAuthCookie } from '~/services/users/helpers';
import { NcError } from '~/helpers/catchError';
import { ncSiteUrl } from '~/utils/envs';
import { PublicApiLimiterGuard } from '~/guards/public-api-limiter.guard';
import type { NcRequest } from '~/interface/config';
import { OidcClient } from './oidc.client';
import { issueState, consumeState } from './state.store';
import {
  issueShortToken,
  consumeShortToken,
} from './short-lived-token.store';

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
      NcError.badRequest(
        'OIDC SSO is not configured. Set NC_SSO=oidc and NC_OIDC_* env vars.',
      );
    }
    // Generate a PKCE code_verifier and a state nonce; store them together
    // so the callback can retrieve the verifier to complete the code exchange.
    const codeVerifier = randomPKCECodeVerifier();
    const state = issueState(codeVerifier);
    const url = await this.oidcClient.getAuthorizationUrl(state, codeVerifier);
    return res.redirect(url);
  }

  /** GET /auth/oidc/callback — IdP redirects here with ?code=&state=. */
  @Get('/auth/oidc/callback')
  @UseGuards(PublicApiLimiterGuard)
  async oidcCallback(@Req() req: NcRequest, @Res() res: Response) {
    const state = (req.query.state as string) || '';
    if (!state) {
      NcError.badRequest('Missing state in OIDC callback.');
    }

    // consumeState is single-use and returns the stored PKCE code_verifier.
    const stateEntry = consumeState(state);
    if (!stateEntry) {
      NcError.badRequest('Invalid or expired OIDC state.');
    }

    // Reconstruct the full callback URL — openid-client v6's
    // authorizationCodeGrant expects the complete URL (it parses code & state
    // itself, and validates expectedState against it).
    const protocol = req.protocol;
    const host = req.get('host');
    const originalUrl = req.originalUrl || req.url;
    const callbackUrl = `${protocol}://${host}${originalUrl}`;

    const { user } = await this.oidcClient.handleCallback(
      callbackUrl,
      state,
      stateEntry.codeVerifier,
      req,
    );

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

    // setRefreshToken needs req.user populated. The short-token store holds
    // the resolved user object; attach it to a shallow req copy so the
    // refresh-token cookie is set (session persistence across browser
    // restarts). Mirrors what AuthController.signin does after its guard
    // populates req.user.
    await this.usersService.setRefreshToken({
      req: { ...req, user } as any,
      res,
    });
    const result = await this.usersService.login(user, req);
    setAuthCookie(res, result.token);

    res.json({
      token: result.token,
      extra: { sso_client_id: (user as any).extra?.sso_client_id },
    });
  }
}
