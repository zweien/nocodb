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
