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
