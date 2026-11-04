/**
 * Stateless, single-user OAuth 2.0 authorization server for clients that can't send a
 * static bearer header (the Gemini app, claude.ai connectors).
 *
 * Flow: the client sends the user to /oauth/authorize, the user proves they own the server by
 * typing MCP_BEARER_TOKEN (or, when only OAuth is configured, the client secret) on our page, we redirect back with a signed short-lived code, and the client exchanges it (with
 * its client secret, plus PKCE when it used it) for signed access and refresh tokens.
 *
 * Nothing is stored. Trade-off: a code can be replayed until it expires (5 minutes), which is
 * acceptable because redeeming it also requires the client secret, and PKCE when used.
 * Rotating the client secret (or MCP_BEARER_TOKEN, when set) revokes everything.
 */
import { ConfigError } from './config.js';
import { errorPage, loginPage } from './page.js';
import { deriveSigningKey, pkceChallenge, randomId, secretsEqual, signToken, verifyToken, type TokenClaims } from './tokens.js';

export const SCOPE = 'garmin:read';
/** Client ID used unless MCP_OAUTH_CLIENT_ID overrides it. Not a secret: the client secret protects the flow. */
export const DEFAULT_CLIENT_ID = 'garmin-mcp';
const CODE_TTL_S = 5 * 60;
const ACCESS_TTL_S = 60 * 60;
const REFRESH_TTL_S = 30 * 24 * 60 * 60;
const MIN_CLIENT_SECRET_LENGTH = 24;

/** Callback URLs of known clients. More can be added with MCP_OAUTH_REDIRECT_URIS. */
export const DEFAULT_REDIRECT_URIS = [
  'https://claude.ai/api/mcp/auth_callback',
  'https://claude.com/api/mcp/auth_callback',
  'https://chatgpt.com/connector_platform_oauth_redirect',
  'https://vertexaisearch.cloud.google.com/oauth-redirect',
];

/**
 * Gemini app custom MCP connectors call back through Google's OAuth relay with a per-user,
 * per-connector path, e.g. https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-<user>-<host>.
 * Only that exact host and the `user_bound_custom-mcp-` prefix are accepted: other `/r/<id>`
 * relay paths forward to arbitrary Google Cloud projects that anyone can create, and other
 * googleusercontent.com hosts serve user content. Even an attacker's own Gemini connector
 * can't finish a sign-in: it needs the owner's secret on the login page and the client secret.
 */
const GEMINI_CONNECTOR_REDIRECT = /^https:\/\/oauth-redirect\.googleusercontent\.com\/r\/user_bound_custom-mcp-[A-Za-z0-9_-]+$/;

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  /** What the owner types on the sign-in page: MCP_BEARER_TOKEN if set, otherwise the client secret. */
  loginSecret: string;
  loginSecretName: 'MCP_BEARER_TOKEN' | 'MCP_OAUTH_CLIENT_SECRET';
  key: CryptoKey;
  redirectUris: string[];
  /** Delay before answering a wrong MCP_BEARER_TOKEN on the login page. */
  failureDelayMs: number;
}

type Env = Record<string, string | undefined>;

/**
 * OAuth is on when MCP_OAUTH_CLIENT_SECRET is set. The client ID defaults to DEFAULT_CLIENT_ID;
 * setting MCP_OAUTH_CLIENT_ID without a secret is a misconfiguration.
 */
export async function loadOAuthConfig(env: Env, authToken: string | undefined): Promise<OAuthConfig | undefined> {
  const configuredId = env.MCP_OAUTH_CLIENT_ID?.trim();
  const clientSecret = env.MCP_OAUTH_CLIENT_SECRET?.trim();
  if (!clientSecret) {
    if (configuredId) {
      throw new ConfigError('MCP_OAUTH_CLIENT_ID is set but MCP_OAUTH_CLIENT_SECRET is missing. Set the secret to enable OAuth, or remove the client ID.');
    }
    return undefined;
  }
  const clientId = configuredId || DEFAULT_CLIENT_ID;
  if (clientSecret.length < MIN_CLIENT_SECRET_LENGTH) {
    throw new ConfigError(`MCP_OAUTH_CLIENT_SECRET must be at least ${MIN_CLIENT_SECRET_LENGTH} characters (e.g. \`openssl rand -base64 32\`).`);
  }
  const extra = (env.MCP_OAUTH_REDIRECT_URIS ?? '')
    .split(',')
    .map((uri) => uri.trim())
    .filter(Boolean);
  for (const uri of extra) {
    if (!isAbsoluteRedirect(uri)) throw new ConfigError(`MCP_OAUTH_REDIRECT_URIS contains an invalid URL: ${uri}`);
  }
  return {
    clientId,
    clientSecret,
    loginSecret: authToken ?? clientSecret,
    loginSecretName: authToken ? 'MCP_BEARER_TOKEN' : 'MCP_OAUTH_CLIENT_SECRET',
    key: await deriveSigningKey(authToken, clientId, clientSecret),
    redirectUris: [...DEFAULT_REDIRECT_URIS, ...extra],
    failureDelayMs: 500,
  };
}

/** Which OAuth endpoint a request targets, if any. Vercel rewrites pass the original path in `__route`. */
export function oauthRoute(url: URL): 'resource-metadata' | 'server-metadata' | 'authorize' | 'token' | undefined {
  const path = (url.searchParams.get('__route') ?? url.pathname).replace(/\/+$/, '');
  if (path.startsWith('/.well-known/oauth-protected-resource')) return 'resource-metadata';
  if (path.startsWith('/.well-known/oauth-authorization-server') || path.startsWith('/.well-known/openid-configuration')) {
    return 'server-metadata';
  }
  if (path === '/oauth/authorize') return 'authorize';
  if (path === '/oauth/token') return 'token';
  return undefined;
}

/** URL clients should fetch to discover how to authorize for the MCP endpoint at `mcpUrl`. */
export function resourceMetadataUrl(mcpUrl: URL): string {
  const path = mcpUrl.pathname === '/' ? '' : mcpUrl.pathname.replace(/\/+$/, '');
  return `${mcpUrl.origin}/.well-known/oauth-protected-resource${path}`;
}

/** True if `token` is a valid, unexpired access token issued by this server to the configured client. */
export async function isValidAccessToken(token: string, config: OAuthConfig, nowMs: number): Promise<boolean> {
  const claims = await verifyToken(config.key, token, 'access', nowMs);
  return claims?.cid === config.clientId;
}

export async function handleOAuth(
  request: Request,
  route: NonNullable<ReturnType<typeof oauthRoute>>,
  config: OAuthConfig,
  nowMs: number,
): Promise<Response> {
  if (request.method === 'OPTIONS') return cors(new Response(null, { status: 204 }));
  const url = new URL(request.url);
  const origin = url.origin;

  switch (route) {
    case 'resource-metadata': {
      const suffix = (url.searchParams.get('__route') ?? url.pathname).replace(/^\/\.well-known\/oauth-protected-resource/, '');
      return cors(
        json({
          resource: `${origin}${suffix && suffix !== '/' ? suffix : '/mcp'}`,
          authorization_servers: [origin],
          scopes_supported: [SCOPE],
          bearer_methods_supported: ['header'],
          resource_name: 'Garmin',
        }),
      );
    }
    case 'server-metadata':
      return cors(
        json({
          issuer: origin,
          authorization_endpoint: `${origin}/oauth/authorize`,
          token_endpoint: `${origin}/oauth/token`,
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          scopes_supported: [SCOPE],
        }),
      );
    case 'authorize':
      return authorize(request, url, config, nowMs);
    case 'token':
      return cors(await token(request, config, nowMs));
  }
}

// ---------------------------------------------------------------------------------------------
// /oauth/authorize

const AUTHORIZE_PARAMS = ['response_type', 'client_id', 'redirect_uri', 'state', 'scope', 'code_challenge', 'code_challenge_method', 'resource'];

async function authorize(request: Request, url: URL, config: OAuthConfig, nowMs: number): Promise<Response> {
  let source: URLSearchParams;
  if (request.method === 'GET') source = url.searchParams;
  else if (request.method === 'POST') source = new URLSearchParams(await request.text());
  else return errorPage('Method not allowed', 'Use GET or POST.', 405);

  const params: Record<string, string> = {};
  for (const name of AUTHORIZE_PARAMS) {
    const value = source.get(name);
    if (value !== null) params[name] = value;
  }

  // Errors about the client or redirect URI must not redirect (RFC 6749 §4.1.2.1).
  const clientId = params.client_id ?? '';
  const redirectUri = params.redirect_uri ?? '';
  if (!(await secretsEqual(clientId, config.clientId))) {
    return errorPage('Unknown client', `The client ID doesn't match this server's (MCP_OAUTH_CLIENT_ID, default "${DEFAULT_CLIENT_ID}").`);
  }
  if (!isAllowedRedirect(redirectUri, config)) {
    return errorPage(
      'Redirect URL not allowed',
      `This server doesn't allow redirecting to "${redirectUri || '(missing)'}". If this is your MCP client's callback URL, add it to MCP_OAUTH_REDIRECT_URIS (comma-separated) and redeploy.`,
    );
  }

  // Other errors go back to the client.
  if (params.response_type !== 'code') return redirectError(redirectUri, params.state, 'unsupported_response_type');
  if (params.code_challenge !== undefined && (params.code_challenge_method ?? 'plain') !== 'S256') {
    return redirectError(redirectUri, params.state, 'invalid_request', 'Only the S256 code_challenge_method is supported.');
  }

  const secretName = config.loginSecretName;
  if (request.method === 'GET') return loginPage({ params, clientId, redirectUri, secretName });

  const presented = source.get('server_secret') ?? '';
  if (!(await secretsEqual(presented.trim(), config.loginSecret))) {
    await new Promise((resolve) => setTimeout(resolve, config.failureDelayMs));
    return loginPage(
      { params, clientId, redirectUri, secretName, error: `That doesn't match ${secretName} on this server.` },
      401,
    );
  }

  const now = Math.floor(nowMs / 1000);
  const code = await signToken(config.key, {
    typ: 'code',
    cid: config.clientId,
    iat: now,
    exp: now + CODE_TTL_S,
    jti: randomId(),
    scope: SCOPE,
    ru: redirectUri,
    cc: params.code_challenge,
  });
  const target = new URL(redirectUri);
  target.searchParams.set('code', code);
  if (params.state !== undefined) target.searchParams.set('state', params.state);
  return new Response(null, { status: 302, headers: { location: target.toString(), 'cache-control': 'no-store' } });
}

function redirectError(redirectUri: string, state: string | undefined, error: string, description?: string): Response {
  const target = new URL(redirectUri);
  target.searchParams.set('error', error);
  if (description) target.searchParams.set('error_description', description);
  if (state !== undefined) target.searchParams.set('state', state);
  return new Response(null, { status: 302, headers: { location: target.toString(), 'cache-control': 'no-store' } });
}

function isAllowedRedirect(uri: string, config: OAuthConfig): boolean {
  if (config.redirectUris.includes(uri)) return true;
  if (GEMINI_CONNECTOR_REDIRECT.test(uri)) return true;
  // Loopback redirects (any port), as for native apps in RFC 8252: MCP Inspector, local clients.
  try {
    const url = new URL(uri);
    return (
      url.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) &&
      !url.username &&
      !url.password &&
      !url.hash
    );
  } catch {
    return false;
  }
}

function isAbsoluteRedirect(uri: string): boolean {
  try {
    const url = new URL(uri);
    return (url.protocol === 'https:' || url.protocol === 'http:') && !url.hash;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// /oauth/token

async function token(request: Request, config: OAuthConfig, nowMs: number): Promise<Response> {
  if (request.method !== 'POST') return oauthError(405, 'invalid_request', 'Use POST.');
  const body = await readBody(request);

  // Client authentication: HTTP Basic (RFC 6749 §2.3.1) or client_secret_post.
  let clientId = body.get('client_id') ?? '';
  let clientSecret = body.get('client_secret') ?? '';
  const basic = /^Basic\s+(.+)$/i.exec(request.headers.get('authorization') ?? '');
  if (basic?.[1]) {
    try {
      const [id = '', secret = ''] = atob(basic[1]).split(/:(.*)/s);
      clientId = decodeURIComponent(id.replace(/\+/g, ' '));
      clientSecret = decodeURIComponent(secret.replace(/\+/g, ' '));
    } catch {
      return invalidClient();
    }
  }
  const [idOk, secretOk] = await Promise.all([
    secretsEqual(clientId, config.clientId),
    secretsEqual(clientSecret, config.clientSecret),
  ]);
  if (!idOk || !secretOk) return invalidClient();

  const grantType = body.get('grant_type');
  if (grantType === 'authorization_code') {
    const claims = await verifyToken(config.key, body.get('code') ?? '', 'code', nowMs);
    if (!claims || claims.cid !== config.clientId) return oauthError(400, 'invalid_grant', 'The authorization code is invalid or expired.');
    if (claims.ru !== body.get('redirect_uri')) return oauthError(400, 'invalid_grant', 'redirect_uri does not match the authorization request.');
    if (claims.cc !== undefined) {
      const verifier = body.get('code_verifier');
      if (!verifier || (await pkceChallenge(verifier)) !== claims.cc) {
        return oauthError(400, 'invalid_grant', 'PKCE verification failed.');
      }
    }
    return issueTokens(config, claims, nowMs);
  }
  if (grantType === 'refresh_token') {
    const claims = await verifyToken(config.key, body.get('refresh_token') ?? '', 'refresh', nowMs);
    if (!claims || claims.cid !== config.clientId) return oauthError(400, 'invalid_grant', 'The refresh token is invalid or expired.');
    return issueTokens(config, claims, nowMs);
  }
  return oauthError(400, 'unsupported_grant_type', 'Supported grant types: authorization_code, refresh_token.');
}

async function issueTokens(config: OAuthConfig, from: TokenClaims, nowMs: number): Promise<Response> {
  const now = Math.floor(nowMs / 1000);
  const base = { cid: config.clientId, iat: now, scope: from.scope ?? SCOPE };
  const [accessToken, refreshToken] = await Promise.all([
    signToken(config.key, { ...base, typ: 'access', exp: now + ACCESS_TTL_S, jti: randomId() }),
    signToken(config.key, { ...base, typ: 'refresh', exp: now + REFRESH_TTL_S, jti: randomId() }),
  ]);
  return json(
    {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_S,
      refresh_token: refreshToken,
      scope: base.scope,
    },
    200,
    { 'cache-control': 'no-store', pragma: 'no-cache' },
  );
}

async function readBody(request: Request): Promise<URLSearchParams> {
  const text = await request.text();
  if ((request.headers.get('content-type') ?? '').includes('application/json')) {
    try {
      const data = JSON.parse(text) as Record<string, unknown>;
      return new URLSearchParams(
        Object.entries(data).flatMap(([key, value]) => (typeof value === 'string' ? [[key, value]] : [])),
      );
    } catch {
      return new URLSearchParams();
    }
  }
  return new URLSearchParams(text);
}

function invalidClient(): Response {
  return oauthError(401, 'invalid_client', 'Client authentication failed: check the client ID and secret.', {
    'www-authenticate': 'Basic realm="garmin-connect-mcp"',
  });
}

function oauthError(status: number, error: string, description: string, headers: Record<string, string> = {}): Response {
  return json({ error, error_description: description }, status, { 'cache-control': 'no-store', ...headers });
}

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', ...headers } });
}

/** Discovery and token endpoints may be called from browser-based MCP clients. No cookies are used. */
function cors(response: Response): Response {
  response.headers.set('access-control-allow-origin', '*');
  response.headers.set('access-control-allow-methods', 'GET, POST, OPTIONS');
  response.headers.set('access-control-allow-headers', 'authorization, content-type, mcp-protocol-version');
  return response;
}

