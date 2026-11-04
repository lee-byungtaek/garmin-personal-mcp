/**
 * Stateless, HMAC-signed OAuth artifacts (authorization codes, access and refresh
 * tokens). Web Crypto only, so this runs on every fetch-style runtime.
 *
 * Format: `gcm1.<base64url(JSON claims)>.<base64url(HMAC-SHA256)>`.
 */
import { base64UrlToBytes, bytesToBase64Url } from './encoding.js';

const PREFIX = 'gcm1';
const encoder = new TextEncoder();

export type TokenType = 'code' | 'access' | 'refresh';

export interface TokenClaims {
  typ: TokenType;
  /** OAuth client ID the token was issued to. */
  cid: string;
  /** Issued at / expires at, epoch seconds. */
  iat: number;
  exp: number;
  /** Random ID so two tokens issued in the same second differ. */
  jti: string;
  scope?: string;
  /** Codes only: the redirect URI and PKCE S256 challenge from the authorization request. */
  ru?: string;
  cc?: string;
}

/**
 * Signing key bound to the client credentials and, when set, MCP_BEARER_TOKEN: changing any
 * of them invalidates every code and token issued before.
 */
export async function deriveSigningKey(authToken: string | undefined, clientId: string, clientSecret: string): Promise<CryptoKey> {
  const material = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`garmin-connect-mcp/oauth/v2\n${clientId}\n${clientSecret}\n${authToken ?? ''}`),
  );
  return crypto.subtle.importKey('raw', material, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function signToken(key: CryptoKey, claims: TokenClaims): Promise<string> {
  const body = bytesToBase64Url(encoder.encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(`${PREFIX}.${body}`));
  return `${PREFIX}.${body}.${bytesToBase64Url(new Uint8Array(signature))}`;
}

/** Returns the claims if the token is ours, unmodified, of the expected type and not expired. */
export async function verifyToken(
  key: CryptoKey,
  token: string,
  expected: TokenType,
  nowMs: number,
): Promise<TokenClaims | undefined> {
  const [prefix, body, signature, ...rest] = token.split('.');
  if (prefix !== PREFIX || !body || !signature || rest.length) return undefined;
  try {
    // crypto.subtle.verify compares in constant time.
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlToBytes(signature),
      encoder.encode(`${PREFIX}.${body}`),
    );
    if (!valid) return undefined;
    const claims = JSON.parse(new TextDecoder().decode(base64UrlToBytes(body))) as TokenClaims;
    if (claims.typ !== expected || typeof claims.exp !== 'number' || claims.exp * 1000 <= nowMs) return undefined;
    return claims;
  } catch {
    return undefined;
  }
}

export function randomId(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
}

/** PKCE S256: base64url(SHA-256(verifier)). */
export async function pkceChallenge(verifier: string): Promise<string> {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(verifier))));
}

/** Constant-time string comparison (hash both, compare digests). */
export async function secretsEqual(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ]);
  const ax = new Uint8Array(x);
  const by = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < ax.length; i++) diff |= (ax[i] ?? 0) ^ (by[i] ?? 0);
  return diff === 0;
}

