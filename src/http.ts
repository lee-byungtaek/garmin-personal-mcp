/**
 * Stateless Streamable HTTP: one server and transport per request, no session ids.
 *
 * Works the same on a long-running process and on serverless hosts (Vercel,
 * Cloudflare Workers, Deno Deploy), because nothing has to survive between calls.
 * The only thing worth keeping warm is the 24-hour Garmin bearer token, held in a
 * process-wide TokenProvider.
 */
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { timingSafeEqual } from "node:crypto";
import { TokenProvider, resolveApiKey } from "./auth.js";
import { GarminClient } from "./client.js";
import { buildServer } from "./server.js";
import { handleOAuth, isValidAccessToken, loadOAuthConfig, oauthRoute, resourceMetadataUrl } from "./oauth/routes.js";

export interface FetchHandlerOptions {
  apiKey?: string;
  apiKeyFile?: string;
  /** Clients must send `Authorization: Bearer <bearerToken>`. Required: this is your health data. */
  bearerToken: string;
  /** Optional confidential-client OAuth for ChatGPT. Static bearer access remains protected. */
  oauthEnv?: Record<string, string | undefined>;
  /** Canonical HTTPS origin used for discovery, callbacks, and token binding. */
  publicOrigin?: string;
  now?: () => number;
  /** Path(s) the handler answers on. Default "/mcp". */
  path?: string | string[];
}

export function createFetchHandler(opts: FetchHandlerOptions): (request: Request) => Promise<Response> {
  if (!opts.bearerToken) throw new Error("bearerToken is required for HTTP mode");
  const expected = Buffer.from(opts.bearerToken);
  // Deferred so legacy local/stdio users don't need OAuth configuration.
  let oauth: ReturnType<typeof loadOAuthConfig> | undefined;
  const getOAuth = () => (oauth ??= loadOAuthConfig(opts.oauthEnv ?? {}, opts.bearerToken));
  const paths = new Set(Array.isArray(opts.path) ? opts.path : [opts.path ?? "/mcp"]);
  let garmin: Promise<GarminClient> | undefined;
  const client = () =>
    (garmin ??= resolveApiKey(opts).then((apiKey) => new GarminClient(new TokenProvider({ apiKey }))));

  return async (request) => {
    const incoming = new URL(request.url);
    const origin = opts.publicOrigin ? new URL(opts.publicOrigin).origin : incoming.origin;
    const url = new URL(incoming.pathname + incoming.search, origin);
    const canonicalRequest = new Request(url, request);
    const config = await getOAuth();
    const route = oauthRoute(url);
    if (route) return config ? handleOAuth(canonicalRequest, route, config, (opts.now ?? Date.now)()) : new Response("OAuth is not configured", { status: 404 });
    if (!paths.has(url.pathname)) return new Response("Not found", { status: 404 });
    const given = Buffer.from(request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "");
    const staticAllowed = given.length === expected.length && timingSafeEqual(given, expected);
    const oauthAllowed = config && await isValidAccessToken(given.toString("utf8"), config, (opts.now ?? Date.now)());
    if (!staticAllowed && !oauthAllowed) {
      const challenge = config ? `Bearer resource_metadata="${resourceMetadataUrl(url)}", scope="garmin:read"` : "Bearer";
      return new Response("Unauthorized", { status: 401, headers: { "WWW-Authenticate": challenge, "Cache-Control": "no-store" } });
    }
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = buildServer(await client());
    await server.connect(transport);
    try {
      return await transport.handleRequest(canonicalRequest);
    } finally {
      // Nothing to keep: the next request builds its own.
      void transport.close().catch(() => {});
    }
  };
}
