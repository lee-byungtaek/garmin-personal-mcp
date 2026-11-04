import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { UnauthorizedError, type OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { createFetchHandler } from "../src/http.js";
import { pkceChallenge } from "../src/oauth/tokens.js";

const ORIGIN = "https://garmin.test";
const SERVER_SECRET = "dummy-server-secret-not-real-0123456789";
const CLIENT_SECRET = "dummy-client-secret-not-real-0123456789";
const REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect";
const VERIFIER = "pkce-verifier-that-is-long-enough-for-the-protocol-0123456789";
function setup(secret = SERVER_SECRET, clientSecret = CLIENT_SECRET) {
  const time = { value: Date.now() };
  const handle = createFetchHandler({ apiKey: "dummy-not-a-garmin-key", bearerToken: secret, publicOrigin: ORIGIN,
    oauthEnv: { MCP_OAUTH_CLIENT_SECRET: clientSecret }, now: () => time.value });
  return { handle, time };
}
type Handle = ReturnType<typeof setup>["handle"];
async function params() {
  return new URLSearchParams({ response_type: "code", client_id: "garmin-mcp", redirect_uri: REDIRECT,
    state: "test-state", scope: "garmin:read", code_challenge_method: "S256", code_challenge: await pkceChallenge(VERIFIER) });
}
async function authorize(handle: Handle, query: URLSearchParams, secret = SERVER_SECRET) {
  const body = new URLSearchParams(query); body.set("server_secret", secret);
  return handle(new Request(`${ORIGIN}/oauth/authorize`, { method: "POST", body }));
}
async function code(handle: Handle) {
  const response = await authorize(handle, await params());
  expect(response.status).toBe(302);
  const location = new URL(response.headers.get("location")!);
  expect(location.searchParams.get("state")).toBe("test-state");
  return location.searchParams.get("code")!;
}
async function token(handle: Handle, fields: Record<string, string>) {
  return handle(new Request(`${ORIGIN}/oauth/token`, { method: "POST", body: new URLSearchParams({
    client_id: "garmin-mcp", client_secret: CLIENT_SECRET, grant_type: "authorization_code",
    redirect_uri: REDIRECT, code_verifier: VERIFIER, ...fields }) }));
}
function listTools(bearer?: string) {
  return new Request(`${ORIGIN}/mcp`, { method: "POST", headers: {
    "content-type": "application/json", accept: "application/json, text/event-stream",
    ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) });
}
describe("ChatGPT OAuth integration", () => {
  it("blocks unauthenticated access and advertises the protected resource", async () => {
    const { handle } = setup();
    const response = await handle(listTools());
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`);
    expect(await (await handle(new Request(`${ORIGIN}/.well-known/oauth-protected-resource/mcp`))).json())
      .toMatchObject({ resource: `${ORIGIN}/mcp`, authorization_servers: [ORIGIN] });
  });
  it("publishes fixed-client OAuth endpoints with no DCR", async () => {
    const { handle } = setup();
    const data = await (await handle(new Request(`${ORIGIN}/.well-known/oauth-authorization-server`))).json();
    expect(data.authorization_endpoint).toBe(`${ORIGIN}/oauth/authorize`);
    expect(data.token_endpoint_auth_methods_supported).toContain("client_secret_post");
    expect(data.registration_endpoint).toBeUndefined();
  });
  it("binds discovery to the configured public origin rather than the Host header", async () => {
    const { handle } = setup();
    const data = await (await handle(new Request("https://untrusted.test/.well-known/oauth-authorization-server"))).json();
    expect(data.issuer).toBe(ORIGIN);
  });
  it("shows a protected sign-in page without revealing either secret", async () => {
    const { handle } = setup();
    const response = await handle(new Request(`${ORIGIN}/oauth/authorize?${await params()}`));
    const html = await response.text();
    expect(response.status).toBe(200);
    expect(html).toContain('type="password"');
    expect(html).not.toContain(SERVER_SECRET);
    expect(html).not.toContain(CLIENT_SECRET);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });
  it("rejects an incorrect owner password", async () => {
    const { handle } = setup();
    const response = await authorize(handle, await params(), "wrong");
    expect(response.status).toBe(401);
    expect(response.headers.get("location")).toBeNull();
  });
  it("rejects unregistered redirect destinations without redirecting", async () => {
    const { handle } = setup();
    const query = await params(); query.set("redirect_uri", "https://attacker.test/callback");
    const response = await authorize(handle, query);
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
  });
  it.each([ { client_secret: "wrong" }, { code_verifier: "wrong" }, { redirect_uri: "https://attacker.test" } ])
    ("rejects invalid token exchange credentials %j", async (overrides) => {
      const { handle } = setup();
      const response = await token(handle, { code: await code(handle), ...overrides } as Record<string, string>);
      expect(response.status).toBeGreaterThanOrEqual(400);
    });
  it("allows OAuth and legacy static-bearer clients to list the existing tools", async () => {
    const { handle } = setup();
    const response = await token(handle, { code: await code(handle) });
    expect(response.status).toBe(200);
    const tokens = await response.json();
    for (const bearer of [tokens.access_token, SERVER_SECRET]) {
      const result = await handle(listTools(bearer));
      expect(result.status).toBe(200);
      expect((await result.json()).result.tools).toHaveLength(25);
    }
    expect((await handle(listTools(CLIENT_SECRET))).status).toBe(401);
  });
  it("rejects expired codes, expired access tokens, and wrong token types", async () => {
    const { handle, time } = setup();
    const grant = await code(handle);
    expect((await handle(listTools(grant))).status).toBe(401);
    const tokens = await (await token(handle, { code: grant })).json();
    expect((await handle(listTools(tokens.refresh_token))).status).toBe(401);
    time.value += 2 * 60 * 60 * 1000;
    expect((await token(handle, { code: grant })).status).toBe(400);
    expect((await handle(listTools(tokens.access_token))).status).toBe(401);
    const refreshed = await token(handle, { grant_type: "refresh_token", refresh_token: tokens.refresh_token });
    expect(refreshed.status).toBe(200);
    expect((await handle(listTools((await refreshed.json()).access_token))).status).toBe(200);
  });
  it("revokes issued tokens when the server password or client secret changes", async () => {
    const { handle } = setup();
    const tokens = await (await token(handle, { code: await code(handle) })).json();
    expect((await setup("rotated-server-secret-0123456789").handle(listTools(tokens.access_token))).status).toBe(401);
    expect((await setup(SERVER_SECRET, "rotated-client-secret-0123456789").handle(listTools(tokens.access_token))).status).toBe(401);
  });
  it("completes OAuth discovery and PKCE with the actual MCP SDK client", async () => {
    const { handle } = setup();
    const fetchViaHandler = (input: string | URL | Request, init?: RequestInit) => handle(input instanceof Request ? input : new Request(input, init));
    let tokens: Awaited<ReturnType<OAuthClientProvider["tokens"]>>;
    let verifier = "";
    let authorizationUrl: URL | undefined;
    const provider: OAuthClientProvider = {
      redirectUrl: REDIRECT,
      clientMetadata: { client_name: "chatgpt-test", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "client_secret_post" },
      clientInformation: () => ({ client_id: "garmin-mcp", client_secret: CLIENT_SECRET }),
      tokens: () => tokens,
      saveTokens: (value) => { tokens = value; },
      redirectToAuthorization: (url) => { authorizationUrl = url; },
      saveCodeVerifier: (value) => { verifier = value; },
      codeVerifier: () => verifier,
    };
    const transport = new StreamableHTTPClientTransport(new URL(`${ORIGIN}/mcp`), { authProvider: provider, fetch: fetchViaHandler });
    const client = new Client({ name: "oauth-test", version: "1.0.0" });
    await expect(client.connect(transport)).rejects.toBeInstanceOf(UnauthorizedError);
    expect(authorizationUrl?.searchParams.get("code_challenge_method")).toBe("S256");
    const response = await authorize(handle, authorizationUrl!.searchParams);
    await transport.finishAuth(new URL(response.headers.get("location")!).searchParams.get("code")!);
    const connected = new Client({ name: "connected-test", version: "1.0.0" });
    await connected.connect(new StreamableHTTPClientTransport(new URL(`${ORIGIN}/mcp`), { authProvider: provider, fetch: fetchViaHandler }));
    expect((await connected.listTools()).tools).toHaveLength(25);
    await connected.close();
  });
});
