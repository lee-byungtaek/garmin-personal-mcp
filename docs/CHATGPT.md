# Connect your personal Garmin MCP to ChatGPT

This fork adds single-owner, confidential-client OAuth to the existing read-only
Garmin MCP. Garmin requests and FIT decoding are unchanged. OAuth code is adapted
from Pedro Kehl's MIT-licensed garmin-connect-mcp (commit
b90f0c226f9cfc8b22a7e119f896c717a5b97bce); its license is in src/oauth/LICENSE.

## Vercel environment variables

Keep the existing GARMIN_PERSONAL_API_KEY and MCP_BEARER_TOKEN values.
Add MCP_OAUTH_CLIENT_SECRET, a NEW random secret of at least 32 bytes, and set:

- MCP_OAUTH_CLIENT_ID: garmin-mcp
- MCP_PUBLIC_ORIGIN: https://garmin-personal-mcp-nu.vercel.app

Store secrets only in Vercel's secret/environment settings, never in the repository.
Redeploy after changing environment variables. Do not disable bearer authentication.

## ChatGPT custom MCP settings

- Server URL: https://garmin-personal-mcp-nu.vercel.app/mcp
- Authentication: OAuth
- Client ID: garmin-mcp
- Client secret: the NEW MCP_OAUTH_CLIENT_SECRET
- Registration URL: leave empty; this uses a pre-registered confidential client

When your own server's authorization page opens, enter MCP_BEARER_TOKEN (the
existing random server password), NOT your Garmin API key. Authorize only the
connection you initiated. Start with `List my last three synced running activities`.

## What has and hasn't been verified

Automated checks use dummy secrets and mocked Garmin responses. No live Garmin
credential is required by the test suite. A ready Vercel deployment alone does not
prove Garmin access or ChatGPT/mobile compatibility; verify those after connecting.

## Single-owner design limits

The inherited OAuth implementation is stateless: authorization codes expire after
five minutes but cannot be marked consumed across serverless instances. Redemption
requires the confidential client secret and the PKCE verifier when a challenge is
present. Refresh tokens have a fixed 30-day lifetime; they aren't stored/revoked
individually. Rotate MCP_BEARER_TOKEN or MCP_OAUTH_CLIENT_SECRET and redeploy to
invalidate all connections. This is a personal deployment, not a multi-user service.
For strict single-use codes and refresh rotation, use a persistent OAuth provider.
