/** Minimal, dependency-free HTML for the OAuth sign-in step. Every reflected value is escaped. */

export interface LoginPageInput {
  /** Hidden fields re-posted with the form (the authorization request). */
  params: Record<string, string>;
  clientId: string;
  redirectUri: string;
  /** Which server secret the owner must type. */
  secretName: 'MCP_BEARER_TOKEN' | 'MCP_OAUTH_CLIENT_SECRET';
  error?: string;
}

const SECRET_LABELS = {
  MCP_BEARER_TOKEN: '서버 접속용 비밀값',
  MCP_OAUTH_CLIENT_SECRET: 'OAuth client secret',
} as const;

export function loginPage(input: LoginPageInput, status = 200): Response {
  const hidden = Object.entries(input.params)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('\n        ');
  const redirectHost = safeHost(input.redirectUri);
  const body = `
    <h1>가민 기록 연결</h1>
    <p><strong>${escapeHtml(input.clientId)}</strong>에서 가민 기록을 읽을 수 있도록 연결합니다.
       연결 후 <strong>${escapeHtml(redirectHost)}</strong>(으)로 돌아갑니다.</p>
    ${input.error ? `<p class="error" role="alert">${escapeHtml(input.error)}</p>` : ''}
    <form method="post" action="/oauth/authorize">
        ${hidden}
        <label for="server_secret">${SECRET_LABELS[input.secretName]} (<code>${input.secretName}</code>)</label>
        <input id="server_secret" name="server_secret" type="password" autocomplete="current-password" required autofocus>
        <button type="submit">연결 허용</button>
    </form>
    <p class="hint">가민 API 키를 입력하는 곳이 아닙니다. Vercel에 저장한 MCP_BEARER_TOKEN을 입력하세요. 본인이 시작한 연결일 때만 허용하세요.</p>`;
  return htmlResponse(body, status);
}

export function errorPage(title: string, message: string, status = 400): Response {
  return htmlResponse(`<h1>${escapeHtml(title)}</h1><p class="error">${escapeHtml(message)}</p>`, status);
}

function htmlResponse(body: string, status: number): Response {
  const html = `<!doctype html>
<html lang="ko">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex">
    <title>가민 기록 연결</title>
    <link rel="icon" href="/favicon.ico" sizes="32x32 64x64">
    <link rel="icon" href="/icon.svg" type="image/svg+xml">
    <style>
      body { font: 16px/1.5 system-ui, sans-serif; max-width: 30rem; margin: 4rem auto; padding: 0 1rem; color: #222; }
      h1 { display: flex; align-items: center; gap: 0.6rem; }
      h1 img { border-radius: 9px; }
      label { display: block; margin: 1.5rem 0 0.4rem; font-weight: 600; }
      input[type=password] { width: 100%; padding: 0.6rem; font-size: 1rem; box-sizing: border-box; }
      button { margin-top: 1rem; padding: 0.6rem 1.2rem; font-size: 1rem; cursor: pointer; }
      .error { color: #b00020; }
      .hint { color: #666; font-size: 0.9rem; margin-top: 2rem; }
      code { background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 4px; }
    </style>
  </head>
  <body>${body}
  </body>
</html>`;
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      // No form-action: browsers apply it to every redirect after the form is submitted, and OAuth
      // callbacks chain through further origins (e.g. Google's relay forwards to Gemini), which it
      // blocks. Injected forms aren't possible anyway: no scripts run and every value is escaped.
      'content-security-policy': "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    },
  });
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeHost(uri: string): string {
  try {
    return new URL(uri).host;
  } catch {
    return 'an unknown address';
  }
}

