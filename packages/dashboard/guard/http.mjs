// Small HTTP helper for the Guard connectors: JSON in/out, one retry on 429/503, readable errors.
export class ProviderError extends Error {
  constructor(message, { status = 0, code = null, body = '' } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

export async function requestJson(
  fetchImpl,
  url,
  { method = 'GET', headers = {}, body, form, timeoutMs = 20_000, raw = false } = {},
) {
  const init = { method, headers: { accept: 'application/json', ...headers }, signal: AbortSignal.timeout(timeoutMs) };
  if (form) {
    init.headers['content-type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  for (let attempt = 0; ; attempt += 1) {
    const response = await fetchImpl(url, init);
    if ((response.status === 429 || response.status === 503) && attempt === 0) {
      const wait = Math.min(10_000, Number(response.headers?.get?.('retry-after') || 2) * 1000);
      await new Promise((resolve) => setTimeout(resolve, wait));
      continue;
    }
    const text = await response.text().catch(() => '');
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {}
    if (!response.ok) {
      const message =
        json?.error?.message ||
        json?.error_description ||
        json?.error?.code ||
        json?.message ||
        (typeof json?.error === 'string' ? json.error : '') ||
        text.slice(0, 200) ||
        `HTTP ${response.status}`;
      throw new ProviderError(`${method} ${new URL(url).pathname} -> ${response.status}: ${message}`, {
        status: response.status,
        code: json?.error?.code || null,
        body: text.slice(0, 500),
      });
    }
    return raw ? { json, headers: response.headers, status: response.status } : json;
  }
}

export function stripPort(ip) {
  const value = String(ip || '').trim();
  if (!value) return null;
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracket) return bracket[1];
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/.exec(value);
  if (v4) return v4[1];
  return value;
}

export function emailsIn(value) {
  return [
    ...new Set(
      String(value || '')
        .toLowerCase()
        .match(/[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}/g) || [],
    ),
  ];
}
