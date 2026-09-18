import http from 'node:http';
import crypto from 'node:crypto';
import { dockerAvailable, executeSandbox } from './exec.mjs';

const port = Number(process.env.PORT || 8080);
const token = String(process.env.SHANNON_SANDBOX_RUNNER_TOKEN || '');
if (token.length < 32) throw new Error('SHANNON_SANDBOX_RUNNER_TOKEN must be at least 32 characters');

function authorized(req) {
  const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return supplied.length === token.length && crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(token));
}
function send(res, status, body) { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); }

http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    if (!authorized(req)) return send(res, 401, { ok: false, error: 'Unauthorized' });
    return send(res, 200, { ok: true, docker: await dockerAvailable() });
  }
  if (req.method !== 'POST' || req.url !== '/v1/run') return send(res, 404, { error: 'Not found' });
  if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
  let raw = ''; let tooLarge = false;
  req.on('data', (chunk) => { raw += chunk; if (raw.length > 300_000) { tooLarge = true; req.destroy(); } });
  req.on('end', async () => {
    if (tooLarge) return send(res, 413, { error: 'Request too large' });
    let body; try { body = JSON.parse(raw); } catch { return send(res, 400, { error: 'Invalid JSON' }); }
    const result = await executeSandbox(body);
    send(res, result.status || 200, result);
  });
}).listen(port, '0.0.0.0', () => console.log(`[sandbox-runner] listening on ${port}`));
