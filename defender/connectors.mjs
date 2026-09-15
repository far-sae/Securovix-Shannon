// defender/connectors.mjs — live traffic sources, normalized to one AttackEvent stream.
//
// Modeled on the engine's proven filtering reverse proxy (purple-engine.mjs startProxy), but
// purpose-built for continuous defense: configurable bind, an event hook that also carries the
// block decision, and FAIL-OPEN semantics (a classifier error forwards traffic, never blocks it).
import http from 'node:http';
import https from 'node:https';

export function httpProxyConnector({ origin, port = 0, host = '127.0.0.1', onEvent }) {
  const o = new URL(origin);
  const agent = o.protocol === 'https:' ? https : http;

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => {
      body += d;
    });
    req.on('end', () => {
      const event = {
        at: new Date().toISOString(),
        source: 'http-proxy',
        srcIp: req.socket?.remoteAddress || null,
        method: req.method,
        url: req.url,
        headers: req.headers,
        body,
        connId: null,
        raw: `${req.method} ${req.url}`,
      };

      let block = false;
      try {
        block = onEvent?.(event)?.block === true;
      } catch {
        block = false; // FAIL-OPEN: never break the protected app on our own error
      }

      if (block) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('Blocked by Shannon Defender');
        return;
      }

      const fwd = agent.request(
        {
          hostname: o.hostname,
          port: o.port || (o.protocol === 'https:' ? 443 : 80),
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: o.host },
          timeout: 10_000,
        },
        (up) => {
          res.writeHead(up.statusCode || 502, up.headers);
          up.pipe(res);
        },
      );
      fwd.on('error', () => {
        res.writeHead(502);
        res.end('upstream error');
      });
      if (body) fwd.write(body);
      fwd.end();
    });
  });

  return new Promise((resolve) =>
    server.listen(port, host, () =>
      resolve({
        meta: { kind: 'http-proxy', url: `http://${host}:${server.address().port}`, origin },
        port: server.address().port,
        stop: () => new Promise((r) => server.close(r)),
      }),
    ),
  );
}
