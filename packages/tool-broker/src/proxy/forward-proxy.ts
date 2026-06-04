import { type IncomingMessage, type Server, createServer, request as httpRequest } from 'node:http';
import { connect as netConnect } from 'node:net';
import type { ScopeEnforcer } from '../scope/enforcer.js';

export interface ForwardProxyDeps {
  enforcer: ScopeEnforcer;
  // Resolves a hostname to the IP the request will actually connect to. Injected so
  // it can be pinned (resolve once at scan start) and mocked in tests. Throwing here
  // (e.g. NXDOMAIN) results in a 502.
  resolve: (host: string) => Promise<string>;
}

// A forward proxy that is the ONLY egress path for sandboxed tools: every forwarded
// request is checked against the ScopeEnforcer on the *resolved, pinned* IP, so a
// tool cannot reach anything out of scope (cloud metadata, RFC1918, other hosts) even
// if it tries — and DNS rebinding can't help, because we connect to the IP we resolved
// and scope-checked, not whatever the tool re-resolves.
export function createForwardProxy(deps: ForwardProxyDeps): Server {
  const server = createServer((req, res) => {
    void (async () => {
      let url: URL;
      try {
        url = new URL(req.url ?? '');
      } catch {
        res.writeHead(400);
        res.end('proxy: absolute URL required');
        return;
      }
      let ip: string;
      try {
        ip = await deps.resolve(url.hostname);
      } catch {
        res.writeHead(502);
        res.end('proxy: resolution failed');
        return;
      }
      const decision = deps.enforcer.evaluate(ip, url.pathname);
      if (!decision.allowed) {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end(`proxy: blocked (${decision.reason})`);
        return;
      }
      forward(req, res, ip, url);
    })();
  });

  // HTTPS via CONNECT: we can't see the path, but we pin+scope-check the host:IP and
  // only then tunnel raw bytes to the resolved IP.
  server.on('connect', (req, clientSocket, head) => {
    void (async () => {
      const [host, portStr] = (req.url ?? '').split(':');
      let ip: string;
      try {
        ip = await deps.resolve(host);
      } catch {
        clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
        return;
      }
      const decision = deps.enforcer.evaluate(ip, '/');
      if (!decision.allowed) {
        clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
        return;
      }
      const upstream = netConnect(Number(portStr) || 443, ip, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
      upstream.on('error', () => clientSocket.end());
      clientSocket.on('error', () => upstream.destroy());
    })();
  });

  return server;
}

function forward(req: IncomingMessage, res: import('node:http').ServerResponse, ip: string, url: URL): void {
  const upstream = httpRequest(
    {
      host: ip,
      port: Number(url.port) || 80,
      path: `${url.pathname}${url.search}`,
      method: req.method,
      headers: { ...req.headers, host: url.host }, // preserve intended Host for vhosts
    },
    (pres) => {
      res.writeHead(pres.statusCode ?? 502, pres.headers);
      pres.pipe(res);
    },
  );
  upstream.on('error', () => {
    res.writeHead(502);
    res.end('proxy: upstream error');
  });
  req.pipe(upstream);
}
