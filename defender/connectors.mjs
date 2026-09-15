// defender/connectors.mjs — live traffic sources, normalized to one AttackEvent stream.
//
// Modeled on the engine's proven filtering reverse proxy (purple-engine.mjs startProxy), but
// purpose-built for continuous defense: configurable bind, an event hook that also carries the
// block decision, and FAIL-OPEN semantics (a classifier error forwards traffic, never blocks it).
import http from 'node:http';
import https from 'node:https';

// TRADE-OFF: we classify the first 1 MB of a request body. An inline device that buffers whole
// uploads is a memory-exhaustion vector, so past the cap we stop buffering and stream the request
// through unclassified — fail-open, consistent with the rest of this connector.
const MAX_CLASSIFIED_BODY = 1024 * 1024;

// Hop-by-hop headers are strictly per-connection (RFC 9110 §7.6.1). This connector re-frames the
// request itself, so forwarding the client's framing/connection headers verbatim would let a
// crafted content-length + transfer-encoding pair desync the proxy from the upstream (CL.TE
// request smuggling) — an unacceptable hazard in a device whose whole job is to sit inline.
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export function httpProxyConnector({ origin, port = 0, host = '127.0.0.1', onEvent }) {
  const o = new URL(origin);
  const agent = o.protocol === 'https:' ? https : http;

  const server = http.createServer((req, res) => {
    // A client that disconnects mid-response makes the response stream emit 'error' inside a
    // callback. Unhandled, that throws with no uncaughtException handler anywhere — killing the
    // dashboard process and every other user's defender along with it.
    res.on('error', () => {});
    req.on('error', () => {});

    // `body` is null on the streaming path: the upstream length then comes from the client's own
    // content-length (we forward the bytes verbatim), or Node re-chunks when there is none.
    const upstreamHeaders = (body) => {
      const out = {};
      for (const [k, v] of Object.entries(req.headers || {})) {
        const lk = k.toLowerCase();
        if (HOP_BY_HOP.has(lk) || lk === 'host' || lk === 'content-length') continue;
        out[k] = v;
      }
      out.host = o.host;
      if (body === null) {
        const cl = req.headers['content-length'];
        if (cl !== undefined) out['content-length'] = cl;
      } else if (body.length) {
        out['content-length'] = String(Buffer.byteLength(body));
      }
      return out;
    };

    const openUpstream = (headers) => {
      const fwd = agent.request(
        {
          hostname: o.hostname,
          port: o.port || (o.protocol === 'https:' ? 443 : 80),
          path: req.url,
          method: req.method,
          headers,
          timeout: 10_000,
        },
        (up) => {
          up.on('error', () => res.destroy());
          try {
            // A malformed upstream header set makes writeHead throw inside this callback.
            res.writeHead(up.statusCode || 502, up.headers);
            up.pipe(res);
          } catch {
            up.destroy();
            res.destroy();
          }
        },
      );
      // `timeout` only arms the socket timer — without this listener the request hangs forever.
      fwd.on('timeout', () => fwd.destroy());
      fwd.on('error', () => {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        try {
          res.writeHead(502);
          res.end('upstream error');
        } catch {
          res.destroy();
        }
      });
      return fwd;
    };

    let chunks = [];
    let size = 0;
    let oversize = false;

    req.on('data', (d) => {
      if (oversize) return; // the pipe below owns the rest of the stream
      size += d.length;
      if (size > MAX_CLASSIFIED_BODY) {
        oversize = true;
        const fwd = openUpstream(upstreamHeaders(null));
        for (const c of chunks) fwd.write(c);
        chunks = [];
        fwd.write(d);
        req.pipe(fwd);
        return;
      }
      chunks.push(d);
    });

    req.on('end', () => {
      if (oversize) return; // forwarded unclassified; req.pipe() ends the upstream request
      const bodyBuf = Buffer.concat(chunks);
      chunks = [];
      // Classify on a text view, but forward the ORIGINAL BYTES. Decoding a binary body as UTF-8
      // and re-encoding it replaces every non-UTF-8 byte with U+FFFD — and because we also re-frame
      // content-length, the corruption is self-consistent, so the protected app never notices its
      // uploads/gzip/protobuf arrived mangled. latin1 is a byte-preserving view: one char per byte,
      // so ASCII signatures still match and nothing is lost on the wire.
      const body = bodyBuf.toString('latin1');
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

      const fwd = openUpstream(upstreamHeaders(bodyBuf));
      if (bodyBuf.length) fwd.write(bodyBuf);
      fwd.end();
    });
  });

  return new Promise((resolve, reject) => {
    // Without this, an EADDRINUSE bind failure is an uncaught exception rather than a rejection
    // the connect route can report.
    server.on('error', reject);
    server.listen(port, host, () =>
      resolve({
        meta: { kind: 'http-proxy', url: `http://${host}:${server.address().port}`, origin },
        port: server.address().port,
        stop: () => new Promise((r) => server.close(r)),
      }),
    );
  });
}
