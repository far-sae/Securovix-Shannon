import { type Server, createServer } from 'node:http';
import type { ToolRequest } from '../types.js';
import type { BrokerResponse } from './handler.js';

const MAX_BODY_BYTES = 1 * 1024 * 1024; // tool requests are small; cap to avoid abuse

// Thin HTTP transport around a broker handler. POST /tool runs the request through
// the handler; GET /health is a liveness probe. The handler holds all the policy.
export function createBrokerServer(handle: (req: ToolRequest) => Promise<BrokerResponse>): Server {
  return createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }

    if (req.method === 'POST' && req.url === '/tool') {
      let body = '';
      let tooLarge = false;
      req.on('data', (chunk) => {
        body += chunk;
        if (body.length > MAX_BODY_BYTES) {
          tooLarge = true;
          req.destroy();
        }
      });
      req.on('end', () => {
        if (tooLarge) return;
        void (async () => {
          try {
            const toolReq = JSON.parse(body) as ToolRequest;
            const response = await handle(toolReq);
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify(response));
          } catch (e) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }));
          }
        })();
      });
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });
}
