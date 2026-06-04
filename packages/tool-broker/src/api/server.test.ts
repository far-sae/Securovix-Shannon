import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ToolRequest } from '../types.js';
import type { BrokerResponse } from './handler.js';
import { createBrokerServer } from './server.js';

// A stub handler — the handler's own logic is covered in handler.test.ts; here we
// only verify the HTTP transport (routing, body parsing, JSON in/out).
const stubHandle = async (req: ToolRequest): Promise<BrokerResponse> => ({
  result: { tool: req.tool, status: 'success', argv: ['x'], stdout: 'ok', exitCode: 0, durationMs: 1 },
  findings: [],
  record: {
    scanId: req.scanId,
    tool: req.tool,
    argvHash: 'deadbeef',
    status: 'success',
    timestamp: '2026-06-04T00:00:00.000Z',
    signature: 'sig',
  },
});

describe('createBrokerServer (HTTP transport)', () => {
  const server = createBrokerServer(stubHandle);
  let base = '';

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;
    base = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('GET /health returns ok', async () => {
    const r = await fetch(`${base}/health`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ status: 'ok' });
  });

  it('POST /tool runs the handler and returns its response', async () => {
    const body: ToolRequest = { tool: 'sqlmap', params: { url: 'https://x/y' }, scanId: 's1', scopeToken: 't' };
    const r = await fetch(`${base}/tool`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    expect(r.status).toBe(200);
    const json = (await r.json()) as BrokerResponse;
    expect(json.result.status).toBe('success');
    expect(json.result.tool).toBe('sqlmap');
  });

  it('POST /tool with malformed JSON returns 400', async () => {
    const r = await fetch(`${base}/tool`, { method: 'POST', body: '{not json' });
    expect(r.status).toBe(400);
  });

  it('unknown route returns 404', async () => {
    const r = await fetch(`${base}/nope`);
    expect(r.status).toBe(404);
  });
});
