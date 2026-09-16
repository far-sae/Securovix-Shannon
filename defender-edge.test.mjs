import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import { createEdgeServer, isPrivateAddress, routes } from './packages/defender-edge/server.mjs';

test('edge upstream guard rejects private and metadata IPv4 ranges', () => {
  for (const ip of ['127.0.0.1', '10.0.0.8', '172.16.2.3', '192.168.1.2', '169.254.169.254', '100.64.0.1']) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  assert.equal(isPrivateAddress('8.8.8.8'), false);
});

test('edge upstream guard rejects private IPv6 ranges', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fd12::1', 'fe80::1']) assert.equal(isPrivateAddress(ip), true, ip);
  assert.equal(isPrivateAddress('2606:4700:4700::1111'), false);
});

test('edge rejects a configured loopback origin by default', async () => {
  routes.set('private.example.test', { origin: 'http://127.0.0.1:9', mode: 'monitor' });
  const edge = createEdgeServer();
  await new Promise((resolve) => edge.listen(0, '127.0.0.1', resolve));
  try {
    const result = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: edge.address().port, path: '/', headers: { host: 'private.example.test' } },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        },
      );
      req.on('error', reject);
      req.end();
    });
    assert.equal(result, 502);
  } finally {
    routes.delete('private.example.test');
    await new Promise((resolve) => edge.close(resolve));
  }
});
