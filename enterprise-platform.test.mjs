import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

const dataDir = mkdtempSync(join(tmpdir(), 'shannon-enterprise-test-'));
process.env.SHANNON_DATA_DIR = dataDir;
process.env.SHANNON_FORCE_LOCAL_DB = '1';
process.env.SHANNON_ENCRYPTION_KEY = 'enterprise-platform-test-encryption-key';
process.env.NODE_ENV = 'test';

const security = await import('./packages/dashboard/enterprise-security.mjs');
const database = await import('./packages/dashboard/enterprise-db.mjs');
const worker = await import('./packages/dashboard/worker.mjs');

after(() => rmSync(dataDir, { recursive: true, force: true }));

test('enterprise secrets, signed challenges, TOTP and recovery codes are verifiable', () => {
  const encrypted = security.encryptSecret({ token: 'very-secret', nested: { value: 7 } });
  assert.notEqual(encrypted, 'very-secret');
  assert.deepEqual(security.decryptSecret(encrypted), { token: 'very-secret', nested: { value: 7 } });
  assert.throws(() => security.decryptSecret(`${encrypted.slice(0, -1)}x`));

  const challenge = security.signChallenge({ uid: 'user-1' }, 'test', 60_000);
  assert.equal(security.verifyChallenge(challenge, 'test').uid, 'user-1');
  assert.equal(security.verifyChallenge(challenge, 'wrong-purpose'), null);

  const secret = security.newTotpSecret();
  const now = 1_800_000_000_000;
  assert.equal(security.verifyTotp(secret, security.totpCode(secret, now), now), true);
  const recovery = security.createRecoveryCodes(2);
  const hashes = security.hashRecoveryCodes(recovery);
  assert.equal(security.consumeRecoveryCode(recovery[0], hashes).length, 1);
  assert.equal(security.consumeRecoveryCode(recovery[0], security.consumeRecoveryCode(recovery[0], hashes)), null);
});

test('one-time auth tokens are consumed once', async () => {
  const raw = security.randomToken();
  const tokenHash = security.hashToken(raw);
  await database.createAuthToken({
    id: 'token-1',
    tokenHash,
    kind: 'password-reset',
    userId: null,
    email: 'user@example.test',
    orgId: null,
    role: null,
    createdBy: null,
    expiresAt: Date.now() + 60_000,
    usedAt: null,
    createdAt: Date.now(),
  });
  assert.equal((await database.findAuthToken(tokenHash, 'password-reset')).id, 'token-1');
  assert.equal((await database.consumeAuthToken(tokenHash, 'password-reset')).id, 'token-1');
  assert.equal(await database.consumeAuthToken(tokenHash, 'password-reset'), null);
});

test('durable jobs are idempotent, claimed once and recovered after a stale lease', async () => {
  const first = await database.enqueueJob({
    orgId: 'org-1',
    type: 'email',
    payload: { to: 'a@example.test' },
    idempotencyKey: 'mail-1',
  });
  const duplicate = await database.enqueueJob({
    orgId: 'org-1',
    type: 'email',
    payload: { to: 'b@example.test' },
    idempotencyKey: 'mail-1',
  });
  assert.equal(duplicate.id, first.id);

  const claimed = await database.claimJobs('worker-a', 5);
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].status, 'running');
  assert.equal((await database.claimJobs('worker-b', 5)).length, 0);

  await database.updateJob(first.id, { heartbeatAt: 1, lockedAt: 1 });
  assert.equal(await database.requeueStaleJobs(Date.now() - 1000), 1);
  const recovered = await database.getJob(first.id);
  assert.equal(recovered.status, 'queued');
  assert.equal(recovered.lockedBy, null);
});

test('operational heartbeats are queryable and worker health is explicit', async () => {
  await database.appendOperationalEvent({
    service: 'worker',
    instanceId: 'worker-test',
    level: 'info',
    event: 'worker.heartbeat',
    metadata: { activeJobs: 0 },
    createdAt: Date.now(),
  });
  const events = await database.listOperationalEvents('worker', 5);
  assert.equal(events[0].event, 'worker.heartbeat');
  assert.equal(events[0].instanceId, 'worker-test');

  const health = worker.createWorkerHealthServer();
  await new Promise((resolve) => health.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${health.address().port}`;
  assert.equal((await fetch(`${base}/healthz`)).status, 200);
  assert.equal((await fetch(`${base}/readyz`)).status, 503);
  await new Promise((resolve) => health.close(resolve));
});
