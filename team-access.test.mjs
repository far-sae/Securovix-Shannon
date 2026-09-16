import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  FINDING_STATUSES,
  can,
  canChangeMember,
  canTransitionFinding,
  slugifyOrg,
  validateFindingTransition,
} from './packages/dashboard/team-access.mjs';

test('RBAC keeps privileged actions away from viewers and developers', () => {
  assert.equal(can('viewer', 'scans.read'), true);
  assert.equal(can('viewer', 'scans.run'), false);
  assert.equal(can('developer', 'findings.remediate'), true);
  assert.equal(can('developer', 'findings.triage'), false);
  assert.equal(can('admin', 'members.manage'), true);
});

test('only an owner can promote another owner or modify an owner', () => {
  const owner = { userId: 'u1', role: 'owner' };
  const admin = { userId: 'u2', role: 'admin' };
  const engineer = { userId: 'u3', role: 'engineer' };
  assert.equal(canChangeMember(admin, engineer, 'viewer'), true);
  assert.equal(canChangeMember(admin, owner, 'viewer'), false);
  assert.equal(canChangeMember(admin, engineer, 'owner'), false);
  assert.equal(canChangeMember(owner, admin, 'owner'), true);
});

test('risk decisions require an explanation and risk acceptance expires', () => {
  assert.equal(canTransitionFinding('analyst', 'new', 'risk-accepted'), true);
  assert.equal(validateFindingTransition({ role: 'analyst', nextStatus: 'false-positive' }).ok, false);
  assert.equal(
    validateFindingTransition({
      role: 'analyst',
      nextStatus: 'risk-accepted',
      reason: 'Compensating control',
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    }).ok,
    true,
  );
  assert.equal(validateFindingTransition({ role: 'viewer', nextStatus: 'triaged' }).ok, false);
  assert.ok(FINDING_STATUSES.includes('ready-for-retest'));
});

test('organization slugs are bounded and URL-safe', () => {
  assert.equal(slugifyOrg('  Red Team / London  '), 'red-team-london');
  assert.equal(slugifyOrg('!!!'), '');
  assert.ok(slugifyOrg('a'.repeat(100)).length <= 48);
});
