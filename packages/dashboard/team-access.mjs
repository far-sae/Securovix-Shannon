export const ROLES = Object.freeze(['owner', 'admin', 'engineer', 'analyst', 'developer', 'viewer']);

const ROLE_RANK = Object.freeze({ owner: 60, admin: 50, engineer: 40, analyst: 30, developer: 20, viewer: 10 });

export const PERMISSIONS = Object.freeze({
  'org.manage': ['owner', 'admin'],
  'members.manage': ['owner', 'admin'],
  'projects.manage': ['owner', 'admin', 'engineer'],
  'scans.run': ['owner', 'admin', 'engineer'],
  'scans.read': ROLES,
  'scans.stop': ['owner', 'admin', 'engineer'],
  'findings.read': ROLES,
  'findings.triage': ['owner', 'admin', 'engineer', 'analyst'],
  'findings.remediate': ['owner', 'admin', 'engineer', 'developer'],
  'defender.manage': ['owner', 'admin', 'engineer'],
  'settings.manage': ['owner', 'admin'],
  'integrations.manage': ['owner', 'admin'],
  'jobs.read': ['owner', 'admin', 'engineer', 'analyst'],
  'audit.read': ['owner', 'admin', 'analyst', 'viewer'],
});

export const FINDING_STATUSES = Object.freeze([
  'new',
  'triaged',
  'assigned',
  'in-progress',
  'ready-for-retest',
  'resolved',
  'risk-accepted',
  'false-positive',
]);

export function normalizeRole(role) {
  return ROLES.includes(role) ? role : 'viewer';
}

export function can(role, permission) {
  return (PERMISSIONS[permission] || []).includes(normalizeRole(role));
}

export function outranks(actorRole, targetRole) {
  return (ROLE_RANK[normalizeRole(actorRole)] || 0) > (ROLE_RANK[normalizeRole(targetRole)] || 0);
}

export function canChangeMember(actor, target, nextRole) {
  if (!actor || !target || !ROLES.includes(nextRole)) return false;
  if (actor.role === 'owner') return target.role !== 'owner' || actor.userId === target.userId;
  if (actor.role !== 'admin') return false;
  return target.role !== 'owner' && nextRole !== 'owner' && outranks(actor.role, target.role);
}

export function canTransitionFinding(role, from, to) {
  if (!FINDING_STATUSES.includes(to)) return false;
  if (to === 'risk-accepted' || to === 'false-positive') return can(role, 'findings.triage');
  if (to === 'ready-for-retest' || to === 'resolved') return can(role, 'findings.remediate') || can(role, 'findings.triage');
  return can(role, 'findings.triage') || can(role, 'findings.remediate');
}

export function validateFindingTransition({ role, currentStatus = 'new', nextStatus, reason, expiresAt }) {
  if (!canTransitionFinding(role, currentStatus, nextStatus)) return { ok: false, error: 'transition not permitted' };
  if ((nextStatus === 'risk-accepted' || nextStatus === 'false-positive') && !String(reason || '').trim()) {
    return { ok: false, error: 'a reason is required' };
  }
  if (nextStatus === 'risk-accepted') {
    const expiry = Date.parse(expiresAt || '');
    if (!Number.isFinite(expiry) || expiry <= Date.now()) return { ok: false, error: 'a future expiry is required' };
  }
  return { ok: true };
}

export function slugifyOrg(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

export function sanitizeLabel(value, max = 120) {
  return [...String(value || '').trim()]
    .filter((char) => {
      const code = char.charCodeAt(0);
      return code > 31 && code !== 127;
    })
    .join('')
    .slice(0, max);
}
