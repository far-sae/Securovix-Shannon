const DAY_MS = 86_400_000;

const severityWeight = Object.freeze({ info: 0, low: 1, medium: 3, high: 7, critical: 12 });

function eventTime(event) {
  return Number(event.createdAt || Date.parse(event.at || '') || 0);
}

function covered(asset, routes, now) {
  if (asset.status !== 'active') return false;
  if (asset.coverage === 'online' && Number(asset.config?.lastSeenAt || 0) >= now - 15 * 60_000) return true;
  if (!['web', 'api', 'domain'].includes(asset.type)) return false;
  let host = '';
  try {
    host = new URL(asset.locator.includes('://') ? asset.locator : `https://${asset.locator}`).hostname;
  } catch {}
  return routes.some((route) => route.host === host);
}

export function buildDefenseCycle({
  assets = [],
  routes = [],
  events = [],
  findings = [],
  jobs = [],
  previousCycle = null,
  now = Date.now(),
} = {}) {
  const recent = events.filter((event) => eventTime(event) >= now - DAY_MS);
  const activeAssets = assets.filter((asset) => asset.status === 'active');
  const coveredAssets = activeAssets.filter((asset) => covered(asset, routes, now));
  const openEvents = recent.filter((event) => ['open', 'investigating'].includes(event.status || 'open'));
  const falsePositives = recent.filter((event) => event.status === 'false-positive');
  const blocked = recent.filter((event) => event.enforced === true);
  const failedJobs = jobs.filter((job) => ['failed', 'dead-letter'].includes(job.status));
  const openFindings = findings.filter((finding) => !['resolved', 'accepted', 'closed'].includes(finding.status));
  const importantFindings = openFindings.filter((finding) => ['high', 'critical'].includes(finding.severity));

  const byClass = new Map();
  for (const event of recent) {
    const name = String(event.cls || 'unknown');
    const row = byClass.get(name) || { name, observed: 0, blocked: 0, unresolved: 0, falsePositives: 0, weight: 0 };
    row.observed += 1;
    if (event.enforced) row.blocked += 1;
    if (['open', 'investigating'].includes(event.status || 'open')) row.unresolved += 1;
    if (event.status === 'false-positive') row.falsePositives += 1;
    row.weight += severityWeight[event.severity] ?? severityWeight.medium;
    byClass.set(name, row);
  }
  const previousClasses = new Map((previousCycle?.learning?.classes || []).map((row) => [row.name, row]));
  const classes = [...byClass.values()]
    .map((row) => ({
      ...row,
      recurring: row.observed > 1 || Number(previousClasses.get(row.name)?.observed || 0) > 0,
      priority: Math.max(0, row.weight + row.unresolved * 3 - row.falsePositives * 4),
    }))
    .sort((a, b) => b.priority - a.priority || b.observed - a.observed);

  const lessons = [];
  for (const row of classes.slice(0, 8)) {
    if (row.falsePositives)
      lessons.push({
        type: 'false-positive',
        attackClass: row.name,
        recommendation: 'Review this deterministic rule before expanding enforcement.',
      });
    else if (row.unresolved && row.recurring)
      lessons.push({
        type: 'recurrence',
        attackClass: row.name,
        recommendation: 'Escalate this recurring class and validate the affected control.',
      });
    else if (row.unresolved)
      lessons.push({
        type: 'unresolved',
        attackClass: row.name,
        recommendation: 'Investigate the open detection and record its disposition.',
      });
  }
  if (coveredAssets.length < activeAssets.length)
    lessons.push({
      type: 'coverage-gap',
      count: activeAssets.length - coveredAssets.length,
      recommendation: 'Install a supported sensor, SDK, edge route, or connector for uncovered assets.',
    });
  if (importantFindings.length)
    lessons.push({
      type: 'finding-backlog',
      count: importantFindings.length,
      recommendation: 'Prioritize open high and critical findings.',
    });
  if (failedJobs.length)
    lessons.push({
      type: 'automation-failure',
      count: failedJobs.length,
      recommendation: 'Repair failed security automation before relying on the next cycle.',
    });

  const coverageRatio = activeAssets.length ? coveredAssets.length / activeAssets.length : 0;
  const enforcementRatio = routes.length
    ? routes.filter((route) => route.mode === 'enforce').length / routes.length
    : 0;
  const responseRatio = recent.length
    ? recent.filter((event) => ['contained', 'closed'].includes(event.status)).length / recent.length
    : 1;
  const backlogPenalty = Math.min(20, importantFindings.length * 3 + openEvents.length);
  const postureScore = activeAssets.length
    ? Math.max(
        0,
        Math.min(100, Math.round(coverageRatio * 45 + enforcementRatio * 20 + responseRatio * 35 - backlogPenalty)),
      )
    : 0;

  return {
    window: { from: new Date(now - DAY_MS).toISOString(), to: new Date(now).toISOString() },
    snapshot: {
      postureScore,
      assets: {
        total: activeAssets.length,
        covered: coveredAssets.length,
        uncovered: activeAssets.length - coveredAssets.length,
      },
      detections: {
        observed: recent.length,
        blocked: blocked.length,
        open: openEvents.length,
        falsePositives: falsePositives.length,
      },
      findings: { open: openFindings.length, highOrCritical: importantFindings.length },
      automation: { failedJobs: failedJobs.length },
      routes: { total: routes.length, enforcing: routes.filter((route) => route.mode === 'enforce').length },
    },
    learning: {
      model: 'bounded-outcome-learning-v1',
      classes,
      lessons,
      changesEnforcementAutomatically: false,
    },
    actions: {
      attacksAlreadyBlocked: blocked.length,
      escalations: classes
        .filter((row) => row.unresolved && (row.priority >= 10 || row.recurring))
        .map((row) => row.name),
      recommendations: lessons.map((lesson) => lesson.recommendation),
    },
  };
}

export function nextDefenseRun(now = Date.now(), cadenceHours = 24) {
  return now + Math.max(1, Math.min(168, Number(cadenceHours || 24))) * 3_600_000;
}
