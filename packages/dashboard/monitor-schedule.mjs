// Scheduling helpers for continuous monitoring — pure, so they're unit-testable. A monitor is DUE when
// it is enabled and its interval has elapsed since its last run (or it has never run). The scheduler
// runs the agent on each due monitor, diffs against the previous run, and alerts on NEW findings.

export function dueMonitors(monitors = [], now = 0) {
  return monitors.filter((m) => {
    if (!m || m.enabled === false) return false;
    const intervalMs = Math.max(1, Number(m.intervalHours) || 24) * 3_600_000;
    const last = Number(m.lastRunAt) || 0;
    return now - last >= intervalMs;
  });
}

// Map a run diff (from agent-history.diffRuns) into the `delta` shape monitor.sendMonitorAlert expects:
// it alerts only when there are NEW findings and it is not the first run.
export function diffToDelta(diff = {}, { firstRun = false, previousScanAt = null } = {}) {
  return {
    firstRun,
    previousScanAt,
    new: (diff.added || []).map((f) => ({ cls: f.cls || f.tool, target: f.target, severity: f.severity })),
    resolved: (diff.removed || []).map((f) => ({ cls: f.cls || f.tool, target: f.target, severity: f.severity })),
  };
}
