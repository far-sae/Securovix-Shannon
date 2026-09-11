import { buildProbeTasks, runConcurrent, taskId } from './agent-loop.mjs';
// agent-team.mjs — a Multi-Agent Security Team built on a shared BLACKBOARD.
//
// Role-specialized agents (recon · exploit pool · remediation · report) coordinate ONLY through a
// shared, observable board and hand off work autonomously by posting/reacting to typed facts. The
// deterministic engine stays the source of truth (probe/escalate are injected), so the zero-FP
// contract holds across every agent. Pure + dependency-injected → unit-testable with fakes.
//
// See docs/superpowers/specs/2026-09-11-multi-agent-security-team-design.md and
// docs/research/multi-agent-security-team.md.
import { analyzeSurface } from './agent-understand.mjs';

// ── Blackboard ──────────────────────────────────────────────────────────────────────────────────
// Append-only, observable store. Agents talk only through post()/all()/subscribe(); claim() gives a
// single agent exclusive ownership of a task so two exploit agents never run the same probe.
export function makeBlackboard() {
  const entries = [];
  const subs = new Map(); // type -> handler[]
  const claimed = new Set();
  let seq = 0;
  return {
    post(type, data, by = 'system') {
      const e = { id: `${type}-${++seq}`, type, data, by, t: entries.length };
      entries.push(e);
      for (const h of subs.get(type) || []) {
        try {
          h(e);
        } catch {}
      }
      return e;
    },
    all(type) {
      return type ? entries.filter((e) => e.type === type) : entries.slice();
    },
    subscribe(type, handler) {
      if (!subs.has(type)) subs.set(type, []);
      subs.get(type).push(handler);
      return () => {
        const arr = subs.get(type) || [];
        const i = arr.indexOf(handler);
        if (i >= 0) arr.splice(i, 1);
      };
    },
    claim(id, by = 'agent') {
      if (claimed.has(id)) return false;
      claimed.add(id);
      this.post('log', { claimedBy: by, task: id }, by);
      return true;
    },
    snapshot() {
      return entries.slice();
    },
  };
}

// ── Recon agent ─────────────────────────────────────────────────────────────────────────────────
// Understands the crawled surface, posts each target and one prioritized plan (human-readable).
export function reconAgent(bb, { surface } = {}) {
  const understanding = analyzeSurface(surface || {});
  const targets = new Set();
  for (const p of surface?.pages || []) targets.add(p.url);
  if (surface?.origin) targets.add(surface.origin);
  for (const t of targets) bb.post('target', { url: t }, 'recon');
  bb.post('plan', { plan: understanding.plan, traits: understanding.traits, stats: understanding.stats }, 'recon');
  return understanding.plan;
}

// ── Coordinator ─────────────────────────────────────────────────────────────────────────────────
// Turns the surface into concrete, claimable, prober-keyed tasks (reuses the tested buildProbeTasks
// so the task set — including the new llm-* classes — stays in sync with the single-agent loop).
export function coordinatorTasks(bb, { surface, maxTasks = 40 } = {}) {
  const tasks = buildProbeTasks(surface || {}, { maxTasks }).map((t) => ({ ...t, id: taskId(t) }));
  for (const t of tasks) bb.post('task', t, 'coordinator');
  return tasks;
}

// ── Exploit pool ────────────────────────────────────────────────────────────────────────────────
// N exploit agents pull unclaimed tasks, run the real (zero-FP) prober, post confirmed findings, and
// escalate each hit into an impact demonstration. Bounded concurrency via runConcurrent.
export async function runExploitPool(bb, { deps, agents = 4, onEvent } = {}) {
  const tasks = bb.all('task').map((e) => e.data);
  const emit = (e) => onEvent && onEvent(e);
  await runConcurrent(
    tasks,
    async (task, i) => {
      const agent = `exploit-${(i % agents) + 1}`;
      if (!bb.claim(task.id, agent)) return; // another agent already owns it
      let findings = [];
      try {
        findings = (await deps.probe(task.key, task.target)) || [];
      } catch {}
      for (const f of findings) {
        const cls = f.cls || task.key;
        bb.post('finding', { ...f, cls, by: agent }, agent);
        emit({ phase: 'confirm', agent, detail: `[${agent}] confirmed ${cls} on ${urlOf(task.target)}` });
        if (deps.escalate) {
          let impacts = [];
          try {
            impacts = (await deps.escalate(cls, task.target)) || [];
          } catch {}
          for (const im of impacts) {
            bb.post('impact', { ...im, cls: im.cls || 'impact', from: cls, by: agent }, agent);
            emit({ phase: 'escalate', agent, detail: `[${agent}] escalated ${cls} → impact` });
          }
        }
      }
    },
    Math.max(1, agents),
  );
  return bb.all('finding').map((e) => e.data);
}

// ── Remediation agent ───────────────────────────────────────────────────────────────────────────
// Subscribes to findings (here: drains those already on the board) and posts a labeled suggested fix
// per finding via the injected locate + patch. Never applies anything — suggestion only.
export async function remediationAgent(bb, { deps, onEvent } = {}) {
  const fixes = [];
  for (const e of bb.all('finding')) {
    const finding = e.data;
    let candidate = null;
    let patch = null;
    try {
      candidate = deps.locate ? await deps.locate(finding) : null;
      patch = deps.patch ? await deps.patch(finding, candidate) : null;
    } catch {}
    const fix = {
      cls: finding.cls,
      target: finding.target,
      candidate,
      patch,
      label: 'suggested — review before applying',
    };
    bb.post('fix', fix, 'remediation');
    fixes.push(fix);
    if (onEvent) onEvent({ phase: 'remediate', agent: 'remediation', detail: `suggested a fix for ${finding.cls}` });
  }
  return fixes;
}

// ── Report agent ────────────────────────────────────────────────────────────────────────────────
// Aggregates confirmed findings + impacts + suggested fixes (leads stay separate) into one report.
export async function reportAgent(bb, { deps, meta = {} } = {}) {
  const run = {
    findings: bb.all('finding').map((e) => e.data),
    impacts: bb.all('impact').map((e) => e.data),
    fixes: bb.all('fix').map((e) => e.data),
    leads: bb.all('lead').map((e) => e.data),
  };
  let report = { markdown: '', ...run };
  try {
    if (deps.report) report = { ...(await deps.report(run, meta)), ...run };
  } catch {}
  bb.post('report', report, 'report');
  return report;
}

const urlOf = (t) => (typeof t === 'string' ? t : t?.url || '');

// ── Orchestrator ────────────────────────────────────────────────────────────────────────────────
// Wires the whole team hands-off, narrates a timeline, and builds a first-class handoff GRAPH
// (role nodes + edges) so the dashboard can render real role-typed agents with animated handoffs.
export async function runSecurityTeam({ surface, deps, roster = {}, onEvent } = {}) {
  const bb = makeBlackboard();
  const timeline = [];
  const nodes = [];
  const edges = [];
  const addNode = (id, role, label) => {
    if (!nodes.some((n) => n.id === id)) nodes.push({ id, role, label });
  };
  const addEdge = (from, to, type) => edges.push({ from, to, type, t: edges.length });
  const step = (phase, detail, agent) => {
    const s = { phase, detail, agent, t: timeline.length };
    timeline.push(s);
    if (onEvent) onEvent(s);
    return s;
  };
  const exploitAgents = Math.max(1, Math.min(8, roster.exploitAgents || 4));

  addNode('target', 'target', urlOf(surface?.origin) || 'target');

  // 1) Recon
  addNode('recon', 'recon', 'Recon');
  const plan = reconAgent(bb, { surface });
  step('recon', `Recon mapped the surface and proposed ${plan.length} attack area(s).`, 'recon');
  addEdge('recon', 'target', 'recon');

  // 2) Coordinator → tasks
  addNode('coordinator', 'coordinator', 'Coordinator');
  const tasks = coordinatorTasks(bb, { surface });
  step('plan', `Coordinator created ${tasks.length} claimable task(s) for the exploit team.`, 'coordinator');
  addEdge('recon', 'coordinator', 'handoff');
  for (let i = 1; i <= exploitAgents; i++) {
    addNode(`exploit-${i}`, 'exploit', `Exploit ${i}`);
    addEdge('coordinator', `exploit-${i}`, 'dispatch');
  }
  step('act', `Dispatching work across ${exploitAgents} parallel exploit agents.`, 'coordinator');

  // 3) Exploit pool (autonomous claim + probe + escalate)
  const onExploit = (e) => {
    const s = step(e.phase, e.detail, e.agent);
    return s;
  };
  await runExploitPool(bb, { deps, agents: exploitAgents, onEvent: onExploit });
  const findings = bb.all('finding').map((e) => e.data);
  // Handoff edges: each confirming exploit agent hands its finding to remediation.
  addNode('remediation', 'remediation', 'Remediation');
  for (const e of bb.all('finding')) addEdge(e.by || 'exploit-1', 'remediation', 'finding');

  // 4) Remediation (subscribed to findings)
  const fixes = findings.length
    ? await remediationAgent(bb, { deps, onEvent: (e) => step(e.phase, e.detail, e.agent) })
    : [];
  if (fixes.length) step('remediate', `Remediation proposed ${fixes.length} suggested fix(es).`, 'remediation');

  // 5) Report
  addNode('report', 'report', 'Report');
  addEdge('remediation', 'report', 'handoff');
  for (const e of bb.all('finding')) addEdge(e.by || 'exploit-1', 'report', 'finding');
  const report = await reportAgent(bb, { deps });
  step('report', `Report agent consolidated ${findings.length} finding(s) and ${fixes.length} fix(es).`, 'report');

  return {
    findings,
    impacts: bb.all('impact').map((e) => e.data),
    fixes,
    report,
    timeline,
    graph: { nodes, edges },
    blackboard: bb.snapshot(),
    stats: { tasks: tasks.length, confirmed: findings.length, fixes: fixes.length, agents: exploitAgents },
  };
}
