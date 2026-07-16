// The autonomous AGENT LOOP: understand → decide → act → escalate → report, optionally across multiple
// adaptive rounds. It turns the deterministic understanding (analyzeSurface) into concrete proof-based
// probe tasks, RUNS them, ESCALATES each confirmed finding into an impact demonstrator, and returns the
// confirmed (zero-FP) findings plus a narrated step timeline — so the AI Agent page *acts*.
//
// probe(key, target) and escalate(cls, target) are injected (real wiring = the engine's PROBERS + the
// impact demonstrators), so the loop's decision/aggregation/narration logic is unit-testable with fakes.
// The agent decides WHAT to run; the engine decides what's REAL (every finding keeps its benign proof).
import { analyzeSurface } from './agent-understand.mjs';

const GET_PROBES = ['sqli', 'xss', 'ssrf', 'nosql', 'crlf', 'open-redirect'];
const FORM_PROBES = ['csrf', 'mass-assignment', 'auth-testing'];
const ORIGIN_PROBES = ['security-headers', 'secrets-exposure', 'cors-misconfig', 'templates'];
const API_PROBES = ['api-data-exposure'];

const urlOf = (target) => (typeof target === 'string' ? target : target.url);
export const taskId = (t) => `${t.key}|${urlOf(t.target)}`;
const pathOf = (u) => {
  try {
    return new URL(u).pathname;
  } catch {
    return u;
  }
};

// Turn a crawled surface into an ordered, de-duplicated, bounded list of {key, target, label} probe
// tasks. GET URLs (with params) get the injection probers; POST forms get the form probers; a GET form
// is synthesized into a query URL; origin + API paths get the config/exposure probers.
export function buildProbeTasks(surface = {}, { maxTasks = 30, maxPer = 6 } = {}) {
  const pages = surface.pages || [];
  const forms = surface.forms || [];
  const apis = surface.apiPaths || [];
  const origin = surface.origin;
  const tasks = [];
  const seen = new Set();
  const add = (key, target, label) => {
    const id = `${key}|${urlOf(target)}`;
    if (seen.has(id) || tasks.length >= maxTasks) return;
    seen.add(id);
    tasks.push({ key, target, label });
  };

  const getUrls = pages
    .map((p) => p.url)
    .filter((u) => {
      try {
        return new URL(u).search.length > 1;
      } catch {
        return false;
      }
    })
    .slice(0, maxPer);
  for (const u of getUrls) for (const k of GET_PROBES) add(k, u, `${k} · ${pathOf(u)}`);

  for (const f of forms.slice(0, maxPer)) {
    if ((f.method || 'get').toLowerCase() === 'post') {
      const desc = { url: f.url, method: 'post', params: f.params || [] };
      for (const k of FORM_PROBES) add(k, desc, `${k} · ${pathOf(f.url)}`);
    } else {
      let u = f.url;
      try {
        const uu = new URL(f.url);
        for (const p of f.params || []) uu.searchParams.set(p, '1');
        u = uu.toString();
      } catch {}
      for (const k of ['sqli', 'xss', 'ssrf']) add(k, u, `${k} · ${pathOf(f.url)}`);
    }
  }

  if (origin) for (const k of ORIGIN_PROBES) add(k, origin, `${k} · /`);
  for (const p of apis.slice(0, maxPer)) {
    const u = origin ? origin.replace(/\/$/, '') + p : p;
    for (const k of API_PROBES) add(k, u, `${k} · ${p}`);
  }
  return tasks.slice(0, maxTasks);
}

// One pass over a surface: run each (not-yet-tested) probe task; on a confirmed finding, escalate it
// into an impact demonstrator. Returns findings (probe + impact), the narrated steps, and testedIds
// (so a campaign can dedupe across rounds).
export async function runAgentLoop({ surface, probe, escalate, skip, maxTasks = 30, onStep } = {}) {
  const understanding = analyzeSurface(surface);
  const steps = [];
  const emit = (phase, detail) => {
    const s = { phase, detail, t: steps.length };
    steps.push(s);
    if (onStep) onStep(s);
    return s;
  };
  const st = understanding.stats;
  emit(
    'understand',
    `Mapped the surface: ${st.pages} pages · ${st.params} params · ${st.forms} forms · ${st.apis} APIs.`,
  );
  emit(
    'plan',
    `Prioritized ${understanding.plan.length} test categor${understanding.plan.length === 1 ? 'y' : 'ies'}${understanding.traits.length ? ` — this target ${understanding.traits.join(', ')}` : ''}.`,
  );

  const tasks = buildProbeTasks(surface, { maxTasks }).filter((t) => !(skip && skip.has(taskId(t))));
  emit(
    'act',
    `Running ${tasks.length} proof-based probe${tasks.length === 1 ? '' : 's'} against the discovered vectors…`,
  );

  const findings = [];
  const testedIds = [];
  for (const task of tasks) {
    testedIds.push(taskId(task));
    let res = [];
    try {
      res = (await probe(task.key, task.target)) || [];
    } catch {
      res = [];
    }
    if (!res.length) continue;
    for (const f of res) findings.push({ ...f, cls: task.key });
    emit(
      'confirm',
      `${task.label} — CONFIRMED (${res.length}): ${String(res[0].detail || res[0].severity || '').slice(0, 160)}`,
    );

    // ESCALATE: chain the confirmed finding into a benign, read-only impact demonstrator.
    if (escalate) {
      let imp = null;
      try {
        imp = await escalate(task.key, task.target);
      } catch {
        imp = null;
      }
      if (imp) {
        findings.push({ ...imp, cls: imp.tool || `impact:${task.key}`, impact: true });
        emit('escalate', `↳ impact proven: ${String(imp.detail || '').slice(0, 200)}`);
        if (imp.session) findings[findings.length - 1].session = imp.session;
      }
    }
  }

  emit(
    'report',
    findings.length
      ? `${findings.length} finding${findings.length === 1 ? '' : 's'} PROVEN — zero false positives (each carries a benign proof).`
      : 'No vulnerabilities confirmed. Every probe abstained — nothing proven, nothing invented.',
  );
  return { understanding, steps, findings, stats: { tasks: tasks.length, confirmed: findings.length }, testedIds };
}

// Multi-round adaptive campaign. Each round runs the loop; between rounds it RE-CRAWLS (deeper, or as a
// newly-obtained identity if a finding yields a session) and continues only while a fresh, untested
// task exists — so rounds never spin on nothing (loop-until-dry). Dedupes tasks across all rounds.
export async function runAgentCampaign({
  surface,
  probe,
  escalate,
  recrawl,
  maxRounds = 3,
  maxTasks = 30,
  onStep,
} = {}) {
  const tested = new Set();
  const steps = [];
  const findings = [];
  const push = (s) => {
    steps.push(s);
    if (onStep) onStep(s);
  };
  let cur = surface;
  let rounds = 0;
  let adoptedIdentity = null;
  for (let round = 1; round <= maxRounds; round++) {
    rounds = round;
    push({
      phase: 'round',
      detail: `Round ${round}${adoptedIdentity ? ' — re-crawling as a newly-obtained identity' : round > 1 ? ' — deeper crawl' : ''} · ${(cur.pages || []).length} pages in scope.`,
      t: steps.length,
    });
    // Run the loop without re-emitting its steps through onStep twice: pass onStep so streaming works,
    // and collect its steps/findings into the campaign aggregate.
    const r = await runAgentLoop({ surface: cur, probe, escalate, skip: tested, maxTasks, onStep });
    for (const s of r.steps) steps.push(s);
    for (const f of r.findings) findings.push({ ...f, round });
    for (const id of r.testedIds) tested.add(id);

    if (round >= maxRounds || !recrawl) break;
    const nextIdentity = r.findings.map((f) => f.session).find(Boolean) || null;
    let next = null;
    try {
      next = await recrawl({ round: round + 1, identity: nextIdentity, prevSurface: cur });
    } catch {
      next = null;
    }
    if (!next) break;
    const fresh = buildProbeTasks(next, { maxTasks }).some((t) => !tested.has(taskId(t)));
    if (!fresh) break; // nothing new to test → stop rather than spin
    cur = next;
    adoptedIdentity = nextIdentity;
  }
  return { steps, findings, stats: { rounds, confirmed: findings.length, tested: tested.size } };
}
