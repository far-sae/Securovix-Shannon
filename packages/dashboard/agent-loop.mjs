// The autonomous AGENT LOOP: understand → decide → act → report. It turns the deterministic
// understanding (analyzeSurface) into concrete proof-based probe tasks, RUNS them against the
// discovered vectors, and returns the confirmed (zero-FP) findings plus a narrated step timeline —
// so the AI Agent page *acts* instead of only planning.
//
// `probe(key, target)` is injected (real wiring = PROBERS[key].probe(target) from the engine), so the
// loop's decision/aggregation logic is unit-testable with fake probers. Every finding is still gated by
// the engine's benign proof marker — the agent decides WHAT to run, the engine decides what's REAL.
import { analyzeSurface } from './agent-understand.mjs';

// Probers keyed by how the engine invokes them: URL-string targets vs form descriptors vs origin-level.
const GET_PROBES = ['sqli', 'xss', 'ssrf', 'nosql', 'crlf', 'open-redirect'];
const FORM_PROBES = ['csrf', 'mass-assignment', 'auth-testing'];
const ORIGIN_PROBES = ['security-headers', 'secrets-exposure', 'cors-misconfig'];
const API_PROBES = ['api-data-exposure'];

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
    const id = `${key}|${typeof target === 'string' ? target : target.url}`;
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

export async function runAgentLoop({ surface, probe, maxTasks = 30, onStep } = {}) {
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

  const tasks = buildProbeTasks(surface, { maxTasks });
  emit(
    'act',
    `Running ${tasks.length} proof-based probe${tasks.length === 1 ? '' : 's'} against the discovered vectors…`,
  );

  const findings = [];
  for (const task of tasks) {
    let res = [];
    try {
      res = (await probe(task.key, task.target)) || [];
    } catch {
      res = [];
    }
    if (res.length) {
      for (const f of res) findings.push({ ...f, cls: task.key });
      emit(
        'confirm',
        `${task.label} — CONFIRMED (${res.length}): ${String(res[0].detail || res[0].severity || '').slice(0, 160)}`,
      );
    }
  }

  emit(
    'report',
    findings.length
      ? `${findings.length} vulnerabilit${findings.length === 1 ? 'y' : 'ies'} PROVEN — zero false positives (each carries a benign proof).`
      : 'No vulnerabilities confirmed. Every probe abstained — nothing proven, nothing invented.',
  );
  return { understanding, steps, findings, stats: { tasks: tasks.length, confirmed: findings.length } };
}
