// Guard malware sandbox (Phase 2): suspicious files go to a CAPE sandbox, the behaviour report is
// scored, and a malicious verdict blocks the file's hash on every customer's machines.
//
// CAPE (https://github.com/kevoreilly/CAPEv2) is operator-hosted: it needs a KVM host with
// analysis VMs, which cannot run inside the dashboard. Point SHANNON_CAPE_URL (and
// SHANNON_CAPE_TOKEN) at it. CAPE runs YARA itself; its matches arrive in the report.
//
// The verdict is a logistic regression over features of the report. It ships with hand-set
// starting weights (DEFAULT_WEIGHTS); fitWeights() retrains them on your own labelled reports and
// evaluate() reports accuracy, so the ">95% on a test malware set" goal is measured, not assumed.
import { requestJson } from './http.mjs';

export const FEATURES = Object.freeze([
  'malscore',
  'sigHigh',
  'sigMedium',
  'ransomware',
  'injection',
  'persistence',
  'evasion',
  'credentials',
  'network',
  'droppedExecutables',
  'yara',
  'family',
  'payloads',
  'deletesFiles',
  'inhibitsRecovery',
]);

export const DEFAULT_WEIGHTS = Object.freeze({
  bias: -4,
  malscore: 4,
  sigHigh: 2.5,
  sigMedium: 0.8,
  ransomware: 3,
  injection: 1.5,
  persistence: 1,
  evasion: 0.8,
  credentials: 2,
  network: 0.5,
  droppedExecutables: 1,
  yara: 2.5,
  family: 3,
  payloads: 2.5,
  deletesFiles: 1,
  inhibitsRecovery: 3,
});

export const VERDICT_THRESHOLDS = Object.freeze({ malicious: 0.8, suspicious: 0.5 });
const cap = (n) => Math.max(0, Math.min(1, n));
const list = (value) => (Array.isArray(value) ? value : value ? [value] : []);

function signatureText(sig) {
  return `${sig?.name || ''} ${sig?.description || ''} ${list(sig?.categories).join(' ')} ${list(sig?.families).join(' ')}`.toLowerCase();
}

// Report -> numbers between 0 and 1, plus readable reasons. Tolerant of missing sections: CAPE
// reports vary by version and by what the sample did.
export function extractFeatures(report = {}) {
  const sigs = list(report.signatures);
  const text = sigs.map(signatureText).join(' \n ');
  const summary = report.behavior?.summary || {};
  const commands = list(summary.executed_commands).join(' \n ').toLowerCase();
  const network = report.network || {};
  const dropped = list(report.dropped);
  const yaraHits = [...list(report.target?.file?.yara), ...list(report.target?.file?.cape_yara)]
    .map((y) => y?.name || y)
    .filter(Boolean);
  const family = String(
    report.malfamily ||
      report.detections?.family ||
      list(report.detections)
        .map((d) => d?.family || d)
        .find(Boolean) ||
      '',
  ).trim();
  const payloads = list(report.CAPE?.payloads || report.CAPE);
  const has = (re) => (re.test(text) ? 1 : 0);
  const features = {
    malscore: cap(Number(report.malscore || 0) / 10),
    sigHigh: cap(sigs.filter((s) => Number(s.severity) >= 3).length / 3),
    sigMedium: cap(sigs.filter((s) => Number(s.severity) === 2).length / 5),
    ransomware: has(/ransom|encrypts? (?:user )?files|file_encryption|mass_file_modification/),
    injection: has(/inject|process_hollow|hollowing|apc_queue/),
    persistence: has(/persisten|autorun|run_key|create_service|scheduled_task|startup/),
    evasion: has(/antivm|anti_vm|antisandbox|anti_sandbox|antidebug|anti_debug|evasi|stealth/),
    credentials: has(/credential|infostealer|browser_password|lsass|mimikatz|steal/),
    network: cap((list(network.hosts).length + list(network.domains).length) / 10),
    droppedExecutables: cap(
      dropped.filter((d) => /pe32|elf|mach-o|executable|\.exe|\.dll/i.test(`${d?.type || ''} ${d?.name || ''}`))
        .length / 3,
    ),
    yara: cap(yaraHits.length / 2),
    family: family ? 1 : 0,
    payloads: payloads.length ? 1 : 0,
    deletesFiles: cap(list(summary.delete_files).length / 50),
    inhibitsRecovery:
      /vssadmin[^\n]{0,40}delete|wbadmin[^\n]{0,40}delete|bcdedit[^\n]{0,60}recoveryenabled|shadowcopy[^\n]{0,20}delete/.test(
        commands,
      )
        ? 1
        : 0,
  };
  const signatures = sigs
    .filter((s) => Number(s.severity) >= 2)
    .sort((a, b) => Number(b.severity) - Number(a.severity))
    .slice(0, 20)
    .map((s) => ({
      name: String(s.name || ''),
      severity: Number(s.severity) || 0,
      description: String(s.description || '').slice(0, 200),
    }));
  return { features, family: family || null, signatures, yara: yaraHits.slice(0, 20).map(String) };
}

const sigmoid = (z) => 1 / (1 + Math.exp(-z));

export function score(features, weights = DEFAULT_WEIGHTS) {
  let z = weights.bias || 0;
  const contributions = [];
  for (const name of FEATURES) {
    const value = Number(features[name] || 0);
    const part = value * (weights[name] || 0);
    z += part;
    if (part > 0.25) contributions.push([name, part]);
  }
  return { score: sigmoid(z), contributions: contributions.sort((a, b) => b[1] - a[1]) };
}

const REASON = {
  malscore: 'CAPE malscore is high',
  sigHigh: 'several high-severity behaviour signatures',
  sigMedium: 'medium-severity behaviour signatures',
  ransomware: 'ransomware behaviour (mass file encryption)',
  injection: 'injects code into other processes',
  persistence: 'installs itself to run at startup',
  evasion: 'tries to detect or evade the sandbox',
  credentials: 'tries to steal stored credentials',
  network: 'contacts many hosts or domains',
  droppedExecutables: 'drops further executables',
  yara: 'matches YARA malware rules',
  family: 'identified as a known malware family',
  payloads: 'CAPE extracted an unpacked payload',
  deletesFiles: 'deletes many files',
  inhibitsRecovery: 'deletes shadow copies or disables recovery',
};

export function classify(report, weights = DEFAULT_WEIGHTS) {
  const extracted = extractFeatures(report);
  const { score: probability, contributions } = score(extracted.features, weights);
  const verdict =
    probability >= VERDICT_THRESHOLDS.malicious
      ? 'malicious'
      : probability >= VERDICT_THRESHOLDS.suspicious
        ? 'suspicious'
        : 'clean';
  return {
    verdict,
    score: Math.round(probability * 1000) / 1000,
    family: extracted.family,
    reasons: contributions.slice(0, 6).map(([name]) => REASON[name] || name),
    signatures: extracted.signatures,
    yara: extracted.yara,
    features: extracted.features,
  };
}

// Logistic regression by gradient descent with L2 regularization. samples: [{ features, label }]
// where label is 1 (malicious) or 0 (clean). Starts from the given weights.
export function fitWeights(samples, { epochs = 400, rate = 0.5, l2 = 0.001, start = DEFAULT_WEIGHTS } = {}) {
  const w = { ...start };
  const n = samples.length;
  if (!n) return w;
  for (let epoch = 0; epoch < epochs; epoch += 1) {
    const grad = Object.fromEntries(['bias', ...FEATURES].map((k) => [k, 0]));
    for (const { features, label } of samples) {
      const error = score(features, w).score - (label ? 1 : 0);
      grad.bias += error;
      for (const name of FEATURES) grad[name] += error * Number(features[name] || 0);
    }
    w.bias -= (rate * grad.bias) / n;
    for (const name of FEATURES) w[name] -= rate * (grad[name] / n + l2 * w[name]);
  }
  return Object.fromEntries(Object.entries(w).map(([k, v]) => [k, Math.round(v * 1000) / 1000]));
}

export function evaluate(samples, weights = DEFAULT_WEIGHTS, threshold = VERDICT_THRESHOLDS.malicious) {
  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;
  for (const { features, label } of samples) {
    const predicted = score(features, weights).score >= threshold;
    if (predicted && label) tp += 1;
    else if (!predicted && !label) tn += 1;
    else if (predicted) fp += 1;
    else fn += 1;
  }
  const total = samples.length || 1;
  return {
    accuracy: (tp + tn) / total,
    precision: tp + fp ? tp / (tp + fp) : 0,
    recall: tp + fn ? tp / (tp + fn) : 0,
    tp,
    tn,
    fp,
    fn,
  };
}

// ---------- CAPE client ----------

export function capeConfig(env = process.env) {
  const url = String(env.SHANNON_CAPE_URL || '').replace(/\/+$/, '');
  return url
    ? { url, token: String(env.SHANNON_CAPE_TOKEN || ''), timeoutSec: Number(env.SHANNON_CAPE_TIMEOUT_SEC || 180) }
    : null;
}

export function createCapeClient({ config = capeConfig(), fetchImpl = fetch } = {}) {
  const headers = () => (config?.token ? { authorization: `Token ${config.token}` } : {});
  return {
    configured: () => !!config,
    async submit({ bytes, filename }) {
      if (!config) throw new Error('No sandbox is configured (SHANNON_CAPE_URL).');
      const form = new FormData();
      form.append('file', new Blob([bytes]), filename || 'sample.bin');
      form.append('timeout', String(config.timeoutSec));
      const response = await fetchImpl(`${config.url}/apiv2/tasks/create/file/`, {
        method: 'POST',
        headers: headers(),
        body: form,
        signal: AbortSignal.timeout(120_000),
      });
      const json = await response.json().catch(() => null);
      const taskId = json?.data?.task_ids?.[0] ?? json?.task_id ?? null;
      if (!response.ok || json?.error || taskId == null)
        throw new Error(`Sandbox refused the file: ${json?.error_value || json?.message || response.status}`);
      return taskId;
    },
    async status(taskId) {
      const json = await requestJson(fetchImpl, `${config.url}/apiv2/tasks/status/${encodeURIComponent(taskId)}/`, {
        headers: headers(),
      });
      return String(json?.data ?? json?.status ?? 'unknown');
    },
    async report(taskId) {
      const json = await requestJson(fetchImpl, `${config.url}/apiv2/tasks/get/report/${encodeURIComponent(taskId)}/`, {
        headers: headers(),
        timeoutMs: 120_000,
      });
      return json?.data &&
        typeof json.data === 'object' &&
        !Array.isArray(json.data) &&
        (json.data.info || json.data.signatures)
        ? json.data
        : json;
    },
  };
}
