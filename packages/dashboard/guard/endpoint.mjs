// Guard endpoint service (Phase 2): the server side of the Guard agent.
//
// Enrollment: an owner/admin creates an enrollment token (shown once); the agent trades it for
// its own credential (svxa_<agentId>.<secret>, stored as a hash). Check-in: every few seconds
// the agent reports health and collects queued commands, policy changes and new malicious hashes.
// Events: batches go through endpoint detection; alerts join Guard incidents like any other.
// Results: the agent confirms each command, which completes the Guard action and re-checks
// containment. Samples: files go to the CAPE sandbox; a malicious verdict is shared as a hash with
// every customer (hash, family and verdict only — never the file name or who submitted it).
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { ACTIONS } from './catalog.mjs';
import {
  ENDPOINT_DEFAULTS,
  detectEndpoint,
  emptyHostState,
  expectsOnline,
  staleAgentAlerts,
  stoppedAgentAlert,
} from './endpoint-detect.mjs';
import { classify } from './sandbox.mjs';

const MIN = 60_000;
const HOUR = 60 * MIN;
const EVENT_TYPES = new Set([
  'process.start',
  'file.write',
  'file.rename',
  'file.delete',
  'canary.touched',
  'ransomware.detected',
  'persistence.created',
  'lsass.access',
  'logon',
  'agent.tamper',
  'agent.offline',
  'malware.blocked',
  'net.connect',
]);
export const MAX_SAMPLE_BYTES = 32 * 1024 * 1024;
const COMMAND_TTL = 24 * HOUR;
const SIGNER_STATES = new Set(['valid', 'invalid', 'unsigned', 'unknown']);

export function defaultPolicy({ sandbox = false } = {}) {
  return {
    version: 1,
    pollSeconds: 10,
    flushSeconds: 5,
    watchUserFolders: true,
    extraWatch: [],
    canaries: true,
    ransomware: { autoKill: true, renameBurst: 20, entropyBurst: 30, windowSeconds: 30, highEntropy: 7.5 },
    quarantineKnownMalware: true,
    autoSubmitExecutables: sandbox,
    useSysmon: true,
  };
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sameHash = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};
const str = (value, max = 500) => (value == null ? null : String(value).slice(0, max));
const secret = () => randomUUID().replaceAll('-', '') + randomUUID().replaceAll('-', '');

export function parseAgentToken(header) {
  const m = /^(?:Bearer\s+)?svxa_(gag_[a-f0-9]{20})\.([a-f0-9]{64})$/.exec(String(header || '').trim());
  return m ? { agentId: m[1], secret: m[2] } : null;
}
export function parseEnrollToken(token) {
  const m = /^svxe_([A-Za-z0-9_-]{1,80})\.([a-f0-9]{64})$/.exec(String(token || '').trim());
  return m ? { orgId: m[1], secret: m[2] } : null;
}

// A small JSON object from the agent, strings capped at 500 characters; anything larger is
// replaced by a marker rather than cut mid-way (which would not parse).
function boundedObject(value, maxChars) {
  if (!value || typeof value !== 'object') return undefined;
  const text = JSON.stringify(value, (_k, v) => (typeof v === 'string' ? v.slice(0, 500) : v));
  return text.length <= maxChars ? JSON.parse(text) : { truncated: true };
}

// Agent events are untrusted input: keep known types and known fields, cap every string.
export function sanitizeEvents(agent, events, now = Date.now()) {
  const out = [];
  for (const raw of (Array.isArray(events) ? events : []).slice(0, 1000)) {
    if (!raw || !EVENT_TYPES.has(raw.type)) continue;
    const at = Number(raw.at);
    const p = raw.process || {};
    out.push({
      id: `${agent.id}:${str(raw.id, 80) || randomUUID()}`,
      type: raw.type,
      at: Number.isFinite(at) && at > now - 7 * 24 * HOUR && at < now + 10 * MIN ? at : now,
      host: { id: agent.id, name: agent.hostname, os: agent.os },
      user: str(raw.user, 200),
      process: raw.process
        ? {
            pid: Number.isFinite(Number(p.pid)) ? Number(p.pid) : null,
            ppid: Number.isFinite(Number(p.ppid)) ? Number(p.ppid) : null,
            name: str(p.name, 260),
            path: str(p.path, 1024),
            cmdline: str(p.cmdline, 32_768),
            user: str(p.user, 200),
            sha256: /^[a-f0-9]{64}$/i.test(p.sha256 || '') ? p.sha256.toLowerCase() : null,
            parents: (Array.isArray(p.parents) ? p.parents : [])
              .slice(0, 8)
              .map((x) => ({ name: str(x?.name ?? x, 260), pid: Number(x?.pid) || null })),
          }
        : undefined,
      file: raw.file
        ? {
            path: str(raw.file.path, 1024),
            oldPath: str(raw.file.oldPath, 1024),
            sha256: /^[a-f0-9]{64}$/i.test(raw.file.sha256 || '') ? raw.file.sha256.toLowerCase() : null,
            entropy: Number.isFinite(Number(raw.file.entropy)) ? Number(raw.file.entropy) : null,
          }
        : undefined,
      persistence: raw.persistence
        ? {
            kind: str(raw.persistence.kind, 40),
            name: str(raw.persistence.name, 260),
            command: str(raw.persistence.command, 4096),
            path: str(raw.persistence.path, 1024),
            // Who signed the program (Windows) or which package owns the file (Linux), when the
            // agent could tell. 'resolved' is where a Store app shortcut really points.
            signer: SIGNER_STATES.has(raw.persistence.signer?.status)
              ? { status: raw.persistence.signer.status, subject: str(raw.persistence.signer.subject, 200) }
              : undefined,
            resolved: str(raw.persistence.resolved, 1024) || undefined,
            packageOwner: str(raw.persistence.packageOwner, 120) || undefined,
          }
        : undefined,
      logon: raw.logon
        ? { type: str(raw.logon.type, 20), source: str(raw.logon.source, 64), user: str(raw.logon.user, 200) }
        : undefined,
      detail: boundedObject(raw.detail, 4000),
    });
  }
  return out;
}

export function publicAgent(agent, now = Date.now()) {
  const { secretHash, ...rest } = agent;
  const online = !!agent.lastSeenAt && now - agent.lastSeenAt < 2 * MIN;
  return { ...rest, online };
}

export function createEndpointService({ store, engine, cape, now = () => Date.now(), publicUrl = () => '' }) {
  const locks = new Map();
  let hashCache = { at: 0, map: new Map(), version: 0, list: [] };

  function withLock(key, fn) {
    const previous = locks.get(key) || Promise.resolve();
    const next = previous.catch(() => {}).then(fn);
    const tail = next.catch(() => {});
    locks.set(key, tail);
    tail.then(() => {
      if (locks.get(key) === tail) locks.delete(key);
    });
    return next;
  }

  async function endpointRecord(orgId) {
    const saved = await store.endpoint.get(orgId);
    return {
      id: orgId,
      orgId,
      enrollHash: saved?.enrollHash || null,
      enrollHint: saved?.enrollHint || null,
      enrollCreatedAt: saved?.enrollCreatedAt || null,
      policy: { ...defaultPolicy({ sandbox: cape.configured() }), ...(saved?.policy || {}) },
      hosts: saved?.hosts || {},
      org: saved?.org || { rdp: [] },
      updatedAt: saved?.updatedAt || now(),
    };
  }

  async function knownHashes(force = false) {
    if (!force && now() - hashCache.at < MIN) return hashCache;
    const rows = await store.hashes.list({}, { orderBy: 'addedAt', limit: 500 });
    hashCache = {
      at: now(),
      map: new Map(
        rows
          .filter((r) => r.verdict === 'malicious')
          .map((r) => [r.id, { family: r.family, source: r.source || 'Securovix sandbox' }]),
      ),
      list: rows.filter((r) => r.verdict === 'malicious').map((r) => r.id),
      version: rows.reduce((m, r) => Math.max(m, r.addedAt || 0), 0),
    };
    return hashCache;
  }

  // ----- enrollment and authentication -----

  async function createEnrollToken(orgId) {
    const raw = secret();
    const token = `svxe_${orgId}.${raw}`;
    const record = await endpointRecord(orgId);
    await store.endpoint.save({
      ...record,
      enrollHash: sha256(raw),
      enrollHint: `svxe_…${raw.slice(-6)}`,
      enrollCreatedAt: now(),
      updatedAt: now(),
    });
    return token;
  }

  async function enroll(body = {}, ip = null) {
    const parsed = parseEnrollToken(body.token);
    if (!parsed) throw Object.assign(new Error('Enrollment token is missing or malformed.'), { status: 401 });
    const record = await store.endpoint.get(parsed.orgId);
    if (!record?.enrollHash || !sameHash(record.enrollHash, sha256(parsed.secret)))
      throw Object.assign(new Error('Enrollment token is not valid. Create a new one on the Guard page.'), {
        status: 401,
      });
    const machineId = str(body.machineId, 128) || null;
    const existing = machineId
      ? (await store.agents.list({ orgId: parsed.orgId }, { limit: 500 })).find(
          (a) => a.machineId === machineId && a.status !== 'retired',
        )
      : null;
    if (!existing && (await store.agents.list({ orgId: parsed.orgId, status: 'active' }, { limit: 500 })).length >= 500)
      throw Object.assign(new Error('This organization already has 500 agents.'), { status: 409 });
    const raw = secret().slice(0, 64);
    const agent = {
      ...(existing || {}),
      id: existing?.id || `gag_${randomUUID().replaceAll('-', '').slice(0, 20)}`,
      orgId: parsed.orgId,
      hostname: str(body.hostname, 128) || 'unknown',
      os: str(body.os, 40) || 'unknown',
      osVersion: str(body.osVersion, 120),
      arch: str(body.arch, 20),
      version: str(body.version, 40),
      machineId,
      secretHash: sha256(raw),
      status: 'active',
      isolated: existing?.isolated || false,
      lastSeenAt: now(),
      lastIp: ip,
      enrolledAt: existing?.enrolledAt || now(),
      stats: existing?.stats || {},
      tamperAlertedAt: null,
      updatedAt: now(),
    };
    await store.agents.save(agent);
    const current = await endpointRecord(parsed.orgId);
    // A reinstall explains a stop that was waiting to be reported.
    if (existing && current.hosts[agent.id]?.pendingStop)
      await withLock(parsed.orgId, async () => {
        const fresh = await endpointRecord(parsed.orgId);
        if (fresh.hosts[agent.id]) fresh.hosts[agent.id].pendingStop = undefined;
        await store.endpoint.save({ ...fresh, updatedAt: now() });
      });
    return { agentId: agent.id, token: `svxa_${agent.id}.${raw}`, policy: current.policy };
  }

  async function authenticate(header) {
    const parsed = parseAgentToken(header);
    if (!parsed) return null;
    const agent = await store.agents.get(parsed.agentId);
    if (!agent || agent.status !== 'active' || !sameHash(agent.secretHash, sha256(parsed.secret))) return null;
    return agent;
  }

  // ----- check-in, events, results -----

  async function checkIn(agent, body = {}, ip = null) {
    const wasStale = !!agent.tamperAlertedAt;
    const updated = {
      ...agent,
      lastSeenAt: now(),
      lastIp: ip || agent.lastIp,
      version: str(body.version, 40) || agent.version,
      isolated: typeof body.isolated === 'boolean' ? body.isolated : agent.isolated,
      stats:
        body.stats && typeof body.stats === 'object'
          ? {
              cpuPercent: Number(body.stats.cpuPercent) || 0,
              memoryMb: Number(body.stats.memoryMb) || 0,
              queued: Number(body.stats.queued) || 0,
              sysmon: !!body.stats.sysmon,
              watched: Number(body.stats.watched) || 0,
            }
          : agent.stats,
      tamperAlertedAt: null,
      updatedAt: now(),
    };
    await store.agents.save(updated);
    const queued = (
      await store.commands.list({ orgId: agent.orgId, agentId: agent.id }, { orderBy: 'createdAt', limit: 100 })
    ).filter((c) => c.status === 'queued' || (c.status === 'sent' && now() - c.sentAt > 2 * MIN));
    for (const command of queued) await store.commands.save({ ...command, status: 'sent', sentAt: now() });
    const record = await endpointRecord(agent.orgId);
    if (record.hosts[agent.id]?.pendingStop) await settleStop(updated, body);
    const hashes = await knownHashes();
    return {
      serverTime: now(),
      backOnline: wasStale,
      commands: queued
        .sort((a, b) => a.createdAt - b.createdAt)
        .map((c) => ({ id: c.id, type: c.type, params: c.params, undoData: c.undoData || null })),
      policy: Number(body.policyVersion) === record.policy.version ? undefined : record.policy,
      hashes: Number(body.hashVersion) === hashes.version ? undefined : { version: hashes.version, list: hashes.list },
    };
  }

  // The Guard service was stopped by hand and the agent is talking again. A new version or a
  // reinstall explains it; the same agent coming back unchanged means someone switched Guard off
  // for a while, which is worth knowing even though it is running again.
  async function settleStop(agent, body = {}) {
    const alert = await withLock(agent.orgId, async () => {
      const record = await endpointRecord(agent.orgId);
      const pending = record.hosts[agent.id]?.pendingStop;
      if (!pending) return null;
      const startedAt = Number(body.startedAt);
      // The stopping agent can still send one last check-in: only a process that started after
      // the stop (or, for agents that do not say, a check-in a few seconds later) is "back".
      const back = Number.isFinite(startedAt) && startedAt > 0 ? startedAt > pending.at : now() - pending.at > 5000;
      if (!back) return null;
      record.hosts[agent.id].pendingStop = undefined;
      await store.endpoint.save({ ...record, updatedAt: now() });
      const sameVersion = (str(body.version, 40) || agent.version) === pending.version;
      return sameVersion && !pending.reported
        ? stoppedAgentAlert(agent, pending, { orgId: agent.orgId, now: now(), back: true })
        : null;
    });
    if (alert) await engine.ingestAlerts(agent.orgId, [alert]);
  }

  async function ingest(agent, events) {
    const clean = sanitizeEvents(agent, events, now());
    if (!clean.length) return { accepted: 0, alerts: 0 };
    const alerts = await withLock(agent.orgId, async () => {
      const record = await endpointRecord(agent.orgId);
      const hashes = await knownHashes();
      const result = detectEndpoint(clean, {
        orgId: agent.orgId,
        hosts: record.hosts,
        org: record.org,
        hashes: hashes.map,
        allow: record.policy.allow || [],
      });
      for (const host of Object.values(result.hosts))
        if (host.seen?.length > 500) host.seen.splice(0, host.seen.length - 500);
      const mine = result.hosts[agent.id];
      if (mine?.pendingStop && !mine.pendingStop.version) mine.pendingStop.version = agent.version || null;
      await store.endpoint.save({ ...record, hosts: result.hosts, org: result.org, updatedAt: now() });
      return result.alerts;
    });
    let processed = { incidents: 0, created: 0 };
    if (alerts.length) processed = await engine.ingestAlerts(agent.orgId, alerts);
    return { accepted: clean.length, alerts: alerts.length, incidents: processed.incidents };
  }

  async function queueCommand(orgId, { agentId, type, params, actionId = null, undoData = null, actor = null }) {
    const agent = await store.agents.get(String(agentId || ''));
    if (!agent || agent.orgId !== orgId || agent.status !== 'active')
      throw Object.assign(new Error('That machine is not enrolled (or was retired).'), {
        status: 400,
        userError: true,
      });
    const command = {
      id: `gcm_${randomUUID().replaceAll('-', '').slice(0, 20)}`,
      orgId,
      agentId: agent.id,
      type,
      params,
      undoData,
      actionId,
      status: 'queued',
      detail: null,
      result: null,
      actor,
      createdAt: now(),
      sentAt: null,
      completedAt: null,
    };
    await store.commands.save(command);
    return { ...command, hostname: agent.hostname };
  }

  async function commandResult(agent, body = {}) {
    const command = await store.commands.get(String(body.commandId || ''));
    if (!command || command.agentId !== agent.id) throw Object.assign(new Error('Unknown command.'), { status: 404 });
    if (command.status === 'done' || command.status === 'failed') return { duplicate: true };
    const ok = body.ok === true;
    const data = boundedObject(body.data, 20_000) || null;
    await store.commands.save({
      ...command,
      status: ok ? 'done' : 'failed',
      detail: str(body.detail, 500),
      result: data,
      completedAt: now(),
    });
    if (ok && (command.type === 'isolate-host' || command.type === 'release-host'))
      await store.agents.save({
        ...(await store.agents.get(agent.id)),
        isolated: command.type === 'isolate-host',
        updatedAt: now(),
      });
    await engine.completeCommand(agent.orgId, command, { ok, detail: body.detail, data });
    return { ok: true };
  }

  // ----- sandbox -----

  async function uploadSample(agent, { bytes, filename, claimedSha, commandId }) {
    if (!bytes?.length) throw Object.assign(new Error('Empty file.'), { status: 400 });
    if (bytes.length > MAX_SAMPLE_BYTES) throw Object.assign(new Error('File is larger than 32 MB.'), { status: 413 });
    const digest = sha256(bytes);
    if (claimedSha && claimedSha.toLowerCase() !== digest)
      throw Object.assign(new Error('The file does not match its SHA-256.'), { status: 400 });
    const base = {
      id: `gsm_${randomUUID().replaceAll('-', '').slice(0, 20)}`,
      orgId: agent.orgId,
      agentId: agent.id,
      hostname: agent.hostname,
      sha256: digest,
      filename: str(filename, 260),
      size: bytes.length,
      commandId: commandId || null,
      taskId: null,
      verdict: null,
      score: null,
      family: null,
      reasons: [],
      signatures: [],
      error: null,
      createdAt: now(),
      updatedAt: now(),
    };
    const known = await store.hashes.get(digest);
    let sample;
    if (known)
      sample = {
        ...base,
        status: 'done',
        verdict: known.verdict,
        score: known.score,
        family: known.family,
        reasons: ['already analysed (known hash)'],
      };
    else if (!cape.configured())
      sample = {
        ...base,
        status: 'skipped',
        error: 'No sandbox is configured. The hash was recorded; set SHANNON_CAPE_URL to analyse files.',
      };
    else {
      try {
        sample = { ...base, status: 'analyzing', taskId: String(await cape.submit({ bytes, filename })) };
      } catch (error) {
        sample = { ...base, status: 'failed', error: str(error.message, 500) };
      }
    }
    await store.samples.save(sample);
    if (sample.verdict === 'malicious') await raiseSampleAlert(sample);
    return sample;
  }

  async function raiseSampleAlert(sample) {
    const hashes = new Map([[sample.sha256, { family: sample.family, source: 'Securovix sandbox' }]]);
    const event = {
      id: `sample:${sample.id}`,
      type: 'file.write',
      at: now(),
      host: { id: sample.agentId, name: sample.hostname },
      file: { path: sample.filename, sha256: sample.sha256 },
    };
    const { alerts } = detectEndpoint([event], { orgId: sample.orgId, hashes });
    if (alerts.length) await engine.ingestAlerts(sample.orgId, alerts);
  }

  async function pollSamples() {
    if (!cape.configured()) return 0;
    const pending = await store.samples.list({ status: 'analyzing' }, { orderBy: 'createdAt', limit: 50 });
    let finished = 0;
    for (const sample of pending) {
      try {
        if (now() - sample.createdAt > 60 * MIN) {
          await store.samples.save({
            ...sample,
            status: 'failed',
            error: 'The sandbox did not finish within an hour.',
            updatedAt: now(),
          });
          continue;
        }
        const status = await cape.status(sample.taskId);
        if (/fail/i.test(status)) {
          await store.samples.save({
            ...sample,
            status: 'failed',
            error: `Sandbox status: ${status}`,
            updatedAt: now(),
          });
          continue;
        }
        if (status !== 'reported') continue;
        const verdict = classify(await cape.report(sample.taskId));
        const done = {
          ...sample,
          status: 'done',
          verdict: verdict.verdict,
          score: verdict.score,
          family: verdict.family,
          reasons: verdict.reasons,
          signatures: verdict.signatures.slice(0, 10),
          updatedAt: now(),
        };
        await store.samples.save(done);
        finished += 1;
        if (verdict.verdict === 'malicious') {
          await store.hashes.save({
            id: sample.sha256,
            verdict: 'malicious',
            score: verdict.score,
            family: verdict.family,
            source: 'Securovix sandbox',
            addedAt: now(),
          });
          await knownHashes(true);
          await raiseSampleAlert(done);
        }
      } catch (error) {
        await store.samples.save({ ...sample, error: str(error.message, 500), updatedAt: now() });
      }
    }
    return finished;
  }

  // ----- housekeeping, run with the Guard cycle -----

  async function cycle() {
    const agents = await store.agents.list({ status: 'active' }, { orderBy: 'lastSeenAt', limit: 500 });
    const byOrg = new Map();
    for (const agent of agents) byOrg.set(agent.orgId, [...(byOrg.get(agent.orgId) || []), agent]);
    let stale = 0;
    for (const [orgId, list] of byOrg) {
      const record = await endpointRecord(orgId);
      const alerts = staleAgentAlerts(list, {
        orgId,
        now: now(),
        hosts: record.hosts,
        expectOnline: record.policy.expectOnline || {},
      });
      for (const alert of alerts) {
        const agent = list.find((a) => a.id === alert.host.id);
        if (agent) await store.agents.save({ ...agent, tamperAlertedAt: now(), updatedAt: now() });
      }
      // A Guard service that was stopped by hand and has stayed down.
      const stopped = await withLock(orgId, async () => {
        const fresh = await endpointRecord(orgId);
        const out = [];
        for (const agent of list) {
          const pending = fresh.hosts[agent.id]?.pendingStop;
          if (!pending || pending.reported || now() - pending.at < ENDPOINT_DEFAULTS.stopGrace) continue;
          pending.reported = true;
          out.push(stoppedAgentAlert(agent, pending, { orgId, now: now() }));
        }
        if (out.length) await store.endpoint.save({ ...fresh, updatedAt: now() });
        return out;
      });
      const all = [...alerts, ...stopped];
      if (!all.length) continue;
      stale += all.length;
      await engine.ingestAlerts(orgId, all);
    }
    let expired = 0;
    for (const command of await store.commands.list({ status: 'queued' }, { orderBy: 'createdAt', limit: 500 })) {
      if (now() - command.createdAt < COMMAND_TTL) continue;
      expired += 1;
      await store.commands.save({
        ...command,
        status: 'failed',
        detail: 'The machine did not check in within 24 hours.',
        completedAt: now(),
      });
      await engine.completeCommand(command.orgId, command, {
        ok: false,
        detail: 'The machine did not check in within 24 hours.',
      });
    }
    const samples = await pollSamples();
    return { stale, expired, samples };
  }

  // ----- dashboard -----

  async function overview(orgId) {
    const [record, agents, samples] = await Promise.all([
      endpointRecord(orgId),
      store.agents.list({ orgId }, { orderBy: 'lastSeenAt', limit: 500 }),
      store.samples.list({ orgId }, { limit: 50 }),
    ]);
    const hashes = await knownHashes();
    return {
      agents: agents
        .filter((a) => a.status !== 'retired')
        .map((a) => {
          const said = record.hosts[a.id]?.offline;
          const view = publicAgent(a, now());
          return {
            ...view,
            expectOnline: expectsOnline(a, record.policy.expectOnline),
            offlineReason: !view.online && said && said.at >= (a.lastSeenAt || 0) - 2 * MIN ? said.reason : null,
          };
        }),
      enrollment: { hint: record.enrollHint, createdAt: record.enrollCreatedAt },
      policy: record.policy,
      expected: [...(record.org.trusted || [])].sort((a, b) => b.at - a.at),
      samples,
      sandbox: { configured: cape.configured(), knownMaliciousHashes: hashes.list.length },
      server: publicUrl(),
    };
  }

  async function savePolicy(orgId, patch) {
    const record = await endpointRecord(orgId);
    const policy = {
      ...record.policy,
      ...patch,
      ransomware: { ...record.policy.ransomware, ...(patch.ransomware || {}) },
      version: record.policy.version + 1,
    };
    await store.endpoint.save({ ...record, policy, updatedAt: now() });
    return policy;
  }

  // Commands and files the organization marked as expected, by fingerprint. Detection skips them
  // from now on, on every machine.
  async function markExpected(orgId, { fp, label, rule }, actor = null) {
    if (!/^(?:cmd|file):[a-f0-9]{16}$/.test(String(fp || '')))
      throw Object.assign(new Error('This kind of alert cannot be marked as expected.'), {
        status: 400,
        userError: true,
      });
    return withLock(orgId, async () => {
      const record = await endpointRecord(orgId);
      const kept = (record.org.trusted || []).filter((t) => t.fp !== fp);
      kept.push({ fp, label: str(label, 300), rule: str(rule, 60), by: actor, at: now() });
      record.org.trusted = kept.slice(-500);
      await store.endpoint.save({ ...record, updatedAt: now() });
      return record.org.trusted;
    });
  }

  async function unmarkExpected(orgId, fp) {
    return withLock(orgId, async () => {
      const record = await endpointRecord(orgId);
      const before = (record.org.trusted || []).length;
      record.org.trusted = (record.org.trusted || []).filter((t) => t.fp !== String(fp));
      await store.endpoint.save({ ...record, updatedAt: now() });
      return before !== record.org.trusted.length;
    });
  }

  // Whether a machine going quiet should raise an alert. Servers default to yes, PCs to no.
  async function setExpectOnline(orgId, agentId, value) {
    const agent = await store.agents.get(String(agentId || ''));
    if (!agent || agent.orgId !== orgId) throw Object.assign(new Error('Machine not found.'), { status: 404 });
    const record = await endpointRecord(orgId);
    const expectOnline = { ...(record.policy.expectOnline || {}), [agent.id]: !!value };
    await store.endpoint.save({ ...record, policy: { ...record.policy, expectOnline }, updatedAt: now() });
    return expectsOnline(agent, expectOnline);
  }

  async function retire(orgId, agentId) {
    const agent = await store.agents.get(agentId);
    if (!agent || agent.orgId !== orgId) throw Object.assign(new Error('Machine not found.'), { status: 404 });
    await store.agents.save({ ...agent, status: 'retired', secretHash: sha256(secret()), updatedAt: now() });
    return true;
  }

  return {
    createEnrollToken,
    enroll,
    authenticate,
    checkIn,
    ingest,
    queueCommand,
    commandResult,
    uploadSample,
    pollSamples,
    cycle,
    overview,
    savePolicy,
    setExpectOnline,
    markExpected,
    unmarkExpected,
    retire,
    knownHashes,
    actions: ACTIONS,
  };
}
