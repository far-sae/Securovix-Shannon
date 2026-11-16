// Guard orchestration: collect -> detect -> incidents -> notify -> (optional) autopilot, plus
// one-click actions, undo, and closing incidents. Storage, providers, crypto and notification
// are injected so tests run against the local store and the demo tenant.
import { randomUUID } from 'node:crypto';
import { ACTIONS, PROVIDERS, RULES, SEVERITY_RANK } from './catalog.mjs';
import { detect, emptyOrgState, exploitAttempts } from './detect.mjs';
import { groupAlerts, publicIncident, rebuildIncident, recommendedActions, securityScore } from './incidents.mjs';

const DAY = 86_400_000;

export const AUTOPILOT_ACTIONS = Object.freeze([
  'revoke-sessions',
  'force-password-reset',
  'disable-user',
  'remove-inbox-rule',
  'revoke-oauth-grant',
  'block-ip',
  // On machines, carried out by the Guard agent.
  'kill-process',
  'quarantine-file',
  'isolate-host',
]);

export function defaultSettings(orgId) {
  return {
    id: orgId,
    orgId,
    domains: [],
    trustedApps: [],
    blocklist: [],
    autopilot: {
      enabled: false,
      minSeverity: 'critical',
      actions: Object.fromEntries(AUTOPILOT_ACTIONS.map((a) => [a, false])),
    },
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

const CONTAINS = new Set(['revoke-sessions', 'disable-user', 'remove-inbox-rule', 'revoke-oauth-grant', 'block-ip']);

// Whether what has been done so far actually stops each thing the incident found.
export function containmentMet(incident, done) {
  const did = (type, match = () => true) => done.some((a) => a.type === type && match(a.params || {}));
  const user = (a) => (p) => String(p.user || '').toLowerCase() === String(a.user || '').toLowerCase();
  for (const alert of incident.alerts || []) {
    if (alert.host?.id) {
      // A machine is contained when it is isolated, or when the specific thing found on it was
      // dealt with: the process stopped, the file quarantined.
      const onHost = (p) => p.host === alert.host.id;
      if (did('isolate-host', onHost)) continue;
      const pid = alert.context?.pid;
      const killed =
        pid != null &&
        (alert.context?.killed || did('kill-process', (p) => onHost(p) && String(p.pid) === String(pid)));
      const quarantined =
        alert.context?.quarantined ||
        (alert.context?.path && did('quarantine-file', (p) => onHost(p) && p.path === alert.context.path));
      const kind = RULES[alert.rule]?.kind;
      if (kind === 'execution' && killed) continue;
      if ((kind === 'host-persistence' || kind === 'malware') && (quarantined || (kind === 'malware' && killed)))
        continue;
      return false; // ransomware, credential theft, lateral movement, evasion: isolate the machine
    }
    const disabled = alert.user && did('disable-user', user(alert));
    if (disabled) continue;
    switch (alert.rule) {
      case 'password-spray':
      case 'exploit-attempt':
        if (!did('block-ip', (p) => p.ip === alert.ip)) return false;
        break;
      case 'brute-force':
        if (!did('block-ip', (p) => p.ip === alert.ip) && !did('force-password-reset', user(alert))) return false;
        break;
      case 'inbox-rule':
      case 'mail-forwarding':
        if (
          alert.context?.ruleName
            ? !did('remove-inbox-rule', (p) => p.ruleName === alert.context.ruleName)
            : !did('revoke-sessions', user(alert))
        )
          return false;
        break;
      case 'oauth-consent':
        if (!did('revoke-oauth-grant', (p) => p.clientId === alert.context?.clientId)) return false;
        break;
      default:
        if (!alert.user || !did('revoke-sessions', user(alert))) return false;
    }
  }
  return true;
}

export function createGuardEngine({
  store,
  providers,
  encrypt,
  decrypt,
  notify = async () => {},
  loadBadIps = async () => new Map(),
  now = () => Date.now(),
  publicUrl = () => '',
}) {
  const running = new Map();
  const locks = new Map();
  let agents = null; // the endpoint service, attached after both exist (see attachAgents)

  // Incident updates for one organization run one at a time: agent uploads arrive every few
  // seconds and the cloud sync every two minutes, and both rewrite the same incidents.
  function withLock(orgId, fn) {
    const previous = locks.get(orgId) || Promise.resolve();
    const next = previous.catch(() => {}).then(fn);
    const tail = next.catch(() => {});
    locks.set(orgId, tail);
    tail.then(() => {
      if (locks.get(orgId) === tail) locks.delete(orgId);
    });
    return next;
  }

  async function getSettings(orgId) {
    const saved = await store.settings.get(orgId);
    const base = defaultSettings(orgId);
    if (!saved) return base;
    return {
      ...base,
      ...saved,
      autopilot: {
        ...base.autopilot,
        ...(saved.autopilot || {}),
        actions: { ...base.autopilot.actions, ...(saved.autopilot?.actions || {}) },
      },
    };
  }

  async function saveSettings(orgId, patch) {
    const current = await getSettings(orgId);
    const next = { ...current, ...patch, id: orgId, orgId, updatedAt: now() };
    await store.settings.save(next);
    return next;
  }

  async function loadState(orgId) {
    const saved = await store.state.get(orgId);
    return {
      id: orgId,
      orgId,
      baselines: saved?.baselines || {},
      orgState: saved?.orgState || emptyOrgState(),
      exploitSince: saved?.exploitSince || now() - DAY,
      updatedAt: saved?.updatedAt || now(),
    };
  }

  async function listConnections(orgId) {
    return store.connections.list({ orgId }, { limit: 50 });
  }

  async function syncConnection(connection, settings, state, badIps) {
    const provider = providers[connection.provider];
    if (!provider) throw new Error(`Unknown provider ${connection.provider}`);
    const secret = connection.secretEnc ? decrypt(connection.secretEnc) : null;
    const collected = await provider.collect(connection, secret, { state: connection.state || {}, now: now() });
    const orgDomains = new Set(
      [...(settings.domains || []), ...(connection.config?.domains || [])].map((d) => String(d).toLowerCase()),
    );
    const baselines = new Map(Object.entries(state.baselines));
    const result = detect(collected.events, {
      orgId: connection.orgId,
      connectionId: connection.id,
      baselines,
      orgState: state.orgState,
      badIps,
      blocked: new Set((settings.blocklist || []).map((b) => b.ip)),
      orgDomains,
      trustedApps: new Set(settings.trustedApps || []),
    });
    state.baselines = Object.fromEntries(result.baselines);
    state.orgState = result.orgState;
    const saved = {
      ...connection,
      state: collected.state,
      lastSyncAt: now(),
      lastError: collected.errors?.length ? collected.errors.join(' | ').slice(0, 1000) : null,
      lastEventCount: result.processed,
      totalEvents: (connection.totalEvents || 0) + result.processed,
      status: collected.errors?.length && !result.processed ? 'error' : 'active',
      updatedAt: now(),
    };
    await store.connections.save(saved);
    return result.alerts;
  }

  async function openIncidents(orgId) {
    return (await store.incidents.list({ orgId }, { orderBy: 'lastSeenAt', limit: 500 })).filter(
      (i) => i.status !== 'closed',
    );
  }

  async function syncOrgNow(orgId) {
    const settings = await getSettings(orgId);
    const state = await loadState(orgId);
    const connections = (await listConnections(orgId)).filter((c) => c.enabled !== false);
    const badIps = connections.some((c) => c.provider !== 'simulation')
      ? await loadBadIps().catch(() => new Map())
      : new Map();
    const alerts = [];
    const errors = [];
    for (const connection of connections) {
      try {
        alerts.push(...(await syncConnection(connection, settings, state, badIps)));
      } catch (error) {
        errors.push(`${connection.name}: ${error.message}`);
        await store.connections.save({
          ...connection,
          lastSyncAt: now(),
          lastError: String(error.message).slice(0, 1000),
          status: 'error',
          updatedAt: now(),
        });
      }
    }
    // Shannon -> Guard: attacks on vulnerabilities Shannon proved.
    try {
      const since = state.exploitSince;
      const events = await store.listDefenseEventsSince(orgId, since);
      alerts.push(...exploitAttempts(events, await store.listFindings(orgId), { orgId, since }));
      state.exploitSince = now();
    } catch (error) {
      errors.push(`Shannon link: ${error.message}`);
    }
    state.updatedAt = now();
    await store.state.save(state);
    const processed = await withLock(orgId, () => processAlerts(orgId, alerts, settings));
    return { alerts: alerts.length, ...processed, errors };
  }

  async function processAlerts(orgId, alerts, settings) {
    if (!alerts.length) return { incidents: 0, created: 0, autopilot: [] };
    const open = await openIncidents(orgId);
    const before = new Map(open.map((i) => [i.id, i.severity]));
    const { changed, created } = groupAlerts(open, alerts, { orgId, now: now() });
    for (const incident of changed) {
      await store.incidents.save(incident);
      await refreshContainment(orgId, incident.id);
    }

    const createdIds = new Set(created.map((i) => i.id));
    for (const incident of changed) {
      const escalated =
        before.has(incident.id) &&
        (SEVERITY_RANK[incident.severity] || 0) > (SEVERITY_RANK[before.get(incident.id)] || 0);
      if (createdIds.has(incident.id) || escalated) {
        await notify(orgId, {
          id: `guard-incident:${incident.id}:${incident.severity}`,
          type: 'guard.incident',
          at: new Date(now()).toISOString(),
          data: {
            title: incident.title,
            severity: incident.severity,
            status: incident.status,
            incidentId: incident.id,
            summary: incident.summary.slice(0, 1500),
            mitre: incident.mitre.map((m) => m.id),
            url: `${publicUrl()}/#guard`,
          },
        }).catch(() => {});
      }
    }
    const autopilot = await runAutopilot(orgId, settings, changed);
    return { incidents: changed.length, created: created.length, autopilot };
  }

  // Alerts that did not come from a cloud sync (the endpoint agent, the sandbox).
  async function ingestAlerts(orgId, alerts) {
    const settings = await getSettings(orgId);
    return withLock(orgId, () => processAlerts(orgId, alerts, settings));
  }

  async function syncOrg(orgId) {
    if (running.has(orgId)) return running.get(orgId);
    const job = syncOrgNow(orgId).finally(() => running.delete(orgId));
    running.set(orgId, job);
    return job;
  }

  async function runAutopilot(orgId, settings, incidents) {
    const auto = settings.autopilot;
    if (!auto?.enabled) return [];
    const ran = [];
    for (const incident of incidents) {
      if (
        incident.status !== 'open' ||
        (SEVERITY_RANK[incident.severity] || 0) < (SEVERITY_RANK[auto.minSeverity] || 4)
      )
        continue;
      const done = await actionsFor(orgId, incident.id);
      // Account actions follow the incident: a takeover is a chain of alerts that are each only
      // "high". Machine actions follow the alert: a process is stopped, a file quarantined or a
      // machine cut off only for an alert that is itself at the chosen severity, never for a
      // lesser alert that happens to share the incident.
      const floor = SEVERITY_RANK[auto.minSeverity] || 4;
      const keyOf = (a) => `${a.type}|${JSON.stringify(a.params)}`;
      const strong = new Set(
        recommendedActions(incident.alerts.filter((a) => (SEVERITY_RANK[a.severity] || 0) >= floor)).map(keyOf),
      );
      for (const action of recommendedActions(incident.alerts)) {
        if (!auto.actions?.[action.type]) continue;
        const onMachine = ACTIONS[action.type]?.channel === 'agent';
        if (onMachine && !strong.has(keyOf(action))) continue;
        if (
          done.some(
            (a) =>
              // A machine action is tried once: a process that has already exited stays exited.
              (onMachine || ((a.status === 'done' || a.status === 'pending') && !a.undoneAt)) &&
              a.type === action.type &&
              JSON.stringify(a.params) === JSON.stringify(action.params),
          )
        )
          continue;
        ran.push(
          await runAction(
            orgId,
            { incidentId: incident.id, type: action.type, params: action.params, connectionId: action.connectionId },
            { actor: 'autopilot', mode: 'autopilot' },
          ).catch((error) => ({ type: action.type, status: 'failed', error: error.message })),
        );
      }
    }
    return ran;
  }

  async function actionsFor(orgId, incidentId) {
    return await store.actions.list({ orgId, incidentId }, { limit: 200 });
  }

  async function refreshContainment(orgId, incidentId) {
    if (!incidentId) return null;
    const incident = await store.incidents.get(incidentId);
    if (!incident || incident.orgId !== orgId || incident.status === 'closed') return incident;
    const done = (await actionsFor(orgId, incidentId)).filter((a) => a.status === 'done' && !a.undoneAt);
    // An incident can be contained with no action from us when the agent already stopped or
    // quarantined what it found; containmentMet decides per alert.
    const met = (incident.alerts || []).length > 0 && containmentMet(incident, done);
    if (met && incident.status === 'open') Object.assign(incident, { status: 'contained', containedAt: now() });
    else if (!met && incident.status === 'contained') Object.assign(incident, { status: 'open', containedAt: null });
    incident.actionsTaken = done.map((a) => a.id);
    incident.updatedAt = now();
    await store.incidents.save(incident);
    return incident;
  }

  async function runAction(
    orgId,
    { incidentId = null, type, params = {}, connectionId = null },
    { actor, mode = 'manual' } = {},
  ) {
    const spec = ACTIONS[type];
    if (!spec || spec.internal) throw Object.assign(new Error(`Unknown action "${type}".`), { status: 400 });
    for (const need of spec.needs)
      if (!params[need]) throw Object.assign(new Error(`The action needs "${need}".`), { status: 400 });
    let incident = null;
    if (incidentId) {
      incident = await store.incidents.get(incidentId);
      if (!incident || incident.orgId !== orgId) throw Object.assign(new Error('Incident not found.'), { status: 404 });
    }
    const record = {
      id: `gac_${randomUUID().replaceAll('-', '').slice(0, 20)}`,
      orgId,
      incidentId,
      connectionId,
      type,
      params,
      status: 'failed',
      error: null,
      detail: null,
      undo: null,
      actor,
      mode,
      createdAt: now(),
      undoneAt: null,
      undoneBy: null,
    };
    try {
      if (type === 'block-ip') {
        const settings = await getSettings(orgId);
        const blocklist = (settings.blocklist || []).filter((b) => b.ip !== params.ip);
        blocklist.push({
          ip: params.ip,
          reason: incident?.title || params.reason || 'Blocked in Guard',
          at: now(),
          by: actor,
        });
        await saveSettings(orgId, { blocklist: blocklist.slice(-1000) });
        Object.assign(record, {
          status: 'done',
          detail: `Added ${params.ip} to the Guard blocklist. Sign-ins from it are now critical alerts; copy the blocklist WAF rule to block it at the edge too.`,
          undo: {},
        });
      } else if (spec.channel === 'agent') {
        if (!agents)
          throw Object.assign(new Error('Endpoint agents are not available.'), { status: 400, userError: true });
        const command = await agents.queueCommand(orgId, {
          agentId: params.host,
          type,
          params,
          actionId: record.id,
          actor,
        });
        Object.assign(record, {
          status: 'pending',
          connectionId: null,
          detail: `Sent to ${command.hostname}. Waiting for the agent to confirm (it checks in every few seconds).`,
        });
      } else {
        const connection = connectionId ? await store.connections.get(connectionId) : null;
        if (!connection || connection.orgId !== orgId)
          throw Object.assign(new Error('Choose the Microsoft 365 or Google connection to act on.'), {
            status: 400,
            userError: true,
          });
        if (!(PROVIDERS[connection.provider]?.actions || []).includes(type))
          throw Object.assign(
            new Error(
              `${PROVIDERS[connection.provider]?.label || connection.provider} cannot ${spec.label.toLowerCase()}.`,
            ),
            { status: 400, userError: true },
          );
        const secret = connection.secretEnc ? decrypt(connection.secretEnc) : null;
        const result = await providers[connection.provider].act(connection, secret, type, params);
        if (connection.provider === 'simulation') await store.connections.save({ ...connection, updatedAt: now() });
        Object.assign(record, {
          status: 'done',
          detail: result.detail || 'Done.',
          undo: spec.reversible && result.undo !== null ? result.undo || {} : null,
        });
      }
    } catch (error) {
      record.error = String(error.message || error).slice(0, 500);
      if (error.userError) throw error;
    }
    await store.actions.save(record);
    const updated = await refreshContainment(orgId, incidentId);
    return { action: record, incident: updated ? publicIncident(updated) : null };
  }

  async function undoAction(orgId, actionId, { actor }) {
    const action = await store.actions.get(actionId);
    if (!action || action.orgId !== orgId) throw Object.assign(new Error('Action not found.'), { status: 404 });
    if (action.status !== 'done' || action.undoneAt)
      throw Object.assign(new Error('Only a completed action can be undone, once.'), { status: 409 });
    const spec = ACTIONS[action.type];
    if (!spec?.reversible || !action.undo)
      throw Object.assign(new Error(`"${spec?.label || action.type}" cannot be undone.`), { status: 409 });
    if (action.undo?.pendingCommandId)
      throw Object.assign(new Error('The undo is already on its way to the machine.'), { status: 409 });
    let detail;
    if (spec.channel === 'agent') {
      if (!agents) throw Object.assign(new Error('Endpoint agents are not available.'), { status: 409 });
      const command = await agents.queueCommand(orgId, {
        agentId: action.params.host,
        type: spec.undo,
        params: action.params,
        actionId: action.id,
        undoData: action.undo,
        actor,
      });
      const pending = { ...action, undo: { ...action.undo, pendingCommandId: command.id, requestedBy: actor } };
      await store.actions.save(pending);
      return {
        action: { ...pending, undoDetail: `Sent to ${command.hostname}; waiting for the agent.` },
        incident: null,
        pending: true,
      };
    }
    if (action.type === 'block-ip') {
      const settings = await getSettings(orgId);
      await saveSettings(orgId, { blocklist: (settings.blocklist || []).filter((b) => b.ip !== action.params.ip) });
      detail = `Removed ${action.params.ip} from the blocklist.`;
    } else {
      const connection = await store.connections.get(action.connectionId);
      if (!connection || connection.orgId !== orgId)
        throw Object.assign(new Error('The connection this action used no longer exists.'), { status: 409 });
      const secret = connection.secretEnc ? decrypt(connection.secretEnc) : null;
      detail = (await providers[connection.provider].act(connection, secret, spec.undo, action.params, action.undo))
        .detail;
      if (connection.provider === 'simulation') await store.connections.save({ ...connection, updatedAt: now() });
    }
    const saved = { ...action, undoneAt: now(), undoneBy: actor, undoDetail: detail };
    await store.actions.save(saved);
    const incident = await refreshContainment(orgId, action.incidentId);
    return { action: saved, incident: incident ? publicIncident(incident) : null };
  }

  // The agent reports how a command went. Finishes the action (or its undo) and re-checks
  // whether the incident is now contained.
  async function completeCommand(orgId, command, { ok, detail, data }) {
    if (!command.actionId) return null;
    const action = await store.actions.get(command.actionId);
    if (!action || action.orgId !== orgId) return null;
    const spec = ACTIONS[action.type];
    let saved;
    if (command.type === action.type) {
      saved = {
        ...action,
        status: ok ? 'done' : 'failed',
        detail: String(detail || (ok ? 'Done.' : '')).slice(0, 500) || null,
        error: ok ? null : String(detail || 'The agent could not do it.').slice(0, 500),
        undo: ok && spec?.reversible ? data || {} : null,
      };
    } else {
      const { pendingCommandId, requestedBy, ...undoData } = action.undo || {};
      saved = ok
        ? {
            ...action,
            undo: undoData,
            undoneAt: now(),
            undoneBy: requestedBy || 'agent',
            undoDetail: String(detail || 'Undone.').slice(0, 500),
          }
        : { ...action, undo: undoData, undoDetail: `Undo failed: ${String(detail || '').slice(0, 400)}` };
    }
    await withLock(orgId, async () => {
      await store.actions.save(saved);
      await refreshContainment(orgId, action.incidentId);
    });
    return saved;
  }

  async function closeIncident(orgId, incidentId, { actor, force = false, note = '' } = {}) {
    const incident = await store.incidents.get(incidentId);
    if (!incident || incident.orgId !== orgId) throw Object.assign(new Error('Incident not found.'), { status: 404 });
    // The loop's last step: an attack on a proven vulnerability closes only once Shannon has
    // re-tested the fix (the finding is resolved), unless someone overrides on purpose.
    const findingIds = [...new Set((incident.alerts || []).map((a) => a.context?.findingId).filter(Boolean))];
    if (findingIds.length && !force) {
      const findings = await store.listFindings(orgId);
      const unresolved = findingIds.filter((id) => findings.find((f) => f.id === id)?.status !== 'resolved');
      if (unresolved.length)
        throw Object.assign(
          new Error(
            'The vulnerability behind this incident is not fixed yet. Re-test it with Shannon; the incident can close once the finding is resolved.',
          ),
          { status: 409, code: 'FIX_NOT_VERIFIED', findingIds: unresolved },
        );
    }
    const saved = {
      ...incident,
      status: 'closed',
      closedAt: now(),
      closedBy: actor,
      closeNote: String(note || '').slice(0, 500) || null,
      forcedClose: !!(findingIds.length && force),
      updatedAt: now(),
    };
    await store.incidents.save(saved);
    return publicIncident(saved);
  }

  // A command or file was marked as expected: take every alert with that fingerprint out of the
  // open incidents. An incident left with no alerts is closed, with a note saying why.
  async function dropExpected(orgId, fp, { actor = null } = {}) {
    return withLock(orgId, async () => {
      let removed = 0;
      let closed = 0;
      for (const incident of await openIncidents(orgId)) {
        const all = incident.alerts || [];
        const keep = all.filter((a) => a.trust?.fp !== fp);
        if (keep.length === all.length) continue;
        removed += all.length - keep.length;
        if (!keep.length) {
          closed += 1;
          await store.incidents.save({
            ...incident,
            status: 'closed',
            closedAt: now(),
            closedBy: actor,
            closeNote: 'Every alert in this incident was marked as expected.',
            updatedAt: now(),
          });
          continue;
        }
        await store.incidents.save(rebuildIncident({ ...incident, alerts: keep, alertCount: keep.length }, now()));
        await refreshContainment(orgId, incident.id);
      }
      return { removed, closed };
    });
  }

  // Disconnects a tenant. With `purge` it also removes everything that connection produced: its
  // incidents, the actions taken on them, the blocklist entries those actions added, and the
  // per-person baselines learned for its domains. An incident that also holds alerts from another
  // source (a second tenant, an endpoint agent, Shannon) is kept. The demo tenant is always
  // purged, so removing it leaves no simulated data behind; a real tenant keeps its incident
  // history unless the caller asks otherwise.
  async function removeConnection(orgId, connectionId, { purge = false } = {}) {
    const connection = await store.connections.get(connectionId);
    if (!connection || connection.orgId !== orgId)
      throw Object.assign(new Error('Connection not found.'), { status: 404 });
    // A sync already in flight would write this connection's baselines straight back.
    if (running.has(orgId)) await running.get(orgId).catch(() => {});
    return withLock(orgId, async () => {
      await store.connections.remove(connectionId);
      const removed = { incidents: 0, actions: 0, baselines: 0, blocklist: 0 };
      if (!purge) return removed;
      const gone = new Set();
      // The store returns at most 500 rows a call, so repeat until a pass finds nothing more.
      for (let pass = 0; pass < 20; pass += 1) {
        const mine = (await store.incidents.list({ orgId }, { orderBy: 'lastSeenAt', limit: 500 })).filter(
          (i) => (i.alerts || []).length && i.alerts.every((a) => a.connectionId === connectionId),
        );
        if (!mine.length) break;
        for (const incident of mine) {
          await store.incidents.remove(incident.id);
          gone.add(incident.id);
        }
      }
      removed.incidents = gone.size;
      const unblock = new Set();
      for (let pass = 0; pass < 20; pass += 1) {
        const mine = (await store.actions.list({ orgId }, { limit: 500 })).filter(
          (a) => a.connectionId === connectionId || (a.incidentId && gone.has(a.incidentId)),
        );
        if (!mine.length) break;
        for (const action of mine) {
          if (action.type === 'block-ip' && action.status === 'done' && !action.undoneAt && action.params?.ip)
            unblock.add(action.params.ip);
          await store.actions.remove(action.id);
          removed.actions += 1;
        }
      }
      if (unblock.size) {
        const settings = await getSettings(orgId);
        const blocklist = (settings.blocklist || []).filter((b) => !unblock.has(b.ip));
        removed.blocklist = (settings.blocklist || []).length - blocklist.length;
        if (removed.blocklist) await saveSettings(orgId, { blocklist });
      }
      const remaining = await listConnections(orgId);
      const lower = (d) => String(d).toLowerCase();
      const stillUsed = new Set(remaining.flatMap((c) => c.config?.domains || []).map(lower));
      const domains = new Set((connection.config?.domains || []).map(lower).filter((d) => !stillUsed.has(d)));
      const state = await loadState(orgId);
      for (const key of Object.keys(state.baselines)) {
        const domain = String(key).split('@')[1];
        if (domain && domains.has(lower(domain))) {
          delete state.baselines[key];
          removed.baselines += 1;
        }
      }
      // With nothing left connected there is no sign-in history worth keeping either.
      if (!remaining.length) state.orgState = emptyOrgState();
      state.updatedAt = now();
      await store.state.save(state);
      return removed;
    });
  }

  async function overview(orgId) {
    const [connections, incidents, findings, kevMatches, settings] = await Promise.all([
      listConnections(orgId),
      store.incidents.list({ orgId }, { orderBy: 'lastSeenAt', limit: 200 }),
      store.listFindings(orgId),
      store.listVulnerabilityMatches(orgId).catch(() => []),
      getSettings(orgId),
    ]);
    const contained = incidents.filter((i) => i.containedAt);
    const times = contained
      .map((i) => i.containedAt - (i.detectedAt || i.firstSeenAt))
      .filter((x) => x >= 0)
      .sort((a, b) => a - b);
    return {
      score: securityScore({ incidents, connections, findings, kevMatches }),
      counts: {
        open: incidents.filter((i) => i.status === 'open').length,
        contained: incidents.filter((i) => i.status === 'contained').length,
        closed: incidents.filter((i) => i.status === 'closed').length,
        kev: kevMatches.filter((m) => m.details?.kev && m.status !== 'resolved').length,
      },
      medianTimeToContainMs: times.length ? times[Math.floor(times.length / 2)] : null,
      connections: connections.map(publicConnection),
      blocklist: settings.blocklist || [],
      autopilot: settings.autopilot,
    };
  }

  return {
    getSettings,
    saveSettings,
    syncOrg,
    ingestAlerts,
    completeCommand,
    attachAgents: (service) => {
      agents = service;
    },
    runAction,
    undoAction,
    closeIncident,
    dropExpected,
    overview,
    listConnections,
    removeConnection,
    actionsFor,
    refreshContainment,
    encrypt,
  };
}

export function publicConnection(connection) {
  const { secretEnc, state, ...rest } = connection;
  return {
    ...rest,
    hasSecret: !!secretEnc,
    label: PROVIDERS[connection.provider]?.label || connection.provider,
    actions: PROVIDERS[connection.provider]?.actions?.filter((a) => !ACTIONS[a]?.internal) || [],
    pendingScenarios: state?.sim?.pending?.length || 0,
  };
}
