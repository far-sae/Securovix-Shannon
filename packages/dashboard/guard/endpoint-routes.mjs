// Routes for Guard Phase 2.
//   /api/endpoint-agent/v1/*  the Guard agent (Authorization: Bearer svxa_...), no cookies
//   /api/guard/endpoints/*    the dashboard (signed-in users, role-checked)
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { ACTIONS } from './catalog.mjs';
import { MAX_SAMPLE_BYTES } from './endpoint.mjs';

const AGENT = '/api/endpoint-agent/v1';
const MACHINE_ACTIONS = new Set(['isolate-host', 'kill-process', 'quarantine-file', 'collect-file']);

export function registerEndpointRoutes(app, deps) {
  const { endpoints, engine, requirePermission, audit, limited, can } = deps;
  const ipOf = (req) => req.ip || req.socket?.remoteAddress || null;
  const fail = (res, error) => res.status(error.status || 500).json({ error: error.message || 'Failed.' });

  async function agentAuth(req, res, next) {
    const agent = await endpoints.authenticate(req.headers.authorization).catch(() => null);
    if (!agent) return res.status(401).json({ error: 'Unknown or retired agent. Re-enroll it with a new token.' });
    if (limited(req, res, `endpoint-agent:${agent.id}`, 900, 5 * 60 * 1000)) return;
    req.guardAgent = agent;
    next();
  }

  // ----- the agent -----

  app.post(`${AGENT}/enroll`, async (req, res) => {
    if (limited(req, res, 'endpoint-enroll', 60, 60 * 60 * 1000)) return;
    try {
      res.status(201).json({ ok: true, ...(await endpoints.enroll(req.body || {}, ipOf(req))) });
    } catch (error) {
      fail(res, error);
    }
  });

  app.post(`${AGENT}/checkin`, agentAuth, async (req, res) => {
    try {
      res.json({ ok: true, ...(await endpoints.checkIn(req.guardAgent, req.body || {}, ipOf(req))) });
    } catch (error) {
      fail(res, error);
    }
  });

  app.post(`${AGENT}/events`, agentAuth, async (req, res) => {
    try {
      res.json({ ok: true, ...(await endpoints.ingest(req.guardAgent, req.body?.events)) });
    } catch (error) {
      fail(res, error);
    }
  });

  app.post(`${AGENT}/results`, agentAuth, async (req, res) => {
    try {
      res.json(await endpoints.commandResult(req.guardAgent, req.body || {}));
    } catch (error) {
      fail(res, error);
    }
  });

  app.post(
    `${AGENT}/samples`,
    agentAuth,
    express.raw({ type: 'application/octet-stream', limit: MAX_SAMPLE_BYTES + 1024 }),
    async (req, res) => {
      try {
        const sample = await endpoints.uploadSample(req.guardAgent, {
          bytes: Buffer.isBuffer(req.body) ? req.body : null,
          filename: decodeURIComponent(String(req.headers['x-file-name'] || 'sample.bin')).slice(0, 260),
          claimedSha: String(req.headers['x-sha256'] || '') || null,
          commandId: String(req.headers['x-command-id'] || '') || null,
        });
        res.status(201).json({ ok: true, sample: { id: sample.id, status: sample.status, verdict: sample.verdict } });
      } catch (error) {
        fail(res, error);
      }
    },
  );

  // ----- the dashboard -----

  app.get('/api/guard/endpoints', async (req, res) => {
    const ctx = requirePermission(req, res, 'findings.read');
    if (!ctx) return;
    try {
      res.json({
        ok: true,
        ...(await endpoints.overview(ctx.org.id)),
        canManage: can(ctx.membership.role, 'integrations.manage'),
        canRespond: can(ctx.membership.role, 'defender.manage'),
      });
    } catch (error) {
      fail(res, error);
    }
  });

  app.post('/api/guard/endpoints/enroll-token', async (req, res) => {
    const ctx = requirePermission(req, res, 'integrations.manage');
    if (!ctx) return;
    const token = await endpoints.createEnrollToken(ctx.org.id);
    audit(ctx, 'guard.endpoint.enroll_token_created', 'guard_endpoint', ctx.org.id, {});
    res.status(201).json({ ok: true, token });
  });

  app.post('/api/guard/endpoints/policy', async (req, res) => {
    const ctx = requirePermission(req, res, 'integrations.manage');
    if (!ctx) return;
    const b = req.body || {};
    const patch = {};
    for (const key of ['canaries', 'quarantineKnownMalware', 'autoSubmitExecutables', 'useSysmon', 'watchUserFolders'])
      if (typeof b[key] === 'boolean') patch[key] = b[key];
    if (b.ransomware && typeof b.ransomware === 'object') {
      patch.ransomware = {};
      if (typeof b.ransomware.autoKill === 'boolean') patch.ransomware.autoKill = b.ransomware.autoKill;
    }
    if (Array.isArray(b.extraWatch))
      patch.extraWatch = b.extraWatch
        .map((p) => String(p).slice(0, 260))
        .filter(Boolean)
        .slice(0, 20);
    if (Array.isArray(b.allow))
      patch.allow = b.allow
        .map((p) => String(p).trim().toLowerCase().slice(0, 260))
        .filter(Boolean)
        .slice(0, 200);
    const policy = await endpoints.savePolicy(ctx.org.id, patch);
    audit(ctx, 'guard.endpoint.policy_updated', 'guard_endpoint', ctx.org.id, { fields: Object.keys(patch) });
    res.json({ ok: true, policy });
  });

  // Isolate / release / stop a process / quarantine or collect a file, outside an incident.
  app.post('/api/guard/endpoints/:agentId/actions', async (req, res) => {
    const ctx = requirePermission(req, res, 'defender.manage');
    if (!ctx) return;
    const type = String(req.body?.type || '');
    const release = type === 'release-host';
    if (!MACHINE_ACTIONS.has(type) && !release) return res.status(400).json({ error: 'Unknown machine action.' });
    const params = { host: String(req.params.agentId) };
    if (req.body?.pid != null) params.pid = Number(req.body.pid);
    if (req.body?.path) params.path = String(req.body.path).slice(0, 1024);
    try {
      let result;
      if (release) {
        // Releasing is the undo of the most recent isolation, so the record stays paired.
        const isolations = (await deps.store.actions.list({ orgId: ctx.org.id }, { limit: 500 })).filter(
          (a) => a.type === 'isolate-host' && a.params?.host === params.host && a.status === 'done' && !a.undoneAt,
        );
        if (!isolations.length) return res.status(409).json({ error: 'This machine has no isolation to release.' });
        result = await engine.undoAction(ctx.org.id, isolations[0].id, { actor: ctx.user.email });
      } else {
        result = await engine.runAction(ctx.org.id, { type, params }, { actor: ctx.user.email, mode: 'manual' });
      }
      audit(ctx, `guard.endpoint.${type}`, 'guard_agent', params.host, { pid: params.pid, path: params.path });
      res.json({ ok: true, action: { ...result.action, undo: undefined, label: ACTIONS[type]?.label || type } });
    } catch (error) {
      fail(res, error);
    }
  });

  // Agent downloads, served from the build output (or SHANNON_GUARD_AGENT_DIR) when present.
  app.get('/api/guard/endpoints/download/:platform', (req, res) => {
    const ctx = requirePermission(req, res, 'findings.read');
    if (!ctx) return;
    const name = { windows: 'securovix-guard-windows-x86_64.exe', linux: 'securovix-guard-linux-x86_64' }[
      req.params.platform
    ];
    if (!name) return res.status(404).json({ error: 'Builds exist for windows and linux.' });
    const dir =
      process.env.SHANNON_GUARD_AGENT_DIR || fileURLToPath(new URL('../../guard-agent/dist/', import.meta.url));
    const file = join(dir, name);
    if (!existsSync(file))
      return res.status(404).json({
        error:
          'The agent has not been built on this server. Run packages/guard-agent/build/build.sh, or set SHANNON_GUARD_AGENT_DIR to where the release binaries are.',
      });
    res.download(file, req.params.platform === 'windows' ? 'securovix-guard.exe' : 'securovix-guard');
  });

  app.delete('/api/guard/endpoints/:agentId', async (req, res) => {
    const ctx = requirePermission(req, res, 'integrations.manage');
    if (!ctx) return;
    try {
      await endpoints.retire(ctx.org.id, String(req.params.agentId));
      audit(ctx, 'guard.endpoint.retired', 'guard_agent', String(req.params.agentId), {});
      res.json({ ok: true });
    } catch (error) {
      fail(res, error);
    }
  });
}
