import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BudgetLedger,
  type ScopeConfig,
  ScopeEnforcer,
  type ToolDescriptor,
  ToolRegistry,
  createBrokerHandler,
  createBrokerServer,
  normalizeNucleiJsonl,
  runInSandbox,
  signScopeToken,
} from '@shannon/tool-broker';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../broker/circuit-breaker.js';
import { ToolClient } from '../broker/tool-client.js';
import { LLMClientFactory } from '../llm/client.js';
import { resolveModel } from '../llm/tiers.js';
import { runBrokerAgent } from './broker-agent.js';
import { CLASS_CONFIGS } from './class-configs.js';
import type { LlmClient } from './tool-loop.js';

function fromEnvFile(name: string): string | undefined {
  for (const candidate of [join(process.cwd(), '..', '..', '.env'), join(process.cwd(), '.env')]) {
    try {
      for (const line of readFileSync(candidate, 'utf8').split(/\r?\n/)) {
        const i = line.indexOf('=');
        if (i > 0 && line.slice(0, i).trim() === name)
          return line
            .slice(i + 1)
            .trim()
            .replace(/^["']|["']$/g, '');
      }
    } catch {
      /* next */
    }
  }
  return undefined;
}
function docker(args: string[]): string {
  return execFileSync('docker', args, { stdio: 'pipe' }).toString();
}
function dockerOk(): boolean {
  try {
    docker(['version', '--format', '{{.Server.Version}}']);
    return true;
  } catch {
    return false;
  }
}
function imageExists(ref: string): boolean {
  try {
    docker(['image', 'inspect', ref]);
    return true;
  } catch {
    return false;
  }
}

const API_KEY = process.env.ANTHROPIC_API_KEY || fromEnvFile('ANTHROPIC_API_KEY');
const MODEL = fromEnvFile('SHANNON_QUICK_MODEL') || resolveModel('medium');
const LAB_IMAGE = 'shannon-lab-idor:local';
const PROBE_IMAGE = 'shannon-idor-probe:local';
const ENABLED =
  process.env.SHANNON_LIVE_E2E === '1' &&
  Boolean(API_KEY) &&
  dockerOk() &&
  imageExists(LAB_IMAGE) &&
  imageExists(PROBE_IMAGE);

const NET = 'shannon-idor-live-net';
const LAB = 'shannon-idor-live-lab';
const SCOPE_KEY = 'scope-key';
const RECORD_KEY = 'record-key';

const PROBE_DESCRIPTOR: ToolDescriptor = {
  id: 'idor-probe',
  bin: 'idor-probe',
  params: [{ name: 'url', required: true, pattern: '^https?://[^\\s]*INJECT[^\\s]*$' }],
  blocklist: [],
};

describe.skipIf(!ENABLED)('LIVE e2e: real LLM agent confirms IDOR via the generic broker agent', () => {
  const savedProviders: Record<string, string | undefined> = {};
  let server: Server;
  let labIp = '';

  beforeAll(async () => {
    for (const v of ['AWS_BEDROCK_REGION', 'VERTEX_PROJECT_ID', 'SHANNON_LLM_BASE_URL']) {
      savedProviders[v] = process.env[v];
      delete process.env[v];
    }
    process.env.ANTHROPIC_API_KEY = API_KEY;
    try {
      docker(['network', 'create', NET]);
    } catch {
      /* exists */
    }
    try {
      docker(['rm', '-f', LAB]);
    } catch {
      /* not running */
    }
    docker(['run', '-d', '--name', LAB, '--network', NET, LAB_IMAGE]);
    for (let i = 0; i < 30; i++) {
      let status = '';
      try {
        status = docker(['inspect', '-f', '{{.State.Health.Status}}', LAB]).trim();
      } catch {
        /* not ready */
      }
      if (status === 'healthy') break;
      await new Promise((r) => setTimeout(r, 1000));
    }
    labIp = docker(['inspect', '-f', `{{(index .NetworkSettings.Networks "${NET}").IPAddress}}`, LAB]).trim();

    const scope = scopeFor(labIp);
    server = createBrokerServer(
      createBrokerHandler({
        authorize: {
          scopeConfig: scope,
          scopeKey: SCOPE_KEY,
          enforcer: new ScopeEnforcer(scope),
          registry: new ToolRegistry([PROBE_DESCRIPTOR]),
          ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'idor-')), 'b.json'), { toolInvocations: 20 }),
        },
        recordKey: RECORD_KEY,
        resolveTarget: () => ({ ip: labIp, path: '/api/item/1' }),
        execute: (argv) => runInSandbox(argv, { image: PROBE_IMAGE, network: NET }),
        now: () => new Date().toISOString(),
        normalize: (_t, stdout) => normalizeNucleiJsonl(stdout),
      }),
    );
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  }, 120_000);

  afterAll(async () => {
    if (server) await new Promise<void>((r) => server.close(() => r()));
    try {
      docker(['rm', '-f', LAB]);
    } catch {
      /* ignore */
    }
    try {
      docker(['network', 'rm', NET]);
    } catch {
      /* ignore */
    }
    for (const [k, v] of Object.entries(savedProviders)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  function scopeFor(ip: string): ScopeConfig {
    return {
      targetHost: LAB,
      targetIps: [ip],
      allowlistCidrs: [],
      allowPrivateCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      focusPaths: [],
      avoidPaths: [],
    };
  }

  it('drives a real Anthropic agent (authz-bypass config) to confirm IDOR through the broker', async () => {
    const port = (server.address() as AddressInfo).port;
    const config = CLASS_CONFIGS['authz-bypass'];
    if (!config) throw new Error('authz-bypass config missing');
    const toolClient = new ToolClient({ brokerUrl: `http://127.0.0.1:${port}`, recordKey: RECORD_KEY });
    const client = new LLMClientFactory().createClient() as unknown as LlmClient;

    // Directive prompt matched to the in-house prober (which self-detects IDOR — no
    // second identity needed). Production uses the richer config.system with real tools.
    const liveSystem =
      'You are an IDOR/BOLA testing agent. You have one tool. Call it now with the target URL, ' +
      'placing the object id position where the URL contains the token INJECT. After the tool runs, ' +
      'report concisely whether IDOR was confirmed.';

    const res = await runBrokerAgent({
      client,
      model: MODEL,
      brokerDeps: { toolClient, breaker: new CircuitBreaker({ failureThreshold: 3, cooldownMs: 30_000 }) },
      scanId: 'idor-live',
      scopeToken: signScopeToken(scopeFor(labIp), SCOPE_KEY),
      system: liveSystem,
      tools: [...config.tools],
      userMessage: `Test this endpoint for IDOR using the tool: http://${LAB}:5000/api/item/INJECT`,
      maxTurns: 6,
    });

    expect(res.toolCalls).toBeGreaterThan(0);
    expect(res.findings.length).toBeGreaterThan(0);
    expect(res.findings[0].detail.toLowerCase()).toMatch(/idor|bola|authoriz/);
  }, 120_000);
});
