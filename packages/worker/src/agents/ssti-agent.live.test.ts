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
import { runSstiAgent } from './ssti-agent.js';
import type { LlmClient } from './tool-loop.js';

// Reads a var from the repo-root .env (vitest doesn't auto-load it).
function fromEnvFile(name: string): string | undefined {
  for (const candidate of [join(process.cwd(), '..', '..', '.env'), join(process.cwd(), '.env')]) {
    try {
      for (const line of readFileSync(candidate, 'utf8').split(/\r?\n/)) {
        const i = line.indexOf('=');
        if (i > 0 && line.slice(0, i).trim() === name) {
          return line
            .slice(i + 1)
            .trim()
            .replace(/^["']|["']$/g, '');
        }
      }
    } catch {
      /* try next */
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
const LAB_IMAGE = 'shannon-lab-ssti:local';
const PROBE_IMAGE = 'shannon-ssti-probe:local';
// Opt-in only: this makes real (paid) Anthropic calls + runs containers. Enable with
// SHANNON_LIVE_E2E=1 so routine `pnpm test` never incurs cost.
const ENABLED =
  process.env.SHANNON_LIVE_E2E === '1' &&
  Boolean(API_KEY) &&
  dockerOk() &&
  imageExists(LAB_IMAGE) &&
  imageExists(PROBE_IMAGE);

const NET = 'shannon-live-net';
const LAB = 'shannon-live-lab';
const SCOPE_KEY = 'scope-key';
const RECORD_KEY = 'record-key';

const SSTI_PROBE_TOOL = {
  name: 'ssti-probe',
  description:
    'Probe a URL for server-side template injection. Pass `url` as the full target URL with the literal token INJECT where the payload should be substituted (e.g. http://host:5000/?name=INJECT).',
  input_schema: {
    type: 'object',
    properties: { url: { type: 'string', description: 'Target URL containing the INJECT marker' } },
    required: ['url'],
  },
};

const PROBE_DESCRIPTOR: ToolDescriptor = {
  id: 'ssti-probe',
  bin: 'ssti-probe',
  params: [{ name: 'url', required: true, pattern: '^https?://[^\\s]*INJECT[^\\s]*$' }],
  blocklist: [],
};

describe.skipIf(!ENABLED)('LIVE e2e: real LLM agent exploits the SSTI lab through the broker', () => {
  const savedProviders: Record<string, string | undefined> = {};
  let server: Server;
  let labIp = '';

  beforeAll(async () => {
    // Pin exactly one LLM provider for the worker's resolveProvider().
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

    const scope: ScopeConfig = {
      targetHost: LAB,
      targetIps: [labIp],
      allowlistCidrs: [],
      allowPrivateCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      focusPaths: [],
      avoidPaths: [],
    };
    const handler = createBrokerHandler({
      authorize: {
        scopeConfig: scope,
        scopeKey: SCOPE_KEY,
        enforcer: new ScopeEnforcer(scope),
        registry: new ToolRegistry([PROBE_DESCRIPTOR]),
        ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'live-')), 'b.json'), { toolInvocations: 20 }),
      },
      recordKey: RECORD_KEY,
      resolveTarget: () => ({ ip: labIp, path: '/' }),
      execute: (argv) => runInSandbox(argv, { image: PROBE_IMAGE, network: NET }),
      now: () => new Date().toISOString(),
      normalize: (_tool, stdout) => normalizeNucleiJsonl(stdout),
    });
    server = createBrokerServer(handler);
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

  it('drives a real Anthropic agent to confirm SSTI via the broker-run prober', async () => {
    const port = (server.address() as AddressInfo).port;
    const scope: ScopeConfig = {
      targetHost: LAB,
      targetIps: [labIp],
      allowlistCidrs: [],
      allowPrivateCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      focusPaths: [],
      avoidPaths: [],
    };
    const toolClient = new ToolClient({ brokerUrl: `http://127.0.0.1:${port}`, recordKey: RECORD_KEY });
    const client = new LLMClientFactory().createClient() as unknown as LlmClient;

    const res = await runSstiAgent({
      client,
      model: MODEL,
      brokerDeps: { toolClient, breaker: new CircuitBreaker({ failureThreshold: 3, cooldownMs: 30_000 }) },
      scanId: 'live',
      scopeToken: signScopeToken(scope, SCOPE_KEY),
      tools: [SSTI_PROBE_TOOL],
      targetUrl: `http://${LAB}:5000/?name=INJECT`,
      maxTurns: 6,
    });

    // The model must have actually invoked the broker tool, which ran the real prober
    // against the real lab and confirmed SSTI.
    expect(res.toolCalls).toBeGreaterThan(0);
    expect(res.findings.length).toBeGreaterThan(0);
    expect(res.findings[0].detail.toLowerCase()).toContain('ssti');
    // And the model concluded it found something (sanity on the narrative).
    expect(res.finalText.length).toBeGreaterThan(0);
  }, 120_000);
});
