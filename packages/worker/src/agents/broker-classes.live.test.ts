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
const SCOPE_KEY = 'scope-key';
const RECORD_KEY = 'record-key';

interface ClassSpec {
  name: string;
  labImage: string;
  probeImage: string;
  tool: string; // broker descriptor id == LLM tool name
  path: string; // endpoint path on the lab
  system: string;
  assert: RegExp;
}

const SPECS: ClassSpec[] = [
  {
    name: 'JWT weak-secret',
    labImage: 'shannon-lab-jwt:local',
    probeImage: 'shannon-jwt-probe:local',
    tool: 'jwt-probe',
    path: '/me',
    system:
      'You are a JWT testing agent. You have one tool. Call it now with the target URL, then report whether a weak-secret forgery was confirmed.',
    assert: /jwt|weak secret|forg/i,
  },
  {
    name: 'GraphQL introspection',
    labImage: 'shannon-lab-graphql:local',
    probeImage: 'shannon-graphql-probe:local',
    tool: 'graphql-probe',
    path: '/graphql',
    system:
      'You are a GraphQL testing agent. You have one tool. Call it now with the target URL, then report whether introspection is exposed.',
    assert: /graphql|introspection|schema/i,
  },
  {
    name: 'Insecure deserialization',
    labImage: 'shannon-lab-deser:local',
    probeImage: 'shannon-deser-probe:local',
    tool: 'deser-probe',
    path: '/load',
    system:
      'You are an insecure-deserialization testing agent. You have one tool. Call it now with the target URL, then report whether deserialization RCE was confirmed.',
    assert: /deserial|pickle|rce|221/i,
  },
  {
    name: 'Prompt injection',
    labImage: 'shannon-lab-pi:local',
    probeImage: 'shannon-pi-probe:local',
    tool: 'pi-probe',
    path: '/chat',
    system:
      'You are a prompt-injection testing agent. You have one tool. Call it now with the target URL, then report whether the system prompt or canary leaked.',
    assert: /prompt.?inject|canary|system.?prompt|exfil/i,
  },
];

function scopeFor(host: string, ip: string): ScopeConfig {
  return {
    targetHost: host,
    targetIps: [ip],
    allowlistCidrs: [],
    allowPrivateCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    focusPaths: [],
    avoidPaths: [],
  };
}

for (const spec of SPECS) {
  const enabled =
    process.env.SHANNON_LIVE_E2E === '1' &&
    Boolean(API_KEY) &&
    dockerOk() &&
    imageExists(spec.labImage) &&
    imageExists(spec.probeImage);
  const NET = `shannon-live-${spec.tool}-net`;
  const LAB = `shannon-live-${spec.tool}-lab`;

  describe.skipIf(!enabled)(`LIVE e2e: ${spec.name} via generic broker agent`, () => {
    const saved: Record<string, string | undefined> = {};
    let server: Server;
    let labIp = '';

    beforeAll(async () => {
      for (const v of ['AWS_BEDROCK_REGION', 'VERTEX_PROJECT_ID', 'SHANNON_LLM_BASE_URL']) {
        saved[v] = process.env[v];
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
      docker(['run', '-d', '--name', LAB, '--network', NET, spec.labImage]);
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

      const scope = scopeFor(LAB, labIp);
      const descriptor: ToolDescriptor = {
        id: spec.tool,
        bin: spec.tool,
        params: [{ name: 'url', required: true, pattern: '^https?://[^\\s]+$' }],
        blocklist: [],
      };
      server = createBrokerServer(
        createBrokerHandler({
          authorize: {
            scopeConfig: scope,
            scopeKey: SCOPE_KEY,
            enforcer: new ScopeEnforcer(scope),
            registry: new ToolRegistry([descriptor]),
            ledger: new BudgetLedger(join(mkdtempSync(join(tmpdir(), 'live-')), 'b.json'), { toolInvocations: 20 }),
          },
          recordKey: RECORD_KEY,
          resolveTarget: () => ({ ip: labIp, path: spec.path }),
          execute: (argv) => runInSandbox(argv, { image: spec.probeImage, network: NET }),
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
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    });

    it('a real LLM agent confirms the finding through the broker', async () => {
      const port = (server.address() as AddressInfo).port;
      const toolClient = new ToolClient({ brokerUrl: `http://127.0.0.1:${port}`, recordKey: RECORD_KEY });
      const client = new LLMClientFactory().createClient() as unknown as LlmClient;
      const toolDef = {
        name: spec.tool,
        description: `Probe the target for ${spec.name}. Pass the full target URL as 'url'.`,
        input_schema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
      };

      const res = await runBrokerAgent({
        client,
        model: MODEL,
        brokerDeps: { toolClient, breaker: new CircuitBreaker({ failureThreshold: 3, cooldownMs: 30_000 }) },
        scanId: `live-${spec.tool}`,
        scopeToken: signScopeToken(scopeFor(LAB, labIp), SCOPE_KEY),
        system: spec.system,
        tools: [toolDef],
        userMessage: `Test this endpoint with the tool: http://${LAB}:5000${spec.path}`,
        maxTurns: 6,
      });

      expect(res.toolCalls).toBeGreaterThan(0);
      expect(res.findings.length).toBeGreaterThan(0);
      expect(res.findings[0].detail).toMatch(spec.assert);
    }, 120_000);
  });
}
