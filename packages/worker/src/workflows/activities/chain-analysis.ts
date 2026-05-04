import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { heartbeat } from '@temporalio/activity';
import type { Container } from '../../di/container.js';
import type { ChainAnalysisInput, ChainAnalysisOutput } from './index.js';
import { unwrap } from '../../result.js';
import { AttackGraph } from '../../attack-graph/graph.js';
import { ChainScorer } from '../../attack-graph/chain-scorer.js';
import type { VulnNode, VulnCategory } from '../../attack-graph/types.js';
import { toTemporalError, truncateForSerialization } from '../../temporal/error-classification.js';

const CATEGORIES = ['sqli', 'xss', 'auth-bypass', 'authz-bypass', 'ssrf', 'business-logic'] as const;

export async function chainAnalysisActivity(
  container: Container,
  input: ChainAnalysisInput,
): Promise<ChainAnalysisOutput> {
  const config = unwrap(container.configLoader.load(input.configPath));
  const outputDir = join(input.workspaceDir, 'chain-analysis');
  mkdirSync(outputDir, { recursive: true });

  try {
    heartbeat('Building attack graph from findings');

    const graph = new AttackGraph();
    let nodeCounter = 0;

    // Load all vuln findings and convert to graph nodes
    for (const category of CATEGORIES) {
      const queuePath = join(input.workspaceDir, 'vuln', category, 'exploitation-queue.json');
      if (!existsSync(queuePath)) continue;

      const queue = JSON.parse(readFileSync(queuePath, 'utf-8'));
      if (!queue.findings) continue;

      for (const finding of queue.findings) {
        const node: VulnNode = {
          id: `node-${++nodeCounter}`,
          category: category as VulnCategory,
          endpoint: finding.endpoint ?? '',
          severity: finding.severity ?? 'medium',
          preconditions: inferPreconditions(category, finding),
          postconditions: inferPostconditions(category, finding),
          feasibilityScore: finding.type === 'confirmed' ? 0.9 : 0.6,
          evidence: finding.description ?? '',
        };
        graph.addNode(node);
      }
    }

    // Build edges based on precondition/postcondition matching
    const allNodes = graph.getAllNodes();
    for (const from of allNodes) {
      for (const to of allNodes) {
        if (from.id === to.id) continue;

        // Check if 'from' postconditions satisfy 'to' preconditions
        const enables = to.preconditions.some((pre) =>
          from.postconditions.some((post) => post.toLowerCase().includes(pre.toLowerCase())),
        );

        if (enables) {
          graph.addEdge({
            from: from.id,
            to: to.id,
            transitionType: 'enables',
            confidence: 0.7,
          });
        }
      }
    }

    heartbeat('Analyzing attack chains with LLM');
    const scorer = new ChainScorer(container.llmClientFactory);
    const result = await scorer.analyzeGraph(graph, config.target.url);

    // Save results
    const chainPath = join(outputDir, 'chains.json');
    writeFileSync(chainPath, truncateForSerialization(JSON.stringify(result, null, 2)));

    // Save graph visualization data
    writeFileSync(
      join(outputDir, 'graph.md'),
      truncateForSerialization(graph.toPromptContext()),
    );

    if (result.highestScoringChain) {
      writeFileSync(
        join(outputDir, 'execution-plan.md'),
        truncateForSerialization(
          [
            `# Attack Chain: ${result.highestScoringChain.objective}`,
            `Score: ${result.highestScoringChain.compositeScore.toFixed(4)}`,
            `Impact: ${result.highestScoringChain.estimatedImpact}`,
            `MITRE Tactics: ${result.highestScoringChain.mitreTactics.join(', ')}`,
            '',
            '## Execution Plan',
            ...result.executionPlan.map((step) => `- ${step}`),
          ].join('\n'),
        ),
      );
    }

    heartbeat('Chain analysis complete');

    return {
      hasChain: result.highestScoringChain !== null,
      chainPath,
    };
  } catch (error) {
    throw toTemporalError(error);
  }
}

function inferPreconditions(category: string, finding: Record<string, unknown>): string[] {
  const pre: string[] = [];
  switch (category) {
    case 'authz-bypass':
      pre.push('authenticated');
      break;
    case 'business-logic':
      pre.push('authenticated');
      break;
  }
  return pre;
}

function inferPostconditions(category: string, finding: Record<string, unknown>): string[] {
  const post: string[] = [];
  switch (category) {
    case 'sqli':
      post.push('data-access', 'credential-theft');
      break;
    case 'xss':
      post.push('session-hijack', 'credential-theft');
      break;
    case 'auth-bypass':
      post.push('authenticated', 'admin-access');
      break;
    case 'authz-bypass':
      post.push('elevated-privileges', 'admin-access');
      break;
    case 'ssrf':
      post.push('internal-network-access', 'credential-theft');
      break;
    case 'business-logic':
      post.push('workflow-manipulation', 'financial-impact');
      break;
  }
  return post;
}
