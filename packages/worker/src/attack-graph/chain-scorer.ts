import Anthropic from '@anthropic-ai/sdk';
import type { AttackChain, VulnNode, Edge, ChainAnalysisResult } from './types.js';
import { AttackGraph } from './graph.js';
import type { LLMClientFactory } from '../llm/client.js';
import { loadPrompt } from '../prompts/loader.js';
import { unwrap } from '../result.js';

const OBJECTIVES = [
  'remote code execution',
  'admin access',
  'data exfiltration',
  'credential theft',
  'full account takeover',
  'persistent backdoor',
];

export class ChainScorer {
  constructor(private llmFactory: LLMClientFactory) {}

  async analyzeGraph(graph: AttackGraph, targetUrl: string): Promise<ChainAnalysisResult> {
    const allChains: AttackChain[] = [];
    let chainCounter = 0;

    // Find chains for each high-value objective
    for (const objective of OBJECTIVES) {
      const paths = graph.findChains(objective);

      for (const path of paths.slice(0, 5)) {
        // Top 5 per objective
        const chainEdges = this.getEdgesForPath(graph, path);
        const score = graph.scoreChain(path, chainEdges);

        allChains.push({
          id: `chain-${++chainCounter}`,
          nodes: path,
          edges: chainEdges,
          entryPoint: path[0],
          objective,
          compositeScore: score,
          estimatedImpact: this.estimateImpact(path),
          mitreTactics: this.mapToMitre(path),
        });
      }
    }

    // Sort all chains by composite score
    allChains.sort((a, b) => b.compositeScore - a.compositeScore);

    // Use LLM to validate and re-score top chains
    const topChains = allChains.slice(0, 10);
    const validatedChains = await this.llmValidateChains(topChains, graph, targetUrl);

    const highest = validatedChains.length > 0 ? validatedChains[0] : null;

    return {
      graph: { nodes: graph.getAllNodes(), edges: graph.getAllEdges() },
      chains: validatedChains,
      highestScoringChain: highest,
      executionPlan: highest ? this.buildExecutionPlan(highest, graph) : [],
    };
  }

  private getEdgesForPath(graph: AttackGraph, path: VulnNode[]): Edge[] {
    const edges: Edge[] = [];
    for (let i = 0; i < path.length - 1; i++) {
      const edge = graph.getEdge(path[i].id, path[i + 1].id);
      if (edge) edges.push(edge);
    }
    return edges;
  }

  private estimateImpact(path: VulnNode[]): 'critical' | 'high' | 'medium' | 'low' {
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const maxSeverity = Math.max(...path.map((n) => severityOrder[n.severity]));
    // Multi-step chains amplify impact
    const amplified = Math.min(4, maxSeverity + Math.floor(path.length / 2));
    const map = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' } as const;
    return map[amplified as keyof typeof map] ?? 'medium';
  }

  private mapToMitre(path: VulnNode[]): string[] {
    const tactics: string[] = [];
    const categoryToTactic: Record<string, string[]> = {
      'sqli': ['TA0001', 'TA0006', 'TA0009'],
      'xss': ['TA0001', 'TA0006'],
      'ssrf': ['TA0008', 'TA0007'],
      'auth-bypass': ['TA0001', 'TA0004'],
      'authz-bypass': ['TA0004', 'TA0005'],
      'rce': ['TA0002', 'TA0003'],
      'credential-theft': ['TA0006'],
      'business-logic': ['TA0001', 'TA0040'],
      'rce-ssti': ['TA0002', 'TA0003'],
      'rce-deser': ['TA0002', 'TA0003'],
      'token-forgery': ['TA0001', 'TA0004', 'TA0006'],
      'prompt-injection': ['TA0001', 'TA0002'],
      'graphql-idor': ['TA0001', 'TA0007', 'TA0009'],
      'request-smuggling': ['TA0001', 'TA0005'],
    };

    for (const node of path) {
      const nodeTactics = categoryToTactic[node.category] ?? [];
      for (const tactic of nodeTactics) {
        if (!tactics.includes(tactic)) tactics.push(tactic);
      }
    }

    return tactics;
  }

  private async llmValidateChains(
    chains: AttackChain[],
    graph: AttackGraph,
    targetUrl: string,
  ): Promise<AttackChain[]> {
    if (chains.length === 0) return [];

    const prompt = unwrap(loadPrompt('chain-reasoning', {
      targetUrl,
      configContext: JSON.stringify(
        chains.map((c) => ({
          id: c.id,
          objective: c.objective,
          steps: c.nodes.map((n) => `${n.category}: ${n.endpoint} (${n.severity})`),
          score: c.compositeScore,
        })),
        null,
        2,
      ),
    }));

    const client = this.llmFactory.createClient();
    const model = this.llmFactory.resolveModelForAgent('chain-analysis');

    const response = await client.messages.create({
      model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    });

    const analysis = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');

    // Parse LLM validation results and adjust scores
    return this.parseValidationResults(chains, analysis);
  }

  private parseValidationResults(chains: AttackChain[], analysis: string): AttackChain[] {
    // LLM may eliminate infeasible chains or boost high-confidence ones
    // For now, return chains sorted by score with LLM annotations
    return chains.filter((chain) => {
      // Remove chains the LLM identifies as infeasible
      const chainMention = analysis.toLowerCase().includes(chain.id.toLowerCase());
      const markedInfeasible = analysis.toLowerCase().includes(`${chain.id}.*infeasible`);
      return !markedInfeasible;
    });
  }

  private buildExecutionPlan(chain: AttackChain, graph: AttackGraph): string[] {
    const sorted = graph.topologicalSort(chain.nodes);
    return sorted.map(
      (node, i) =>
        `Step ${i + 1}: Exploit ${node.category} at ${node.endpoint} (${node.severity}) -> gains: ${node.postconditions.join(', ')}`,
    );
  }
}
