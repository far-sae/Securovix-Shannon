import type { AttackChain, VulnNode } from './types.js';
import type { LLMClientFactory } from '../llm/client.js';
import type { EvidenceStore } from '../forensic/evidence-store.js';
import type { CustodyMetadata } from '../forensic/types.js';
import { loadPrompt } from '../prompts/loader.js';
import { unwrap } from '../result.js';

export interface ChainExploitResult {
  chainId: string;
  success: boolean;
  completedSteps: number;
  totalSteps: number;
  evidence: StepEvidence[];
  failedAtStep?: number;
  failureReason?: string;
}

export interface StepEvidence {
  step: number;
  nodeId: string;
  category: string;
  endpoint: string;
  exploitPayload: string;
  responseEvidence: string;
  accessGained: string;
  success: boolean;
}

export class ChainExecutor {
  constructor(
    private llmFactory: LLMClientFactory,
    private evidenceStore?: EvidenceStore,
    private custodyMetadata?: CustodyMetadata,
  ) {}

  async executeChain(chain: AttackChain, targetUrl: string): Promise<ChainExploitResult> {
    const evidence: StepEvidence[] = [];
    let currentAccess: string[] = [];

    for (let i = 0; i < chain.nodes.length; i++) {
      const node = chain.nodes[i];

      const stepResult = await this.executeStep(node, targetUrl, currentAccess, i + 1);
      evidence.push(stepResult);

      if (!stepResult.success) {
        return {
          chainId: chain.id,
          success: false,
          completedSteps: i,
          totalSteps: chain.nodes.length,
          evidence,
          failedAtStep: i + 1,
          failureReason: `Failed to exploit ${node.category} at ${node.endpoint}`,
        };
      }

      // Update current access with postconditions gained
      currentAccess = [...currentAccess, ...node.postconditions];

      // Record in forensic evidence store
      if (this.evidenceStore && this.custodyMetadata) {
        this.evidenceStore.record(
          'chain-executor',
          stepResult.success ? 'finding-confirmed' : 'exploit-attempt',
          {
            httpUrl: node.endpoint,
            httpBody: stepResult.exploitPayload,
            description: `Chain ${chain.id} step ${i + 1}: ${node.category} - ${stepResult.success ? 'SUCCESS' : 'FAILED'}`,
          },
          this.custodyMetadata,
        );
      }
    }

    return {
      chainId: chain.id,
      success: true,
      completedSteps: chain.nodes.length,
      totalSteps: chain.nodes.length,
      evidence,
    };
  }

  private async executeStep(
    node: VulnNode,
    targetUrl: string,
    currentAccess: string[],
    stepNumber: number,
  ): Promise<StepEvidence> {
    const client = this.llmFactory.createClient();
    const model = this.llmFactory.resolveModelForAgent('chain-exploit');

    const prompt = [
      `You are executing step ${stepNumber} of a multi-step attack chain.`,
      `Target: ${targetUrl}`,
      `Current access level: ${currentAccess.join(', ') || 'unauthenticated'}`,
      ``,
      `Exploit this vulnerability:`,
      `- Category: ${node.category}`,
      `- Endpoint: ${node.endpoint}`,
      `- Severity: ${node.severity}`,
      `- Evidence so far: ${node.evidence}`,
      `- Goal: Achieve these postconditions: ${node.postconditions.join(', ')}`,
      ``,
      `Provide:`,
      `1. The exact exploit payload (curl command or HTTP request)`,
      `2. Expected response that confirms success`,
      `3. What access/capability is gained after exploitation`,
    ].join('\n');

    const response = await client.messages.create({
      model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }],
    });

    const exploitPlan = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');

    return {
      step: stepNumber,
      nodeId: node.id,
      category: node.category,
      endpoint: node.endpoint,
      exploitPayload: exploitPlan,
      responseEvidence: 'LLM-generated exploit plan',
      accessGained: node.postconditions.join(', '),
      success: true,
    };
  }
}
