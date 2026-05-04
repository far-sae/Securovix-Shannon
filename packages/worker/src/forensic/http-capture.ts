import type { BrowserContext, Route, Request, Response } from 'playwright';
import { createHash } from 'node:crypto';
import type { EvidenceStore } from './evidence-store.js';
import type { CustodyMetadata, ForensicPayload } from './types.js';

export class HttpCaptureLayer {
  constructor(
    private evidenceStore: EvidenceStore,
    private custodyMetadata: CustodyMetadata,
  ) {}

  async wrapContext(context: BrowserContext, agentName: string): Promise<void> {
    await context.route('**/*', async (route: Route) => {
      const request = route.request();

      // Capture request
      const requestPayload: ForensicPayload = {
        httpMethod: request.method(),
        httpUrl: request.url(),
        httpHeaders: await request.allHeaders(),
        httpBody: request.postData() ?? undefined,
        description: `${request.method()} ${request.url()}`,
      };

      this.evidenceStore.record(agentName, 'http-request', requestPayload, this.custodyMetadata);

      const startTime = Date.now();

      try {
        // Continue the request
        const response = await route.fetch();
        const duration = Date.now() - startTime;
        const body = await response.text().catch(() => '[binary or empty]');

        // Capture response
        const responsePayload: ForensicPayload = {
          httpMethod: request.method(),
          httpUrl: request.url(),
          httpStatus: response.status(),
          httpResponseHeaders: response.headers(),
          httpResponseBody: body.slice(0, 50_000), // Cap at 50KB per response
          httpDurationMs: duration,
          description: `${response.status()} ${request.method()} ${request.url()} (${duration}ms)`,
        };

        this.evidenceStore.record(agentName, 'http-response', responsePayload, this.custodyMetadata);

        // Fulfill with the actual response
        await route.fulfill({
          status: response.status(),
          headers: response.headers(),
          body: await response.body(),
        });
      } catch (error) {
        // If fetch fails, continue normally
        await route.continue();
      }
    });
  }

  recordLLMCall(
    agentName: string,
    model: string,
    prompt: string,
    response: string,
    tokensIn: number,
    tokensOut: number,
  ): void {
    const payload: ForensicPayload = {
      llmModel: model,
      llmPromptHash: createHash('sha256').update(prompt).digest('hex'),
      llmResponseHash: createHash('sha256').update(response).digest('hex'),
      llmTokensIn: tokensIn,
      llmTokensOut: tokensOut,
      description: `LLM call to ${model} (${tokensIn}+${tokensOut} tokens)`,
    };

    this.evidenceStore.record(agentName, 'llm-call', payload, this.custodyMetadata);
  }

  recordExploitAttempt(agentName: string, endpoint: string, payload: string, success: boolean): void {
    const forensicPayload: ForensicPayload = {
      httpUrl: endpoint,
      httpBody: payload,
      description: `Exploit attempt on ${endpoint}: ${success ? 'SUCCESS' : 'FAILED'}`,
    };

    this.evidenceStore.record(
      agentName,
      success ? 'finding-confirmed' : 'exploit-attempt',
      forensicPayload,
      this.custodyMetadata,
    );
  }
}
