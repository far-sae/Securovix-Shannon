import type { BrokerResponse, ToolRequest } from '@shannon/tool-broker';
import type { CircuitBreaker } from './circuit-breaker.js';
import type { ToolClient } from './tool-client.js';

export interface BrokerInvokeDeps {
  toolClient: ToolClient;
  breaker: CircuitBreaker;
}

export type BrokerInvokeOutcome =
  | { degraded: true } // circuit open → caller should fall back to the LLM+Playwright path
  | { degraded: false; response: BrokerResponse };

// Invokes a broker tool through the circuit breaker. A returned response — even a
// scope/budget *denial* — counts as success for the breaker (the broker is reachable);
// only a thrown error (HTTP failure, HMAC mismatch) trips it toward the degraded state.
export async function brokerInvoke(deps: BrokerInvokeDeps, request: ToolRequest): Promise<BrokerInvokeOutcome> {
  if (!deps.breaker.canProceed()) {
    return { degraded: true };
  }
  try {
    const response = await deps.toolClient.invoke(request);
    deps.breaker.recordSuccess();
    return { degraded: false, response };
  } catch (e) {
    deps.breaker.recordFailure();
    throw e;
  }
}
