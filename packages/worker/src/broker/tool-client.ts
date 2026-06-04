import { type BrokerResponse, type ToolRequest, verifyInvocationRecord } from '@shannon/tool-broker';

export interface ToolClientConfig {
  brokerUrl: string; // e.g. http://tool-broker:8443
  recordKey: string; // per-scan HMAC key; the broker signs InvocationRecords with the matching key
  fetchImpl?: typeof fetch; // injectable for tests
}

// Worker-side client for the tool-broker. The broker runs as a separate, less-trusted
// process; the worker therefore HMAC-VERIFIES the signed InvocationRecord in every
// response before acting on it or appending it to the forensic chain. A response whose
// record does not verify under our per-scan key is rejected outright.
export class ToolClient {
  constructor(private readonly cfg: ToolClientConfig) {}

  async invoke(request: ToolRequest): Promise<BrokerResponse> {
    const doFetch = this.cfg.fetchImpl ?? fetch;
    const res = await doFetch(`${this.cfg.brokerUrl}/tool`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    });
    if (!res.ok) {
      throw new Error(`tool-broker returned HTTP ${res.status}`);
    }
    const body = (await res.json()) as BrokerResponse;
    if (!verifyInvocationRecord(body.record, this.cfg.recordKey)) {
      throw new Error('tool-broker InvocationRecord failed HMAC verification — response rejected');
    }
    return body;
  }
}
