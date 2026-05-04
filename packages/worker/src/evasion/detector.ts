import type { DetectionSignal, DetectionType } from './types.js';

const DETECTION_PATTERNS: Record<DetectionType, RegExp[]> = {
  'waf-block': [
    /access denied/i,
    /forbidden/i,
    /blocked by/i,
    /web application firewall/i,
    /request blocked/i,
    /security policy/i,
  ],
  'rate-limit': [
    /rate limit/i,
    /too many requests/i,
    /throttl/i,
    /retry.after/i,
    /slow down/i,
  ],
  'captcha': [
    /captcha/i,
    /recaptcha/i,
    /hcaptcha/i,
    /challenge/i,
    /verify.*human/i,
    /turnstile/i,
  ],
  'ip-block': [
    /ip.*blocked/i,
    /banned/i,
    /blacklist/i,
    /your ip/i,
  ],
  'session-invalidation': [
    /session.*expired/i,
    /session.*invalid/i,
    /logged out/i,
    /re.?authenticate/i,
  ],
  'tarpit': [],
  'fingerprint-challenge': [
    /browser.*check/i,
    /checking your browser/i,
    /just a moment/i,
    /enable javascript/i,
  ],
};

const WAF_SIGNATURES: Record<string, RegExp[]> = {
  cloudflare: [/cloudflare/i, /cf-ray/i, /__cfduid/i],
  akamai: [/akamai/i, /akamaighost/i, /ak_bmsc/i],
  'aws-waf': [/awswaf/i, /x-amzn-waf/i],
  'mod-security': [/mod_security/i, /modsecurity/i],
  imperva: [/imperva/i, /incapsula/i, /visid_incap/i],
  f5: [/big-?ip/i, /f5/i, /ts[a-z0-9]{6,}/i],
  sucuri: [/sucuri/i, /cloudproxy/i],
  barracuda: [/barracuda/i, /barra_counter/i],
};

export class DetectionDetector {
  analyzeResponse(
    status: number,
    headers: Record<string, string>,
    body: string,
  ): DetectionSignal | null {
    // Status-based detection
    if (status === 403 || status === 429 || status === 503) {
      const detectionType = this.classifyByStatus(status, body);
      if (detectionType) {
        return {
          type: detectionType,
          timestamp: new Date().toISOString(),
          httpStatus: status,
          responseIndicators: this.extractIndicators(headers, body),
          requestThatTriggered: '',
          confidence: this.calculateConfidence(status, headers, body),
        };
      }
    }

    // Content-based detection (even on 200 responses)
    for (const [type, patterns] of Object.entries(DETECTION_PATTERNS)) {
      for (const pattern of patterns) {
        if (pattern.test(body)) {
          return {
            type: type as DetectionType,
            timestamp: new Date().toISOString(),
            httpStatus: status,
            responseIndicators: [pattern.source],
            requestThatTriggered: '',
            confidence: 0.7,
          };
        }
      }
    }

    return null;
  }

  identifyWAF(headers: Record<string, string>): string | null {
    const headerStr = JSON.stringify(headers).toLowerCase();

    for (const [waf, patterns] of Object.entries(WAF_SIGNATURES)) {
      for (const pattern of patterns) {
        if (pattern.test(headerStr)) {
          return waf;
        }
      }
    }

    // Check server header
    const server = headers['server'] ?? '';
    for (const [waf, patterns] of Object.entries(WAF_SIGNATURES)) {
      for (const pattern of patterns) {
        if (pattern.test(server)) {
          return waf;
        }
      }
    }

    return null;
  }

  private classifyByStatus(status: number, body: string): DetectionType | null {
    if (status === 429) return 'rate-limit';
    if (status === 403) {
      if (DETECTION_PATTERNS.captcha.some((p) => p.test(body))) return 'captcha';
      return 'waf-block';
    }
    if (status === 503) {
      if (DETECTION_PATTERNS['fingerprint-challenge'].some((p) => p.test(body))) return 'fingerprint-challenge';
      return 'waf-block';
    }
    return null;
  }

  private extractIndicators(headers: Record<string, string>, body: string): string[] {
    const indicators: string[] = [];

    const waf = this.identifyWAF(headers);
    if (waf) indicators.push(`WAF: ${waf}`);

    if (headers['retry-after']) indicators.push(`Retry-After: ${headers['retry-after']}`);
    if (headers['x-ratelimit-remaining']) indicators.push(`RateLimit-Remaining: ${headers['x-ratelimit-remaining']}`);

    return indicators;
  }

  private calculateConfidence(status: number, headers: Record<string, string>, body: string): number {
    let confidence = 0.5;
    if (status === 429) confidence = 0.95;
    if (status === 403 && this.identifyWAF(headers)) confidence = 0.9;
    if (DETECTION_PATTERNS.captcha.some((p) => p.test(body))) confidence = 0.95;
    return confidence;
  }
}
