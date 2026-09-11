// llm-compliance.mjs — OWASP GenAI / LLM Top 10 (2025) compliance framework for Shannon.
//
// A brand-new compliance surface alongside the existing OWASP Web Top 10 / CWE / MITRE mapping.
// The engine's COMPLIANCE table mirrors these entries so reports, SARIF, and the dashboard carry
// LLM-layer findings with correct standards mapping.

export const OWASP_LLM_TOP10 = {
  LLM01: 'Prompt Injection',
  LLM02: 'Sensitive Information Disclosure',
  LLM03: 'Supply Chain',
  LLM04: 'Data and Model Poisoning',
  LLM05: 'Improper Output Handling',
  LLM06: 'Excessive Agency',
  LLM07: 'System Prompt Leakage',
  LLM08: 'Vector and Embedding Weaknesses',
  LLM09: 'Misinformation',
  LLM10: 'Unbounded Consumption',
};

// Detection classes this module introduces → standards mapping.
export const LLM_COMPLIANCE = {
  'llm-prompt-injection': {
    owasp: 'LLM01:2025-Prompt Injection',
    cwe: 'CWE-1427',
    mitre: ['TA0001', 'TA0002'],
  },
  'llm-indirect-injection': {
    owasp: 'LLM01:2025-Prompt Injection (Indirect / 2nd-order)',
    cwe: 'CWE-1427',
    mitre: ['TA0001', 'TA0002', 'TA0003'],
  },
  'llm-system-prompt-leak': {
    owasp: 'LLM07:2025-System Prompt Leakage',
    cwe: 'CWE-1427',
    mitre: ['TA0007'],
  },
  'llm-sensitive-disclosure': {
    owasp: 'LLM02:2025-Sensitive Information Disclosure',
    cwe: 'CWE-200',
    mitre: ['TA0007', 'TA0009'],
  },
  'llm-excessive-agency': {
    owasp: 'LLM06:2025-Excessive Agency',
    cwe: 'CWE-250',
    mitre: ['TA0002', 'TA0004'],
  },
};

export function mapLlmFinding(cls) {
  return LLM_COMPLIANCE[cls] || null;
}

// True for any class this module owns (used by the engine to route standards mapping).
export function isLlmClass(cls) {
  return Object.hasOwn(LLM_COMPLIANCE, cls);
}
