// Strips high-confidence secret patterns before tool output enters any log,
// the forensic chain, or the LLM context. Conservative: only well-known shapes.
const PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g,
  /aws_secret_access_key\s*[=:]\s*[^\s'"]+/gi,
  /(?:bearer\s+)[A-Za-z0-9._-]{12,}/gi,
  /(authorization\s*:\s*)[^\s]+/gi,
  /\/security-credentials\/[^\s'"]*/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

export function redact(text: string): string {
  let out = text;
  for (const re of PATTERNS) {
    out = out.replace(re, (match, p1?: string) => (typeof p1 === 'string' ? `${p1}[REDACTED]` : '[REDACTED]'));
  }
  return out;
}
