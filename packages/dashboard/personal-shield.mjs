// Read-only personal threat triage. This module never opens links, invokes a model, executes content,
// or stores submitted text. Its output is explainable and deterministic so untrusted content cannot
// turn into instructions for Shannon.

const URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;
const SHORTENERS = new Set([
  'bit.ly',
  'buff.ly',
  'cutt.ly',
  'is.gd',
  'rebrand.ly',
  'shorturl.at',
  't.co',
  'tinyurl.com',
]);

function snippet(value, max = 120) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

function evidenceFor(text, pattern) {
  const match = text.match(pattern);
  if (!match) return null;
  const at = Math.max(0, Number(match.index || 0) - 32);
  return snippet(text.slice(at, at + 150));
}

function parsedUrls(message, supplied) {
  const values = [...String(message || '').matchAll(URL_RE)].map((match) => match[0]);
  if (String(supplied || '').trim()) values.unshift(String(supplied).trim());
  return [...new Set(values)].slice(0, 10).map((raw) => {
    try {
      const value = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
      return { raw, url: new URL(value) };
    } catch {
      return { raw, url: null };
    }
  });
}

export function analyzePersonalThreat({ message = '', link = '' } = {}) {
  const text = String(message || '').slice(0, 20_000);
  const findings = [];
  const seen = new Set();
  let score = 0;

  const add = ({ id, title, severity, weight, evidence, explanation }) => {
    if (seen.has(id)) return;
    seen.add(id);
    score += weight;
    findings.push({ id, title, severity, evidence: snippet(evidence), explanation });
  };

  const credentialEvidence = evidenceFor(
    text,
    /(?<!do not )(?<!never )(?:send|share|provide|enter|confirm|verify|reply with|paste|upload).{0,45}(?:password|passcode|one[- ]?time code|otp|mfa code|verification code|recovery code|seed phrase|private key|api key)|(?:password|passcode|one[- ]?time code|otp|mfa code|verification code|recovery code|seed phrase|private key|api key).{0,35}(?:is required|is needed|now|here|to continue|to unlock)/i,
  );
  if (credentialEvidence) {
    add({
      id: 'credential-request',
      title: 'Request for authentication or recovery secrets',
      severity: 'high',
      weight: 35,
      evidence: credentialEvidence,
      explanation: 'Legitimate support teams should not ask for passwords, MFA codes, recovery codes, seed phrases, private keys, or API keys.',
    });
  }

  const exfilEvidence = evidenceFor(
    text,
    /(?<!do not )(?<!never )(?:send|share|upload|paste|forward|reply with|provide).{0,45}(?:password|passcode|code|secret|token|key|document|wallet|bank details)/i,
  );
  if (exfilEvidence) {
    add({
      id: 'data-exfiltration',
      title: 'Instruction to disclose sensitive information',
      severity: 'critical',
      weight: 40,
      evidence: exfilEvidence,
      explanation: 'The message combines a disclosure action with sensitive information, a common account-takeover and data-theft pattern.',
    });
  }

  const urgency = /(?:act now|immediately|urgent|within \d+ (?:minutes?|hours?)|account (?:will be )?(?:closed|locked|suspended)|final warning|do not delay)/i.test(text);
  const payment = /(?:gift cards?|wire transfer|bank transfer|crypto(?:currency)?|bitcoin|wallet address|payment|invoice|refund|send money)/i.test(text);
  if (urgency && payment) {
    add({
      id: 'urgent-payment',
      title: 'Urgent or unusual payment pressure',
      severity: 'high',
      weight: 30,
      evidence: evidenceFor(text, /(?:act now|immediately|urgent|gift cards?|wire transfer|crypto(?:currency)?|send money)/i),
      explanation: 'Urgency combined with payment instructions is a strong social-engineering signal. Verify through a known contact method.',
    });
  }

  const impersonation = /(?:i am|this is|on behalf of|from).{0,35}(?:your boss|ceo|director|bank|support|microsoft|google|apple|police|tax|government)/i.test(text)
    || /(?:ceo|director|bank|support team|security team).{0,45}(?:urgent|confidential|secret|do not call|do not tell)/i.test(text);
  if (impersonation) {
    add({
      id: 'impersonation',
      title: 'Possible authority or support impersonation',
      severity: payment ? 'high' : 'medium',
      weight: payment ? 25 : 18,
      evidence: evidenceFor(text, /(?:boss|ceo|director|bank|support|microsoft|google|apple|police|tax|government)/i),
      explanation: 'The sender claims authority or trusted support status. Confirm the request using a phone number or account portal you already know.',
    });
  }

  const injectionEvidence = evidenceFor(
    text,
    /(?:ignore|disregard|override|forget).{0,35}(?:previous|prior|system|developer|security|instructions?|rules?|policy)|(?:reveal|print|repeat|show).{0,30}(?:system prompt|developer message|hidden instructions?)/i,
  );
  if (injectionEvidence) {
    add({
      id: 'prompt-injection',
      title: 'AI prompt-injection language',
      severity: 'high',
      weight: 35,
      evidence: injectionEvidence,
      explanation: 'The content attempts to override AI rules or reveal hidden instructions. Treat it as untrusted data and do not give it tool access.',
    });
  }

  const covertEvidence = evidenceFor(
    text,
    /(?:do not tell|hide this from|secretly|without (?:the )?user knowing|bypass (?:the )?(?:safety|security)|disable (?:the )?(?:guard|protection|filter))/i,
  );
  if (covertEvidence) {
    add({
      id: 'covert-action',
      title: 'Request for hidden or bypassed action',
      severity: 'high',
      weight: 28,
      evidence: covertEvidence,
      explanation: 'Requests to hide activity or bypass safeguards should never be executed by an assistant or trusted automation.',
    });
  }

  const attachmentEvidence = evidenceFor(text, /\.(?:exe|scr|lnk|iso|img|js|vbs|ps1|bat|cmd|msi|hta)(?:\b|[?#])/i);
  if (attachmentEvidence) {
    add({
      id: 'dangerous-attachment',
      title: 'Potentially dangerous attachment or executable',
      severity: 'high',
      weight: 35,
      evidence: attachmentEvidence,
      explanation: 'The content references a file type commonly used for malware delivery. Do not open it on a normal device.',
    });
  }

  const urls = parsedUrls(text, link);
  for (const item of urls) {
    if (!item.url) {
      add({
        id: 'invalid-link', title: 'Malformed link', severity: 'medium', weight: 15,
        evidence: item.raw, explanation: 'The submitted link could not be parsed safely. Do not open or repair it by guessing.',
      });
      continue;
    }
    const host = item.url.hostname.toLowerCase();
    if (item.url.protocol !== 'https:') {
      add({
        id: 'unencrypted-link', title: 'Link does not use HTTPS', severity: 'medium', weight: 12,
        evidence: item.url.href, explanation: 'An unencrypted link can expose or alter traffic and should not be used for sign-in or sensitive data.',
      });
    }
    if (item.url.username || item.url.password) {
      add({
        id: 'embedded-link-credentials', title: 'Link contains embedded credentials', severity: 'high', weight: 30,
        evidence: `${item.url.protocol}//***@${host}${item.url.pathname}`,
        explanation: 'User information before the @ sign can hide the real destination and is unsafe in an unsolicited link.',
      });
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(':')) {
      add({
        id: 'ip-address-link', title: 'Link uses a raw IP address', severity: 'medium', weight: 18,
        evidence: host, explanation: 'Unsolicited login or payment links rarely need a raw IP address; verify the destination independently.',
      });
    }
    if (host.includes('xn--')) {
      add({
        id: 'punycode-link', title: 'Internationalized/punycode hostname', severity: 'medium', weight: 18,
        evidence: host, explanation: 'Punycode may be legitimate, but it is also used for look-alike domains. Verify the brand domain manually.',
      });
    }
    if (SHORTENERS.has(host)) {
      add({
        id: 'shortened-link', title: 'Shortened destination hides the final site', severity: 'medium', weight: 16,
        evidence: host, explanation: 'The final destination is hidden. Do not open it until the sender and destination are independently verified.',
      });
    }
    if (host.split('.').length > 5) {
      add({
        id: 'deep-subdomain-link', title: 'Unusually deep hostname', severity: 'low', weight: 8,
        evidence: host, explanation: 'Long subdomain chains can be used to make an unrelated destination look trusted at a glance.',
      });
    }
  }

  if (payment && (impersonation || urgency)) {
    add({
      id: 'out-of-band-verification',
      title: 'Voice, video, or identity must be verified separately',
      severity: 'high',
      weight: 15,
      evidence: 'Payment or sensitive request combined with urgency/authority',
      explanation: 'AI-generated voice, video, and writing can imitate trusted people. Call them using a known number and use a pre-agreed verification phrase.',
    });
  }

  score = Math.min(100, score);
  const risk = score >= 70 ? 'critical' : score >= 45 ? 'high' : score >= 20 ? 'medium' : 'low';
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const actions = findings.length
    ? [
        'Do not click links, open attachments, reply, pay, or share codes from this message.',
        'Verify the sender through a separate contact method you already trust.',
        'If you already interacted, disconnect the affected session, change credentials from a clean device, enable MFA, and contact the real provider.',
      ]
    : [
        'No strong deterministic warning was found, but that does not prove the content is safe.',
        'Verify unexpected requests independently before sharing sensitive information or taking irreversible action.',
      ];

  return {
    risk,
    score,
    findings: findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]),
    actions,
    analyzedLinks: urls.length,
    safety: {
      engine: 'local-deterministic',
      openedLinks: false,
      executedContent: false,
      usedAiModel: false,
      storedSubmittedContent: false,
    },
  };
}
