import type Anthropic from '@anthropic-ai/sdk';
import type { FindingInput, MitreMapping } from './types.js';

// MITRE ATT&CK Enterprise Tactics
const MITRE_TACTICS: Record<string, { id: string; name: string }> = {
  'initial-access': { id: 'TA0001', name: 'Initial Access' },
  'execution': { id: 'TA0002', name: 'Execution' },
  'persistence': { id: 'TA0003', name: 'Persistence' },
  'privilege-escalation': { id: 'TA0004', name: 'Privilege Escalation' },
  'defense-evasion': { id: 'TA0005', name: 'Defense Evasion' },
  'credential-access': { id: 'TA0006', name: 'Credential Access' },
  'discovery': { id: 'TA0007', name: 'Discovery' },
  'lateral-movement': { id: 'TA0008', name: 'Lateral Movement' },
  'collection': { id: 'TA0009', name: 'Collection' },
  'exfiltration': { id: 'TA0010', name: 'Exfiltration' },
  'impact': { id: 'TA0040', name: 'Impact' },
};

// Common techniques by vulnerability category
const CATEGORY_TECHNIQUES: Record<string, Array<{ id: string; name: string; tactic: string }>> = {
  sqli: [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access' },
    { id: 'T1005', name: 'Data from Local System', tactic: 'collection' },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'credential-access' },
  ],
  xss: [
    { id: 'T1189', name: 'Drive-by Compromise', tactic: 'initial-access' },
    { id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'credential-access' },
    { id: 'T1185', name: 'Browser Session Hijacking', tactic: 'collection' },
  ],
  ssrf: [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access' },
    { id: 'T1552', name: 'Unsecured Credentials', tactic: 'credential-access' },
    { id: 'T1046', name: 'Network Service Discovery', tactic: 'discovery' },
  ],
  'auth-bypass': [
    { id: 'T1078', name: 'Valid Accounts', tactic: 'initial-access' },
    { id: 'T1550', name: 'Use Alternate Authentication Material', tactic: 'defense-evasion' },
  ],
  'authz-bypass': [
    { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'privilege-escalation' },
    { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'privilege-escalation' },
  ],
  'business-logic': [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access' },
    { id: 'T1565', name: 'Data Manipulation', tactic: 'impact' },
  ],
};

export class AdversarySimAgent {
  constructor(
    private client: Anthropic,
    private model: string,
  ) {}

  async analyze(finding: FindingInput, debateHistory: string): Promise<{ assessment: string; mappings: MitreMapping[] }> {
    // First, get static MITRE mappings
    const staticMappings = this.getStaticMappings(finding);

    // Then, use LLM for deeper analysis
    const prompt = [
      'You are an Adversary Simulation specialist in a penetration testing war room.',
      'Your expertise is mapping vulnerabilities to real-world threat actor TTPs (Tactics, Techniques, and Procedures).',
      '',
      '## Your Responsibilities',
      '- Map findings to MITRE ATT&CK framework tactics and techniques',
      '- Identify which real-world APT groups use similar techniques',
      '- Assess how a sophisticated attacker would chain this with other findings',
      '- Evaluate the finding from an adversary perspective',
      '',
      '## Finding Under Review',
      `ID: ${finding.id}`,
      `Category: ${finding.category}`,
      `Endpoint: ${finding.endpoint}`,
      `Severity: ${finding.severity}`,
      `Description: ${finding.description}`,
      `Evidence: ${finding.evidence}`,
      '',
      '## Initial MITRE Mappings',
      ...staticMappings.map((m) => `- ${m.tacticId} (${m.tacticName}) / ${m.techniqueId} (${m.techniqueName})`),
      '',
      debateHistory ? `## Previous Discussion\n${debateHistory}\n` : '',
      '',
      '## Your Analysis',
      'Provide:',
      '1. Confirm or adjust the MITRE ATT&CK mappings',
      '2. Which APT groups (if any) use similar TTPs',
      '3. How would a nation-state actor leverage this finding',
      '4. Kill chain position: where does this sit in a full attack?',
      '5. Risk amplification: does this finding amplify other vulnerabilities?',
    ].join('\n');

    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });

    const assessment = response.content
      .filter((b) => b.type === 'text')
      .map((b) => b.text)
      .join('\n');

    return { assessment, mappings: staticMappings };
  }

  private getStaticMappings(finding: FindingInput): MitreMapping[] {
    const techniques = CATEGORY_TECHNIQUES[finding.category] ?? [];

    return techniques.map((tech) => {
      const tactic = MITRE_TACTICS[tech.tactic];
      return {
        tacticId: tactic?.id ?? 'TA0001',
        tacticName: tactic?.name ?? 'Unknown',
        techniqueId: tech.id,
        techniqueName: tech.name,
        confidence: 0.8,
      };
    });
  }
}
