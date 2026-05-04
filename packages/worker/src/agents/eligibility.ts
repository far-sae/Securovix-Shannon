export interface VulnQueue {
  category: string;
  findings: Array<{
    id: string;
    type: string;
    severity: string;
  }>;
}

export class ExploitEligibilityChecker {
  isEligible(queue: VulnQueue): boolean {
    if (!queue.findings || queue.findings.length === 0) return false;
    // Only attempt exploitation if there are actionable findings
    return queue.findings.some((f) => f.type === 'potential' || f.type === 'confirmed');
  }
}
