import { proxyActivities } from '@temporalio/workflow';
import type { ScanActivities } from './activities/index.js';

const acts = proxyActivities<ScanActivities>({
  startToCloseTimeout: '2h',
  heartbeatTimeout: '60m',
});

export interface ScanInput {
  configPath: string;
  workspaceDir: string;
  resume: boolean;
}

export async function scanWorkflow(input: ScanInput): Promise<string> {
  // Phase 1: Pre-Recon (sequential)
  await acts.runPreRecon({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
    resume: input.resume,
  });

  // Phase 2: Recon + Counter-Deception (sequential)
  await acts.runRecon({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
    resume: input.resume,
  });

  // Phase 2.5: Counter-Deception Scan
  await acts.runDeceptionScan({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
  });

  // Phase 3 & 4: Vuln + Exploit agents (paired, parallel across categories)
  // Each exploit agent starts as soon as its corresponding vuln agent finishes.
  // No global sync barrier between phase 3 and 4.
  // Includes business-logic as a 6th category.
  const vulnExploitPairs = [
    { vuln: 'sqli', exploit: 'sqli' },
    { vuln: 'xss', exploit: 'xss' },
    { vuln: 'auth-bypass', exploit: 'auth-bypass' },
    { vuln: 'authz-bypass', exploit: 'authz-bypass' },
    { vuln: 'ssrf', exploit: 'ssrf' },
    { vuln: 'business-logic', exploit: 'business-logic' },
  ] as const;

  const pairPromises = vulnExploitPairs.map(async (pair) => {
    // Run vuln agent first
    const vulnResult = await acts.runVulnAgent({
      category: pair.vuln,
      configPath: input.configPath,
      workspaceDir: input.workspaceDir,
      resume: input.resume,
    });

    // Immediately start exploit agent when vuln agent finishes
    if (vulnResult.hasFindings) {
      await acts.runExploitAgent({
        category: pair.exploit,
        configPath: input.configPath,
        workspaceDir: input.workspaceDir,
        vulnQueuePath: vulnResult.queuePath,
        resume: input.resume,
      });
    }
  });

  await Promise.all(pairPromises);

  // Phase 3.5: Attack Chain Graph Analysis
  // Build directed graph from all findings, discover multi-step kill chains
  const chainResult = await acts.runChainAnalysis({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
  });

  // Execute highest-scoring attack chain if found
  if (chainResult.hasChain) {
    await acts.runChainExploit({
      configPath: input.configPath,
      workspaceDir: input.workspaceDir,
      chainPath: chainResult.chainPath,
    });
  }

  // Phase 4.5: Multi-Agent War Room
  // Three agents debate every finding to eliminate false positives
  const warRoomResult = await acts.runWarRoom({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
  });

  // Phase 4.7: Purple Team (Red x Blue)
  // 2 red agents (strategist + attacker) and 2 blue agents (defender + IR) talk
  // within their team and across teams, then a moderator synthesizes the conclusion.
  const purpleResult = await acts.runPurpleTeam({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
    warRoomVerdictsPath: warRoomResult.verdictsPath,
  });

  // Phase 5: Report Assembly (sequential)
  const reportPath = await acts.assembleReport({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
    warRoomVerdictsPath: warRoomResult.verdictsPath,
    purpleTeamReportPath: purpleResult.reportPath,
  });

  // Phase 5.5: Forensic Evidence Package
  await acts.buildForensicPackage({
    configPath: input.configPath,
    workspaceDir: input.workspaceDir,
  });

  return reportPath;
}
