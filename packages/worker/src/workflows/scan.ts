import { proxyActivities } from '@temporalio/workflow';
import type { ScanActivities } from './activities/index.js';
import { ACTIVE_VULN_CATEGORIES } from './categories.js';

const acts = proxyActivities<ScanActivities>({
  startToCloseTimeout: '2h',
  heartbeatTimeout: '60m',
});

// Broker-backed exploitation runs on a tighter clock than the 2h LLM-agent activities.
const brokerActs = proxyActivities<ScanActivities>({
  startToCloseTimeout: '10m',
  heartbeatTimeout: '2m',
});

export interface ScanInput {
  configPath: string;
  workspaceDir: string;
  resume: boolean;
  // Track B (opt-in): vuln classes to run through the tool-broker, plus the scope-lock
  // token the CLI signed at scan start. Omitted → broker phase is skipped entirely.
  brokerCategories?: string[];
  scopeToken?: string;
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

  // Phase 3 & 4: Vuln + Exploit agents (paired, parallel across categories).
  // Categories come from the single source of truth in categories.ts.
  const vulnExploitPairs = ACTIVE_VULN_CATEGORIES.map((c) => ({ vuln: c, exploit: c }));

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

  // Phase 3.4: Broker-backed exploitation (Track B) — opt-in. Each class runs the
  // recall → LLM-agent-via-broker → record + compliance loop. Skipped unless the CLI
  // supplied brokerCategories + a signed scopeToken.
  const scopeToken = input.scopeToken;
  if (scopeToken && input.brokerCategories && input.brokerCategories.length > 0) {
    await Promise.all(
      input.brokerCategories.map((category) =>
        brokerActs.runBrokerExploit({
          category,
          scopeToken,
          configPath: input.configPath,
          workspaceDir: input.workspaceDir,
          scanId: input.workspaceDir,
        }),
      ),
    );
  }

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
