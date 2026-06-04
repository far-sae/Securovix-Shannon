import type { Container } from '../../di/container.js';
import { brokerExploitActivity } from './broker-exploit.js';
import { chainAnalysisActivity } from './chain-analysis.js';
import { chainExploitActivity } from './chain-exploit.js';
import { deceptionScanActivity } from './deception-scan.js';
import { exploitAgentActivity } from './exploit-agents.js';
import { forensicPackageActivity } from './forensic-package.js';
import { preReconActivity } from './pre-recon.js';
import { purpleTeamActivity } from './purple-team.js';
import { reconActivity } from './recon.js';
import { reportActivity } from './report.js';
import { vulnAgentActivity } from './vuln-agents.js';
import { warRoomActivity } from './war-room.js';

export interface PreReconInput {
  configPath: string;
  workspaceDir: string;
  resume: boolean;
}

export interface ReconInput {
  configPath: string;
  workspaceDir: string;
  resume: boolean;
}

export interface DeceptionScanInput {
  configPath: string;
  workspaceDir: string;
}

export interface VulnAgentInput {
  category: string;
  configPath: string;
  workspaceDir: string;
  resume: boolean;
}

export interface VulnAgentOutput {
  hasFindings: boolean;
  queuePath: string;
  analysisPath: string;
}

export interface ExploitAgentInput {
  category: string;
  configPath: string;
  workspaceDir: string;
  vulnQueuePath: string;
  resume: boolean;
}

export interface ChainAnalysisInput {
  configPath: string;
  workspaceDir: string;
}

export interface ChainAnalysisOutput {
  hasChain: boolean;
  chainPath: string;
}

export interface ChainExploitInput {
  configPath: string;
  workspaceDir: string;
  chainPath: string;
}

export interface WarRoomInput {
  configPath: string;
  workspaceDir: string;
}

export interface WarRoomOutput {
  verdictsPath: string;
}

export interface PurpleTeamInput {
  configPath: string;
  workspaceDir: string;
  warRoomVerdictsPath?: string;
}

export interface PurpleTeamOutput {
  conclusionsPath: string;
  reportPath: string;
}

export interface ReportInput {
  configPath: string;
  workspaceDir: string;
  warRoomVerdictsPath?: string;
  purpleTeamReportPath?: string;
}

export interface ForensicPackageInput {
  configPath: string;
  workspaceDir: string;
}

export interface BrokerExploitInput {
  category: string;
  scopeToken: string; // signed scope-lock token from the CLI
  configPath: string;
  workspaceDir: string;
  scanId: string;
  wafVendor?: string;
}

export interface BrokerExploitOutput {
  skipped: boolean;
  findingsCount: number;
}

export interface ScanActivities {
  runPreRecon(input: PreReconInput): Promise<void>;
  runRecon(input: ReconInput): Promise<void>;
  runDeceptionScan(input: DeceptionScanInput): Promise<void>;
  runVulnAgent(input: VulnAgentInput): Promise<VulnAgentOutput>;
  runExploitAgent(input: ExploitAgentInput): Promise<void>;
  runChainAnalysis(input: ChainAnalysisInput): Promise<ChainAnalysisOutput>;
  runChainExploit(input: ChainExploitInput): Promise<void>;
  runWarRoom(input: WarRoomInput): Promise<WarRoomOutput>;
  runPurpleTeam(input: PurpleTeamInput): Promise<PurpleTeamOutput>;
  assembleReport(input: ReportInput): Promise<string>;
  buildForensicPackage(input: ForensicPackageInput): Promise<void>;
  runBrokerExploit(input: BrokerExploitInput): Promise<BrokerExploitOutput>;
}

export function createActivities(container: Container): ScanActivities {
  return {
    runPreRecon: (input) => preReconActivity(container, input),
    runRecon: (input) => reconActivity(container, input),
    runDeceptionScan: (input) => deceptionScanActivity(container, input),
    runVulnAgent: (input) => vulnAgentActivity(container, input),
    runExploitAgent: (input) => exploitAgentActivity(container, input),
    runChainAnalysis: (input) => chainAnalysisActivity(container, input),
    runChainExploit: (input) => chainExploitActivity(container, input),
    runWarRoom: (input) => warRoomActivity(container, input),
    runPurpleTeam: (input) => purpleTeamActivity(container, input),
    assembleReport: (input) => reportActivity(container, input),
    buildForensicPackage: (input) => forensicPackageActivity(container, input),
    runBrokerExploit: (input) => brokerExploitActivity(container, input),
  };
}
