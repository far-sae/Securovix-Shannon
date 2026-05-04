import { ConfigLoader } from '../config/loader.js';
import { LLMClientFactory } from '../llm/client.js';
import { AgentOrchestrator } from '../agents/orchestrator.js';
import { ExploitEligibilityChecker } from '../agents/eligibility.js';
import type { CheckpointPlugin, FindingsPlugin, ReportPlugin } from '../plugins/interfaces.js';
import { NoopCheckpointPlugin, NoopFindingsPlugin, NoopReportPlugin } from '../plugins/noop.js';
import { EvidenceStore } from '../forensic/evidence-store.js';
import { EvidenceChainHasher } from '../forensic/hasher.js';
import { HttpCaptureLayer } from '../forensic/http-capture.js';
import type { CustodyMetadata } from '../forensic/types.js';
import { EvasionStrategyEngine } from '../evasion/strategy-engine.js';
import { DetectionDetector } from '../evasion/detector.js';
import { EvasionMiddleware } from '../evasion/http-middleware.js';
import { AttackGraph } from '../attack-graph/graph.js';
import { ChainScorer } from '../attack-graph/chain-scorer.js';
import { DeceptionFingerprinter } from '../counter-deception/fingerprinter.js';
import { DeceptionClassifier } from '../counter-deception/deception-classifier.js';
import { SchemaParser } from '../business-logic/schema-parser.js';
import { StateMachineBuilder } from '../business-logic/state-machine.js';
import { WarRoomModerator } from '../war-room/moderator.js';

export interface Container {
  // Core
  configLoader: ConfigLoader;
  llmClientFactory: LLMClientFactory;
  agentOrchestrator: AgentOrchestrator;
  exploitChecker: ExploitEligibilityChecker;

  // Plugins
  checkpointPlugin: CheckpointPlugin;
  findingsPlugin: FindingsPlugin;
  reportPlugin: ReportPlugin;

  // Module 1: Attack Chain Graph
  attackGraph: AttackGraph;
  chainScorer: ChainScorer;

  // Module 2: Counter-Deception
  deceptionFingerprinter: DeceptionFingerprinter;
  deceptionClassifier: DeceptionClassifier;

  // Module 3: Business Logic
  schemaParser: SchemaParser;
  stateMachineBuilder: StateMachineBuilder;

  // Module 4: War Room
  warRoomModerator: WarRoomModerator;

  // Module 5: Forensic Evidence
  evidenceStore?: EvidenceStore;
  evidenceHasher: EvidenceChainHasher;
  httpCaptureLayer?: HttpCaptureLayer;
  custodyMetadata?: CustodyMetadata;

  // Module 6: Adaptive Evasion
  evasionEngine: EvasionStrategyEngine;
  detectionDetector: DetectionDetector;
  evasionMiddleware: EvasionMiddleware;
}

export function createContainer(workspaceDir?: string): Container {
  const configLoader = new ConfigLoader();
  const llmClientFactory = new LLMClientFactory();
  const agentOrchestrator = new AgentOrchestrator(llmClientFactory);
  const exploitChecker = new ExploitEligibilityChecker();

  // Forensic evidence
  const evidenceHasher = new EvidenceChainHasher();
  const evidenceStore = workspaceDir ? new EvidenceStore(workspaceDir) : undefined;

  // Evasion
  const targetHost = process.env.SHANNON_TARGET ?? 'unknown';
  const detectionDetector = new DetectionDetector();
  const evasionEngine = new EvasionStrategyEngine(targetHost);
  const evasionMiddleware = new EvasionMiddleware(evasionEngine, detectionDetector, evidenceStore);

  // Restore evasion profile if resuming
  if (workspaceDir) {
    evasionEngine.restoreProfile(workspaceDir);
  }

  return {
    // Core
    configLoader,
    llmClientFactory,
    agentOrchestrator,
    exploitChecker,

    // Plugins
    checkpointPlugin: new NoopCheckpointPlugin(),
    findingsPlugin: new NoopFindingsPlugin(),
    reportPlugin: new NoopReportPlugin(),

    // Module 1: Attack Chain Graph
    attackGraph: new AttackGraph(),
    chainScorer: new ChainScorer(llmClientFactory),

    // Module 2: Counter-Deception
    deceptionFingerprinter: new DeceptionFingerprinter(),
    deceptionClassifier: new DeceptionClassifier(),

    // Module 3: Business Logic
    schemaParser: new SchemaParser(),
    stateMachineBuilder: new StateMachineBuilder(),

    // Module 4: War Room
    warRoomModerator: new WarRoomModerator(llmClientFactory),

    // Module 5: Forensic Evidence
    evidenceStore,
    evidenceHasher,

    // Module 6: Adaptive Evasion
    evasionEngine,
    detectionDetector,
    evasionMiddleware,
  };
}
