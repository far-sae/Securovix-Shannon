import { ExploitEligibilityChecker } from '../agents/eligibility.js';
import { AgentOrchestrator } from '../agents/orchestrator.js';
import { ChainScorer } from '../attack-graph/chain-scorer.js';
import { AttackGraph } from '../attack-graph/graph.js';
import { CircuitBreaker } from '../broker/circuit-breaker.js';
import { ToolClient } from '../broker/tool-client.js';
import { SchemaParser } from '../business-logic/schema-parser.js';
import { StateMachineBuilder } from '../business-logic/state-machine.js';
import { ConfigLoader } from '../config/loader.js';
import { DeceptionClassifier } from '../counter-deception/deception-classifier.js';
import { DeceptionFingerprinter } from '../counter-deception/fingerprinter.js';
import { DetectionDetector } from '../evasion/detector.js';
import { EvasionMiddleware } from '../evasion/http-middleware.js';
import { EvasionStrategyEngine } from '../evasion/strategy-engine.js';
import { EvidenceStore } from '../forensic/evidence-store.js';
import type { HttpCaptureLayer } from '../forensic/http-capture.js';
import type { CustodyMetadata } from '../forensic/types.js';
import { KnowledgeStore } from '../knowledge/knowledge-store.js';
import { LLMClientFactory } from '../llm/client.js';
import type { CheckpointPlugin, FindingsPlugin, ReportPlugin } from '../plugins/interfaces.js';
import { NoopCheckpointPlugin, NoopFindingsPlugin, NoopReportPlugin } from '../plugins/noop.js';
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
  httpCaptureLayer?: HttpCaptureLayer;
  custodyMetadata?: CustodyMetadata;

  // Module 6: Adaptive Evasion
  evasionEngine: EvasionStrategyEngine;
  detectionDetector: DetectionDetector;
  evasionMiddleware: EvasionMiddleware;

  // Module 7: Tool Broker (Track B) — client present only when BROKER_URL is set.
  toolClient?: ToolClient;
  brokerBreaker: CircuitBreaker;

  // Module 8: Learning Brain (Track A) — present only with a workspace.
  knowledgeStore?: KnowledgeStore;
}

export function createContainer(workspaceDir?: string): Container {
  const configLoader = new ConfigLoader();
  const llmClientFactory = new LLMClientFactory();
  const agentOrchestrator = new AgentOrchestrator(llmClientFactory);
  const exploitChecker = new ExploitEligibilityChecker();

  // Forensic evidence
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

  // Tool broker (Track B): breaker is always present; the client is wired only when a
  // BROKER_URL is configured, so non-broker scans (and tests) build cleanly without it.
  const brokerBreaker = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 30_000 });
  const brokerUrl = process.env.BROKER_URL;
  const toolClient = brokerUrl
    ? new ToolClient({ brokerUrl, recordKey: process.env.SHANNON_BROKER_RECORD_KEY ?? '' })
    : undefined;

  // Learning Brain (Track A): cross-scan knowledge, persisted in the workspace.
  const knowledgeStore = workspaceDir ? new KnowledgeStore(workspaceDir) : undefined;

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
    // Module 6: Adaptive Evasion
    evasionEngine,
    detectionDetector,
    evasionMiddleware,

    // Module 7: Tool Broker
    toolClient,
    brokerBreaker,

    // Module 8: Learning Brain
    knowledgeStore,
  };
}
