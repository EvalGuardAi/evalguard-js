export { EvalGuard, EvalGuardError, SDK_VERSION } from "./client";
export type { EvalGuardConfig, VersionPolicyResult, IntentClassification, ShadowAiDetection, ShadowAiDetectionsResult } from "./client";
// Data-boundary façade (G11) wire types (core DataBoundaryPolicy/Decision come via `export type * from "@evalguard/core"`).
export type { DataBoundaryPolicyRecord, DataBoundaryEvalDecision } from "./client";

// Eval types
export type {
  EvalParams,
  EvalRun,
  CaseResult,
  EvalResult,
  CompareEvalsParams,
  EvalComparison,
  EvalComparisonRun,
  EvalComparisonCase,
} from "./client";

// Imperative (Weave-style) EvaluationLogger — record predictions/scores against
// a live run without a full declarative eval() config.
export { EvaluationLogger } from "./eval-logger";
export type {
  EvalLoggerParams,
  EvalLoggerSummary,
  PredictionRow,
  EvalRunStatus,
  BoundRequest,
} from "./eval-logger";

// Security scan types
export type {
  SecurityScanParams,
  Severity,
  SecurityFinding,
  SecurityScanResult,
  ScanSummary,
} from "./client";

// Data-quality + red-team-planning types
export type {
  DatasetHealthParams,
  DatasetHealthResult,
  RedTeamPlanParams,
  RedTeamPlanResult,
} from "./client";

// RAG ingest types
export type { RagIngestParams, RagIngestResult, RagIngestChunk } from "./client";

// Committed-secret detection types (G10)
export type {
  SecretScanParams,
  SecretScanFinding,
  SecretScanResult,
} from "./client";

// Trace types
export type { TraceParams } from "./client";

// Scorer & plugin types
export type { Scorer, Plugin } from "./client";

// Firewall types
export type { FirewallRule, FirewallCheckParams, FirewallResult, FirewallSensitivity } from "./client";

// Visual-workflow, agent-observability, guardrails, chat, embedding, retrieval,
// trace-curation/export/import/aggregate, code-eval, and MCP-invoke wire types
// for the runtime methods added in the 2026-06-29 SDK/CLI parity pass.
export type {
  WorkflowSummary,
  WorkflowRecord,
  CreateWorkflowParams,
  WorkflowRunRecord,
  AgentSummary,
  AgentListResult,
  AgentTraceStep,
  CreateAgentParams,
  CreateAgentResult,
  RunGuardrailsParams,
  GuardrailsCheckResult,
  ChatCompletionMessage,
  ChatCompletionsParams,
  ChatCompletionsResult,
  StoreEmbeddingParams,
  StoredEmbeddingRecord,
  FindSimilarEmbeddingsParams,
  EmbeddingSimilarityHit,
  RerankProvider,
  RerankParams,
  RerankResultItem,
  RerankResult,
  HybridRetrievalDocument,
  HybridRetrievalParams,
  HybridRetrievalResult,
  CorpusIntegrityDocument,
  CorpusIntegrityParams,
  AnalyzeTraceSpansParams,
  TraceToDatasetParams,
  TraceToDatasetResult,
  TraceImportSourcePlatform,
  ImportTracesParams,
  ImportTracesResult,
  AggregateTracesParams,
  AggregateTracesResult,
  EvalCodeParams,
  EvalCodeScorerResult,
  EvalCodeResult,
  McpInvokeParams,
  McpInvokeResult,
} from "./client";

// Firewall advanced-rails types (re-exported from @evalguard/core via client)
export type {
  FirewallEngineConfig,
  AdvancedRailsConfig,
  DetectionResult,
} from "./client";

// Gateway routing-config + router-aware chat types
export type {
  GatewayRoutingStrategy,
  GatewayRoutingProvider,
  GatewayRoutingConfig,
  ChatMessage,
  GatewayChatResponse,
} from "./client";

// RAG AutoML types
export type {
  RagAutoMLLeaderboardEntry,
  RagAutoMLStudyResult,
} from "./client";

// Decision-BOM types
export type { DecisionBOMResponse } from "./client";

// FinOps cost export types
export type { FinOpsCostExportFormat } from "./client";

// Agent-tool builder types (headline agent-builder feature)
export type {
  AgentTool,
  AgentToolParameters,
  AgentToolRest,
  AgentToolCode,
  AgentToolMcp,
  AgentToolTestResult,
} from "./client";

// Abuse-report (trust-&-safety intake) types
export type {
  AbuseReport,
  AbuseReportCategory,
  AbuseReportStatus,
  AbuseReportTriage,
} from "./client";

// Agent-deployment (publish workflow as chat widget) types
export type {
  AgentDeployment,
  AgentDeploymentChannel,
  AgentDeploymentStatus,
} from "./client";

// Decision-BOM signature verification — independently verify a fetched BOM
// client-side (no server roundtrip) using the embedded public key.
export { verifyDecisionBOM, signDecisionBOM, canonicalize } from "@evalguard/core";
export type { SignedDecisionBOM, DecisionBOM, VerifyDecisionBOMResult } from "@evalguard/core";

// Benchmark types
export type { BenchmarkParams, BenchmarkResult } from "./client";

// Compliance types
export type { ComplianceReportParams, ComplianceReport } from "./client";

// Drift types
export type { DriftDetectParams, DriftReport } from "./client";

// Continuous SBOM monitoring types (G1)
export type {
  SbomMonitorInput,
  SbomMonitorRecord,
  SbomSnapshotSummary,
  SbomMonitorAlertableCve,
  SbomMonitorRunResult,
} from "./client";

// Idempotent issue sync types (G5)
export type {
  IssueSyncFindingInput,
  IssueSyncInput,
  IssueSyncResponse,
} from "./client";

export type * from "@evalguard/core";

// Tracing
export {
  traceable,
  traced,
  configureTracing,
  getCurrentSpan,
  getCurrentTraceId,
  getTraceIdentity,
  flushTraces,
} from "./tracing";
export type { TraceSpan, TraceableOptions, TracingConfig, TraceIdentity } from "./tracing";

// Vercel AI SDK auto-wrapper — one-line instrumentation for users of the `ai` package
export { wrapAISDK, configureVercelAI } from "@evalguard/core";
export type {
  AISDKFunctions,
  AISDKSpan,
  WrapAISDKOptions,
} from "@evalguard/core";

// Programmatic plugin / strategy / scorer registration — closes the
// Promptfoo gap (custom redteam plugins / graders defined in user code).
export {
  definePlugin,
  defineStrategy,
  defineScorer,
  ExtensionRegistry,
  runCustomScan,
} from "./extensions";
export type {
  CustomPlugin,
  CustomStrategy,
  CustomScorer,
  PluginProbe,
  GradeArgs,
  GradeResult,
  CustomScanArgs,
  CustomScanResult,
} from "./extensions";

// Vitest plugin
export {
  EvalGuardReporter,
  evalguardPlugin,
  evalguardTest,
  expectScore,
} from "./vitest";
export type { EvalGuardVitestConfig } from "./vitest";
