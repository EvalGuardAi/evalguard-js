export { EvalGuard, EvalGuardError, SDK_VERSION } from "./client";
// Fail-closed response validation. Every verdict-returning method raises
// `EvalGuardError { code: INDETERMINATE_VERDICT_CODE }` when the 2xx body
// carries no usable verdict — it is never resolved as "allowed". Callers that
// want to distinguish "the control could not run" from a genuine API error
// match on this code. See the "Indeterminate verdicts" block in client.ts.
export { INDETERMINATE_VERDICT_CODE, GUARDRAIL_ACTIONS } from "./client";
// The MCP gateway's 2xx decision vocabulary (mcpInvoke), and the code
// assertVersionAllowed() throws when the org's client-version policy could not
// be READ — distinguishable from a genuine pin violation.
export { MCP_INVOKE_DECISIONS, VERSION_POLICY_INDETERMINATE_CODE } from "./client";
export type { EvalGuardConfig, VersionPolicyResult, IntentClassification, ShadowAiDetection, ShadowAiDetectionsResult } from "./client";
// Data-boundary façade (G11) wire types (core DataBoundaryPolicy/Decision come via `export type * from "@evalguard/core"`).
export type { DataBoundaryPolicyRecord, DataBoundaryEvalDecision } from "./client";
// Agent memory-governance policy (Wave 3) wire type (core MemoryGovernanceMode/
// MemoryGovernanceConfig come via `export type * from "@evalguard/core"`).
export type { MemoryGovernancePolicyRecord } from "./client";
// Gateway guardrail-config (Wave 2) CRUD types + the local-vendor value array /
// guard so callers can model the local-vs-vendor secretRef rule (core
// GuardrailFlagAction comes via `export type * from "@evalguard/core"`).
export type {
  GuardrailConfigRecord,
  UpsertGuardrailConfigParams,
  LocalGuardrailVendor,
} from "./client";
export { LOCAL_GUARDRAIL_VENDORS, isLocalGuardrailVendor } from "./client";

// Eval types
export type {
  EvalParams,
  EvalRun,
  CaseResult,
  EvalResult,
  EvalStartedRun,
  EvalRunCaseResult,
  EvalRunSummary,
  EvalRunDetail,
  CompareEvalsParams,
  EvalComparison,
  EvalComparisonRun,
  EvalComparisonCase,
} from "./client";

// Imperative EvaluationLogger — record predictions/scores against
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
  SecurityScanStartedRun,
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
  GuardrailsReason,
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

// ── Typed prompt artifacts (Phase 1) ──────────────────────────────────────
// A prompt version is a first-class TYPED artifact: a `PromptConfig`
// (model + the standard LLM generation parameters + tools), a
// structured `PromptTemplate` (completion string or ordered ChatTemplate), and
// a portable `.prompt` file format. The *types* already reach SDK consumers via
// `export type *` above; the runtime helpers and enum VALUE arrays need
// explicit VALUE re-exports so callers can build, validate, render and
// (de)serialize a prompt's identity from `@evalguard/sdk` without a second
// import of `@evalguard/core`.
export {
  MODEL_ENDPOINT_VALUES,
  MODEL_PROVIDER_VALUES,
  TEMPLATE_LANGUAGE_VALUES,
  OPENAI_REASONING_EFFORT_VALUES,
  RESPONSE_FORMAT_TYPE_VALUES,
  CHAT_ROLE_VALUES,
  validatePromptConfig,
  isChatTemplate,
  extractTemplateVariables,
  validateTemplateInputs,
  renderStringTemplate,
  renderChatTemplate,
  renderPromptTemplate,
  MissingTemplateInputError,
  // NOTE: `findUnsupportedTemplateSyntax` / `UnsupportedTemplateSyntaxError`
  // (strict rendering now refuses jinja `{% … %}` / `{# … #}` instead of
  // shipping the raw tag to the provider) are reachable via `@evalguard/core`.
  // They are not re-exported here yet because this package typechecks against
  // core's built `dist/`, which has to be rebuilt first.
  serializePromptFile,
  parsePromptFile,
  promptFileFrom,
} from "@evalguard/core";

// ── Named environments + managed Tools (Phase 2) ──────────────────────────
// Arbitrary named deployment environments (replacing hardcoded staging/prod)
// and a managed, versioned Tool system with deployment + env-vars. The *types*
// (Environment, ToolConfig, ToolEnvironmentVariable, …) reach SDK consumers via
// `export type *` above; the runtime helpers and value arrays need explicit
// value re-exports.
export {
  ENVIRONMENT_TAG_VALUES,
  SEEDED_ENVIRONMENTS,
  validateToolConfig,
} from "@evalguard/core";

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

// ── Tracing + security decorators (Phase 3) ───────────────────────────────
// Sugar over the tracing substrate (`traceable`) and the core firewall
// (`guard`/`guardOutput`): `flow`/`prompt`/`tool` span wrappers
// (+ `@withFlow`/`@withPrompt`/`@withTool`/`@withTrace` method decorators) and
// the `@guard`/`withGuard` firewall decorator that gates a call's inputs +
// outputs in one line.
export {
  flow,
  prompt,
  tool,
  guard,
  GuardBlockedError,
  EG_FILE_TYPE_ATTR,
  withFlow,
  withPrompt,
  withTool,
  withTrace,
  withGuard,
} from "./decorators";
export type {
  SpanFileType,
  SpanDecoratorOptions,
  GuardPolicy,
  GuardPhase,
  GuardViolationEvent,
  GuardOptions,
} from "./decorators";

// Vercel AI SDK auto-wrapper — one-line instrumentation for users of the `ai` package
export { wrapAISDK, configureVercelAI } from "@evalguard/core";
export type {
  AISDKFunctions,
  AISDKSpan,
  WrapAISDKOptions,
} from "@evalguard/core";

// Programmatic plugin / strategy / scorer registration — custom redteam
// plugins / graders defined in user code, without forking the monorepo.
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

// Sandbox awareness. Detects a NemoClaw/OpenClaw sandbox and reads its egress
// policy, so a blocked host is reported as a one-line YAML fix instead of an
// undifferentiated `fetch failed`. Advisory only — nothing here throws or
// blocks a call. Held identical to `@evalguard/nemoclaw`'s copy by
// scripts/duplicated-source-drift-check.mjs.
export {
  detectSandbox,
  isNemoClawEnv,
  readPolicyFileRaw,
  readSandboxPolicy,
  isHostAllowedByPolicy,
  isEvalGuardAllowed,
  diagnoseSandboxEgress,
} from "./sandbox";
export type { SandboxInfo, NemoClawPolicy, SandboxEgressDiagnosis } from "./sandbox";
