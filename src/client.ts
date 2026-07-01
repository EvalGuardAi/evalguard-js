import { ExtensionRegistry } from "./extensions";
import { SDK_VERSION } from "./version";
import { EvaluationLogger } from "./eval-logger";
import type { EvalLoggerParams } from "./eval-logger";
import type {
  FirewallEngineConfig,
  AdvancedRailsConfig,
  DetectionResult,
} from "@evalguard/core";

// Re-export the core firewall types so SDK consumers can import them from
// @evalguard/sdk directly (they're already re-exported via `export type *`
// in index.ts, but naming them here keeps the helper signatures readable).
export type { FirewallEngineConfig, AdvancedRailsConfig, DetectionResult };

// ── Typed errors ──────────────────────────────────────────────────────

/**
 * The single error type thrown by every transport call (`request` /
 * `requestText`). Lets a consumer cleanly distinguish a NETWORK failure
 * (no server / DNS / connection refused — the raw `TypeError: fetch failed`
 * that used to escape uncaught) from an HTTP API error, without string-matching
 * the message.
 *
 *   try {
 *     await client.eval(...);
 *   } catch (err) {
 *     if (err instanceof EvalGuardError) {
 *       if (err.code === "NETWORK_ERROR") retryLater();
 *       else if (err.status === 401) reauth();
 *     }
 *   }
 *
 * `code` is a stable machine token (`"NETWORK_ERROR"`, `"HTTP_ERROR"`, or a
 * per-status `"HTTP_<status>"`). `status` is the HTTP status when the failure
 * was an HTTP response. `cause` carries the underlying error (e.g. the original
 * fetch `TypeError`) for diagnostics.
 */
export class EvalGuardError extends Error {
  /** Stable machine-readable code (e.g. "NETWORK_ERROR", "HTTP_ERROR", "HTTP_401"). */
  readonly code: string;
  /** HTTP status code, when the failure originated from an HTTP response. */
  readonly status?: number;
  /** The underlying error (original fetch TypeError, JSON parse error, etc.). */
  readonly cause?: unknown;
  /** Server-provided request id (from the {success:false,error:{requestId}} envelope), for support correlation. */
  readonly requestId?: string;

  constructor(message: string, options: { code: string; status?: number; cause?: unknown; requestId?: string }) {
    // Pass cause through Error's standard options bag too, so native tooling
    // (Node's util.inspect, error.cause) sees it; we also expose it as a typed
    // own-property for stable cross-runtime access.
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = "EvalGuardError";
    this.code = options.code;
    this.status = options.status;
    this.cause = options.cause;
    this.requestId = options.requestId;
    // Restore the prototype chain so `instanceof EvalGuardError` holds even
    // when the class is transpiled to ES5-target output.
    Object.setPrototypeOf(this, EvalGuardError.prototype);
  }
}

// ── Idempotency ───────────────────────────────────────────────────────

/**
 * One random UUID per logical request, reused across retries so a transient
 * 5xx/network blip dedups server-side instead of creating duplicate
 * scans/runs. Mirrors `newTraceId` in @evalguard/wrapper-core (same
 * crypto.randomUUID strategy) without adding a published-package dependency
 * edge to this transport client. Web Crypto when available; a non-crypto
 * fallback for older runtimes — the value is a dedup join key, not a secret.
 */
function newIdempotencyKey(): string {
  const cryptoAny = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (cryptoAny?.randomUUID) return cryptoAny.randomUUID();
  const r = () => Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0");
  return `${r()}${r()}-${r().slice(0, 4)}-4${r().slice(0, 3)}-${r().slice(0, 4)}-${r()}${r().slice(0, 4)}`;
}

// ── Client version pinning (enterprise-managed governance tier) ─────────

/**
 * This SDK's version. Reported to the gateway on every request via the
 * `x-evalguard-client-version` header so an org that pins an allowed client
 * version range (enterprise-managed policy) can enforce it server-side, and read
 * by `checkVersionPolicy()` so the SDK can refuse to run when out of range.
 *
 * Kept in sync with packages/sdk/package.json#version by the release tooling.
 */
export { SDK_VERSION };

/** Parse `N.N.N` (ignoring any -prerelease/+build) → [major, minor, patch]. */
function parseSemverTuple(raw: string | null | undefined): [number, number, number] | null {
  if (!raw) return null;
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(raw.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function cmpSemver(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

export interface VersionPolicyResult {
  allowed: boolean;
  requiredMinimumVersion: string | null;
  requiredMaximumVersion: string | null;
  reason?: string;
}

/** Cadence at which a virtual key's spend cap (and `current_period_spent_usd`)
 *  auto-resets. Defaults to 'monthly' for keys created before B1 (2026-06-27). */
export type ApiKeyBudgetResetPeriod = "daily" | "weekly" | "monthly";

/** One request in an async batch (OpenAI-style). */
export interface BatchInferenceRequest {
  custom_id?: string;
  model?: string;
  messages: Array<{ role: string; content: string }>;
}

/** A batch's polled state, including the discounted-tier cost accounting (B2). */
export interface BatchInferenceView {
  id: string;
  status: string;
  endpoint: string;
  model: string | null;
  completion_window?: string;
  total_requests: number;
  completed_requests: number;
  failed_requests: number;
  /** % off list applied to this batch's recorded cost (observability). */
  discount_pct: number;
  /** Full synchronous list cost of completed requests (USD). */
  list_cost_usd: number;
  /** Discounted batch cost = list_cost_usd * (1 - discount_pct/100) (USD). */
  cost_usd: number;
  total_tokens_in: number;
  total_tokens_out: number;
  results?: Array<{
    custom_id?: string;
    status: "ok" | "error";
    response?: { content: string; model: string };
    error?: string;
    cost_usd?: number;
    tokens_in?: number;
    tokens_out?: number;
  }>;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  expires_at?: string | null;
}

/** Result of {@link EvalGuard.classifyIntent}. */
export interface IntentClassification {
  intent: string;
  confidence: number;
  sensitivity: "public" | "internal" | "confidential" | "restricted";
  riskScore: number;
  signals: string[];
  scores: Record<string, number>;
}

/** A detected AI tool from {@link EvalGuard.listShadowAiDetections}. */
export interface ShadowAiDetection {
  domain: string;
  toolName: string;
  category: string;
  dataRisk: string;
  policyStatus: string;
  userCount: number;
  requestCount: number;
  departments: string[];
  firstSeen: string;
  lastSeen: string;
  unsanctioned: boolean;
}

export interface ShadowAiDetectionsResult {
  detections: ShadowAiDetection[];
  summary: {
    totalTools: number;
    unsanctionedTools: number;
    highRiskTools: number;
    totalUsers: number;
    totalRequests: number;
  };
}

// ── Data-boundary façade (G11) response types ───────────────────────────
// Wire shapes returned by /data-boundary + /data-boundary/evaluate (the core
// DataBoundaryPolicy / DataBoundaryDecision are re-exported from @evalguard/core).

export interface DataBoundaryPolicyRecord {
  id: string;
  orgId: string;
  projectId: string | null;
  name: string;
  classificationLevels: string[];
  boundaryRules: Record<string, unknown>;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface DataBoundaryEvalDecision {
  allow: boolean;
  boundary: "user-can-see" | "workflow-can-use" | "model-can-receive" | "output-can-reveal";
  classification: "public" | "internal" | "confidential" | "restricted";
  redactions?: {
    boundary: string;
    dictionaryId: string;
    category: string;
    severity: string;
    startIndex: number;
    endIndex: number;
  }[];
  redactedContent?: string;
  reason: string;
  authzDecision?: { allowed: boolean; outcome: string; reason: string };
}

// ── Config ────────────────────────────────────────────────────────────

export interface EvalGuardConfig {
  apiKey: string;
  baseUrl?: string;
}

/**
 * Subject of the call, for consent enforcement at the gateway proxy.
 *
 * When a subject is bound via `withSubject()`, the SDK injects the
 * `x-evalguard-subject-email` / `-id` and `x-evalguard-purpose` headers
 * the gateway uses to look up consent records. If the org has revoked
 * or denied consent for this subject + purpose, the gateway returns
 * HTTP 451 *before* forwarding to the upstream LLM provider.
 *
 * Either email or id is sufficient — provide whichever you have. Purpose
 * defaults to "model_inference" on the server side.
 */
export interface SubjectContext {
  email?: string;
  id?: string;
  purpose?: string;
}

// ── Eval types ────────────────────────────────────────────────────────

export interface EvalParams {
  name: string;
  /**
   * Tenant/project scope. Optional: when omitted, the SDK resolves a default
   * project for the API key via GET /project/current (cached per client
   * instance). Pass it explicitly to skip that lookup.
   */
  projectId?: string;
  model: string;
  prompt: string;
  cases: { input: string; expectedOutput?: string }[];
  scorers: string[];
}

export interface EvalRun {
  id: string;
  projectId: string;
  name: string;
  status: "pending" | "running" | "passed" | "failed" | "error";
  score: number | null;
  maxScore: number;
  duration: number | null;
  createdAt: string;
  completedAt?: string;
  metadata?: Record<string, unknown>;
}

export interface CaseResult {
  input: string;
  actualOutput: string;
  score: number;
  passed: boolean;
  latency: number;
  expectedOutput?: string;
  scorerResults?: Record<string, unknown>;
  tokenUsage?: { prompt: number; completion: number; total: number };
}

export interface EvalResult {
  cases: CaseResult[];
  score: number;
  maxScore: number;
  passRate: number;
  totalLatency: number;
  totalTokens: number;
}

export interface CompareEvalsParams {
  /** First eval run id (the baseline). */
  runA: string;
  /** Second eval run id (the candidate). */
  runB: string;
  /** Project the runs belong to (tenant scope). */
  projectId: string;
}

/** Per-run summary in an {@link EvalComparison}. */
export interface EvalComparisonRun {
  id: string;
  name: string;
  model: string;
  dataset: string;
  /** Score on a 0–100 scale. */
  score: number;
  total_cases: number;
  created_at: string;
}

/** A single case matched across the two runs. */
export interface EvalComparisonCase {
  id: string;
  input: string;
  expected: string;
  run_a_output: string;
  run_a_score: number;
  run_b_output: string;
  run_b_score: number;
  /** True when run B regressed vs run A on this case. */
  regression: boolean;
}

/** Result of {@link EvalGuard.compareEvals}. Fields mirror the
 *  GET /api/v1/evals/compare response shape (snake_case, as returned). */
export interface EvalComparison {
  run_a: EvalComparisonRun;
  run_b: EvalComparisonRun;
  /** run B score minus run A score, 0–100 scale. */
  score_diff: number;
  regressions: number;
  improvements: number;
  unchanged: number;
  cases: EvalComparisonCase[];
}

// ── Security scan types ───────────────────────────────────────────────

export interface SecurityScanParams {
  /**
   * Tenant/project scope. Optional: when omitted, the SDK resolves a default
   * project for the API key via GET /project/current (cached per client
   * instance). Pass it explicitly to skip that lookup.
   */
  projectId?: string;
  model: string;
  prompt: string;
  attackTypes: string[];
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface SecurityFinding {
  id: string;
  scanId: string;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  input: string;
  output: string;
  passed: boolean;
  pluginId?: string;
  strategyId?: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityScanResult {
  findings: SecurityFinding[];
  passRate: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  totalTests: number;
  duration: number;
}

/** OpenSSF Scorecard result from {@link EvalGuard.getScorecard}. */
export interface ScorecardLookupResult {
  repo: string;
  available: boolean;
  score?: number; // 0-10, 10 = best
  riskScore?: number; // 0-10, 10 = riskiest (derived: 10 - score)
  checks?: Array<{ name: string; score: number; reason?: string }>;
  date?: string;
  error?: string;
}

/** Summary row from {@link EvalGuard.listScans}. Mirrors the
 *  GET /api/v1/security list response (snake_case, as returned). */
export interface ScanSummary {
  id: string;
  model: string;
  prompt: string;
  status: string;
  config: Record<string, unknown> | null;
  created_at: string;
  completed_at: string | null;
  created_by: string | null;
  attack_types: string[] | null;
}

// ── Supply-chain (PURL lookup) types ──────────────────────────────────
export interface PurlVulnerability {
  id: string;
  severity?: string;
  summary?: string;
  references?: string[];
  [key: string]: unknown;
}
export interface PurlLookupEntry {
  purl: string;
  status: "ok" | "unsupported" | "invalid";
  ecosystem?: string;
  name?: string;
  version?: string;
  vulnerabilities?: PurlVulnerability[];
  reason?: string;
}
export interface PurlLookupResult {
  entries: PurlLookupEntry[];
  summary: {
    total: number;
    queried: number;
    unsupported: number;
    invalid: number;
    vulnerable: number;
    vulnerabilitiesFound: number;
  };
  truncatedAdvisoryCount: number;
}

// ── Per-CVE waiver / ignore policy types (G2) ──────────────────────────
// snyk `.snyk`-style: waive a (CVE, package) tuple so it stops failing the
// supply-chain CI gate while the finding stays visible.

export interface CveWaiverInput {
  projectId: string;
  cveId: string;
  affectedPackage: string;
  reason: string;
  severity?: "critical" | "high" | "medium" | "low" | "none" | null;
  /** ISO timestamp; omit / null = never expires. */
  expiresAt?: string | null;
}

export interface CveWaiverRecord {
  id: string;
  projectId: string;
  orgId: string;
  cveId: string;
  affectedPackage: string;
  severity: string | null;
  reason: string;
  expiresAt: string | null;
  approvedBy: string | null;
  createdAt: string;
  updatedAt: string;
}

// ── Continuous SBOM monitoring types (G1) ─────────────────────────────
// A monitored project gets its supply-chain scan re-run on a schedule; a new
// KEV-listed / high-EPSS CVE disclosed against a shipped dependency fires an
// alert. These types describe the monitor config + the run-now diff result.

export interface SbomMonitorInput {
  projectId: string;
  /** Enable / disable the scheduled re-scan. */
  enabled?: boolean;
  /** Alert when a NEW CVE's EPSS exploit-probability is >= this (0..1). */
  epssThreshold?: number;
  /** Always alert when a new CVE lands on CISA's KEV catalog. */
  alertOnKev?: boolean;
}

export interface SbomMonitorRecord {
  id: string;
  orgId: string;
  projectId: string;
  enabled: boolean;
  epssThreshold: number;
  alertOnKev: boolean;
  lastRunAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SbomSnapshotSummary {
  id: string;
  dayKey: string;
  vulnCount: number;
  newVulns: unknown[];
  kevCount: number;
  highEpssCount: number;
  scannedAt: string;
}

export interface SbomMonitorAlertableCve {
  cveId: string;
  affectedPackage: string;
  severity: string;
  epssScore: number | null;
  kevListed: boolean;
}

export interface SbomMonitorRunResult {
  projectId: string;
  vulnCount: number;
  kevCount: number;
  highEpssCount: number;
  newVulns: SbomMonitorAlertableCve[];
  alertable: SbomMonitorAlertableCve[];
  scanMode: "live" | "offline";
  liveStatus: "ok" | "degraded" | "skipped";
  scannedAt: string;
}

// ── Idempotent issue sync types (G5) ──────────────────────────────────
// Sync security findings to GitHub Issues / Jira as deduped issues: a stable
// fingerprint (CVE/rule + file) maps each defect to ONE tracker issue, so
// re-syncing updates that issue and a resolved finding closes it.

export interface IssueSyncFindingInput {
  /** Per-scan surrogate id (last-resort identity; cveId/rule preferred). */
  vulnId?: string;
  /** CVE identifier when this is a supply-chain finding. */
  cveId?: string;
  /** Scanner rule / detector id (e.g. "prompt-injection"). */
  rule?: string;
  /** Where the defect lives — source file path or affected package@version. */
  file?: string;
  /** Issue title. */
  title: string;
  /** Long-form description. */
  description?: string;
  severity?: "critical" | "high" | "medium" | "low" | "info";
  /** Remediation / fixed-version hint. */
  remediation?: string;
  references?: string[];
  /** "open" (default) or "resolved" — a resolved finding closes its issue. */
  status?: "open" | "resolved";
}

export interface IssueSyncInput {
  projectId: string;
  provider: "github" | "jira";
  findings: IssueSyncFindingInput[];
}

export interface IssueSyncResponse {
  provider: "github" | "jira";
  createdCount: number;
  updatedCount: number;
  closedCount: number;
  errorCount: number;
  created: { fingerprint: string; externalIssueId: string; externalUrl?: string }[];
  updated: { fingerprint: string; externalIssueId: string }[];
  closed: { fingerprint: string; externalIssueId: string }[];
  errors: { fingerprint: string; op: "create" | "update" | "close"; message: string }[];
}

// ── Governance-risk types (G12) ───────────────────────────────────────

export interface GovernanceRiskRequest {
  securityFindings?: { critical?: number; high?: number; medium?: number; low?: number };
  supplyChainScore?: number;
  vulnerabilityScore?: number;
  complianceCoverage?: number;
  firewallHits?: { critical?: number; high?: number; medium?: number; low?: number };
  evalPassRate?: number;
  weights?: Record<string, number>;
}

export interface GovernanceRiskResult {
  /** 0-100 composite (100 = worst). */
  overallScore: number;
  level: "low" | "medium" | "high" | "critical";
  axes: Array<{ key: string; name: string; score: number; weight: number; detail: string }>;
  missingAxes: string[];
  recommendations: string[];
}

// ── Multi-LLM consensus types (G13) ───────────────────────────────────

export interface ConsensusRequest {
  candidates: Array<{ model: string; content?: string; error?: string }>;
  method?: "similarity" | "exact";
  threshold?: number;
}

export interface ConsensusResponse {
  chosen: string | null;
  chosenModels: string[];
  agreement: number;
  isMajority: boolean;
  method: "similarity" | "exact";
  clusters: Array<{ representative: string; models: string[]; size: number }>;
  candidateCount: number;
  successCount: number;
  errorCount: number;
}

// ── Committed-secret detection types (G10) ────────────────────────────

export interface SecretScanParams {
  /** A single content blob (use `files` for a multi-file / PR-diff scan). */
  content?: string;
  /** Repo-relative path for the single-content form (locates the finding). */
  path?: string;
  /** Multiple files (e.g. a PR's changed files). */
  files?: Array<{ path: string; content: string }>;
  /** Only report findings ≥ this severity. */
  minSeverity?: "low" | "medium" | "high" | "critical";
}

export interface SecretScanFinding {
  ruleId: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  line: number;
  column: number;
  charOffset: number;
  /** REDACTED matched value — never the raw secret. */
  redactedMatch: string;
  matchLength: number;
  file: string;
}

export interface SecretScanResult {
  scannedFiles: number;
  filesWithFindings: number;
  findingsCount: number;
  findings: SecretScanFinding[];
  severityCounts: { critical: number; high: number; medium: number; low: number };
}

// ── Data-quality types ────────────────────────────────────────────────

export interface DatasetHealthParams {
  /** Class index per row (for imbalance + label-quality). */
  labels?: number[];
  /** One embedding vector per row (for OOD / near-dup / non-IID). */
  embeddings?: number[][];
  /** One numeric feature vector per row (for spurious-correlation). */
  features?: number[][];
  /** Per-row predicted class probabilities (for Confident-Learning label quality). */
  predProbs?: number[][];
  numClasses?: number;
  outlierThreshold?: number;
  duplicateThreshold?: number;
  spuriousThreshold?: number;
}

export interface DatasetHealthResult {
  health: {
    rowCount: number;
    imbalance?: { counts: number[]; fractions: number[]; imbalanceRatio: number; minorityClasses: number[] };
    outlierScores?: number[];
    outlierRows?: number[];
    nearDuplicates?: { i: number; j: number; similarity: number }[];
    spuriousFeatures?: { feature: number; correlation: number }[];
    nonIid?: { score: number; nonIid: boolean };
  };
  labelQuality?: {
    estimatedNoiseRate: number;
    numClasses: number;
    issueCount: number;
    topIssues: { index: number; givenLabel: number; suggestedLabel: number; qualityScore: number }[];
  };
}

// ── Red-team planning types ───────────────────────────────────────────

export interface RedTeamPlanParams {
  usesTools?: boolean;
  executesCode?: boolean;
  queriesDatabase?: boolean;
  usesMcp?: boolean;
  hasMemoryOrRag?: boolean;
  isConversational?: boolean;
  isMultimodal?: boolean;
  handlesPii?: boolean;
  makesNetworkRequests?: boolean;
  givesProfessionalAdvice?: boolean;
  hasSystemPrompt?: boolean;
}

export interface RedTeamPlanResult {
  plan: {
    categories: { id: string; name: string; pluginCount: number }[];
    plugins: { id: string; name: string; severity: string; category: string }[];
    totalPlugins: number;
  };
}

// ── RAG ingest types ──────────────────────────────────────────────────

export interface RagIngestParams {
  documents: { id?: string; text: string; metadata?: Record<string, unknown> }[];
  chunking?: { strategy?: "fixed" | "recursive"; chunkSize?: number; chunkOverlap?: number };
  /** When true, attach an embedding to each chunk (uses your BYOK OpenAI key). */
  embed?: boolean;
  embedModel?: string;
  /** Membership-verified project whose BYOK key is used for embedding. */
  projectId?: string;
}

export interface RagIngestChunk {
  id: string;
  documentId: string;
  index: number;
  text: string;
  startChar: number;
  endChar: number;
  metadata?: Record<string, unknown>;
  embedding?: number[];
}

export interface RagIngestResult {
  chunks: RagIngestChunk[];
  chunkCount: number;
  embedded: boolean;
  model?: string;
}

// ── Trace types ───────────────────────────────────────────────────────

export interface TraceParams {
  projectId: string;
  sessionId: string;
  steps: unknown[];
}

// ── Scorer & plugin types ─────────────────────────────────────────────

export interface Scorer {
  id: string;
  name: string;
  description: string;
  type: string;
  config?: Record<string, unknown>;
}

export interface Plugin {
  id: string;
  name: string;
  description: string;
  type: string;
  config?: Record<string, unknown>;
}

// ── Firewall types ────────────────────────────────────────────────────

export interface FirewallRule {
  id: string;
  name: string;
  type: "pii" | "injection" | "toxic" | "topic" | "custom";
  enabled: boolean;
  config?: Record<string, unknown>;
}

/**
 * Sensitivity dial for {@link EvalGuard.checkFirewall} (parity with Lakera's
 * L1–L4). Accepts the level name or its ordinal (1–4). When unset, the engine's
 * L2 ("balanced") baseline applies, so existing callers are unchanged.
 */
export type FirewallSensitivity = "monitor" | "balanced" | "strict" | "lockdown" | 1 | 2 | 3 | 4;

export interface FirewallCheckParams {
  input: string;
  /**
   * Attack categories to force-block (e.g. ["prompt-injection","jailbreak"]).
   * The /firewall/check route accepts a `string[]` of category names; passing
   * full {@link FirewallRule} objects is also accepted for backwards-compat
   * (only their ids/names are wire-relevant). Prefer the string form.
   */
  rules?: FirewallRule[] | string[];
  /** L1–L4 sensitivity preset — lower = permissive, higher = aggressive. */
  sensitivity?: FirewallSensitivity;
  /** Optional project scope, used for the route's consent gate + telemetry. */
  projectId?: string;
  /** Subject email — when supplied with projectId, the route enforces the
   *  subject's "firewall_check" consent (HTTP 451 if revoked). */
  subjectEmail?: string;
  /** Subject id — alternative to subjectEmail for the consent gate. */
  subjectId?: string;
}

export interface FirewallHit {
  layer: string;
  details: string;
  score: number;
  latencyMs: number;
}

// Matches the POST /firewall/check response exactly (see
// apps/web/src/app/api/v1/firewall/check/route.ts). The previous shape
// ({ action, reasons }) did not exist on the wire, so result.action /
// result.reasons were always undefined at runtime while TS reported them
// as valid (audit A3). Use `blocked` for the allow/deny decision.
export interface FirewallResult {
  blocked: boolean;
  score: number;
  category: string | null;
  subcategory: string | null;
  /** Echoes the applied sensitivity preset ("balanced" when unset). */
  sensitivity?: FirewallSensitivity;
  latencyMs: number;
  hits: FirewallHit[];
}

// ── Benchmark types ───────────────────────────────────────────────────

export interface BenchmarkParams {
  /** Benchmark name, e.g. "mmlu", "humaneval", "truthfulqa". */
  benchmark: string;
  model: string;
  /** Overall score for the run (the API requires this). */
  totalScore: number;
  /** Optional per-category / per-suite breakdown. */
  scores?: Record<string, unknown>;
}

export interface BenchmarkResult {
  id: string;
  benchmark: string;
  model: string;
  totalScore: number;
  scores?: Record<string, unknown>;
  verified?: boolean;
  createdAt?: string;
}

// ── Compliance types ──────────────────────────────────────────────────

export interface ComplianceReportParams {
  scanId: string;
  framework: string;
}

export interface ComplianceReport {
  framework: string;
  totalControls: number;
  testedControls: number;
  passedControls: number;
  failedControls: number;
  coverage: number;
  findings: Record<string, unknown>[];
}

// ── Drift types ───────────────────────────────────────────────────────

export interface DriftDetectParams {
  baselineRunId: string;
  currentRunId: string;
  [key: string]: unknown;
}

export interface DriftReport {
  hasDrift: boolean;
  overallDelta: number;
  metricDeltas: Record<string, unknown>[];
  alerts: string[];
}

// ── Gateway routing-config + router-aware chat types ─────────────────

/** Learned-routing strategies the per-org gateway config supports. */
export type GatewayRoutingStrategy =
  | "priority"
  | "round-robin"
  | "weighted"
  | "least-latency"
  | "least-cost"
  | "least-load"
  | "random"
  | "quality-cost"
  | "thompson";

/** A provider entry in the routing config — NEVER carries a raw API key. */
export interface GatewayRoutingProvider {
  name: string;
  enabled?: boolean;
  weight?: number;
  priority?: number;
  models?: string[];
}

export interface GatewayRoutingConfig {
  orgId: string;
  routingStrategy: GatewayRoutingStrategy | string;
  enabled: boolean;
  providers: GatewayRoutingProvider[];
  cacheEnabled: boolean;
  cacheTtlSec: number;
  updatedBy?: string;
  note?: string;
}

export interface ChatMessage {
  role: "user" | "assistant" | "system" | string;
  content: string;
}

export interface GatewayChatResponse {
  requestId?: string;
  model: string;
  provider: string;
  content: string;
  usage?: { promptTokens: number; completionTokens: number; totalTokens: number };
  cached: boolean;
  retries: number;
  latencyMs: number;
  costUsd?: number;
}

// ── RAG AutoML types ──────────────────────────────────────────────────

export interface RagAutoMLLeaderboardEntry {
  rank: number;
  configIndex: number;
  config: Record<string, number | string | boolean>;
  objectiveValue: number | null;
  metrics: Record<string, unknown>;
  failureReason?: string;
}

export interface RagAutoMLStudyResult {
  id: string;
  name: string;
  status: string;
  objective: string;
  objectiveK: number;
  ks: number[];
  totalConfigs: number;
  evaluatedConfigs: number;
  failedConfigs: number;
  bestConfig: Record<string, number | string | boolean> | null;
  bestObjectiveValue: number | null;
  leaderboard: RagAutoMLLeaderboardEntry[];
  message?: string;
}

// ── Decision-BOM types ────────────────────────────────────────────────

export interface DecisionBOMResponse {
  id: string;
  decisionId: string;
  surface: string;
  verdict: string;
  category: string;
  signedAt: string;
  createdAt: string;
  bom: Record<string, unknown>;
  signature: { algorithm: string; value: string; publicKeyPem: string };
  verification: { valid: boolean; errors: string[] };
}

// ── FinOps cost export types ──────────────────────────────────────────

export type FinOpsCostExportFormat = "focus" | "openmeter" | "lago";

// ── Agent-tool builder types ──────────────────────────────────────────
//
// The headline agent-builder feature: a customer-authored "tool" the agent
// can call. A tool is one of three kinds — a `rest` HTTP call, an inline
// `code` snippet, or an `mcp` server invocation — plus a JSON-Schema
// `parameters` object describing the arguments the LLM must supply.

/** JSON-Schema (object) describing a tool's call arguments. */
export interface AgentToolParameters {
  type: "object";
  properties: Record<string, unknown>;
  required?: string[];
}

/** REST-tool transport config. `auth.value` is write-only; reads return `hasSecret`. */
export interface AgentToolRest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  auth?: { type: string; header?: string; value?: string };
  bodyTemplate?: string;
  timeoutMs?: number;
}

/** Inline-code tool config (sandbox-executed source). */
export interface AgentToolCode {
  source: string;
  timeoutMs?: number;
}

/** MCP-server tool config. */
export interface AgentToolMcp {
  server: string;
  toolName?: string;
}

/** A customer-authored agent tool (REST / inline-code / MCP). */
export interface AgentTool {
  id?: string;
  name: string;
  description: string;
  type: "rest" | "code" | "mcp";
  parameters: AgentToolParameters;
  rest?: AgentToolRest;
  code?: AgentToolCode;
  mcp?: AgentToolMcp;
  /** True when a secret (e.g. rest.auth.value) is stored server-side; the value itself is never returned. */
  hasSecret?: boolean;
}

/** Result of {@link EvalGuard.testAgentTool} — a dry-run invocation with the supplied args. */
export interface AgentToolTestResult {
  ok: boolean;
  /** Which stage the test reached/failed at (e.g. "validate", "request", "execute"). */
  stage: string;
  /** HTTP status, for `rest` tools that issued a request. */
  status?: number;
  /** Response body (or execution output) when the test ran. */
  body?: unknown;
  /** Validation/runtime issues when `ok` is false. */
  issues?: string[];
  message?: string;
}

// ── Abuse-report types (defense-in-depth intake) ──────────────────────

/** Trust-&-safety report category. */
export type AbuseReportCategory =
  | "csam"
  | "violence"
  | "self_harm"
  | "harassment"
  | "hate"
  | "fraud"
  | "privacy"
  | "spam"
  | "other";

export type AbuseReportStatus = "open" | "reviewing" | "actioned" | "dismissed";

export interface AbuseReport {
  id: string;
  projectId: string;
  category: AbuseReportCategory;
  description: string | null;
  subjectId: string | null;
  reporterId: string | null;
  evidence: Record<string, unknown> | null;
  status: AbuseReportStatus;
  createdAt: string;
}

/** Auto-triage decision attached to a freshly submitted {@link AbuseReport}. */
export interface AbuseReportTriage {
  severity: Severity;
  category: AbuseReportCategory;
  /** Stable dedup key — repeat reports of the same subject+category collapse on it. */
  dedupKey: string;
  /** True when the category/severity warrants immediate human escalation. */
  autoEscalate: boolean;
  /** True when this report should be fed back into the abuse detector training loop. */
  feedToDetector: boolean;
  reasons: string[];
}

// ── Agent-deployment types (publish a workflow as a chat widget) ──────

export type AgentDeploymentChannel = "web" | "slack" | "whatsapp" | "api";
export type AgentDeploymentStatus = "active" | "paused";

/** A published workflow deployment — `public_id` is the embeddable widget handle. */
export interface AgentDeployment {
  id: string;
  workflow_id: string;
  project_id: string;
  public_id: string;
  channel: AgentDeploymentChannel;
  status: AgentDeploymentStatus;
  allowed_origins: string[] | null;
  greeting: string | null;
  created_at: string;
  updated_at: string | null;
}

// ── Visual-workflow types (run / list / create) ───────────────────────

/** Summary row from {@link EvalGuard.listWorkflows} (GET /workflows). */
export interface WorkflowSummary {
  id: string;
  name: string;
  description: string | null;
  tags: string[];
  created_by: string | null;
  created_at: string;
  updated_at: string | null;
}

/** A created workflow from {@link EvalGuard.createWorkflow} (POST /workflows). */
export interface WorkflowRecord {
  id: string;
  name: string;
  description: string | null;
  tags: string[];
  created_at: string;
  updated_at: string | null;
}

export interface CreateWorkflowParams {
  projectId: string;
  name: string;
  description?: string;
  tags?: string[];
  /** Visual-builder node/edge graph (optional — creates an empty workflow when omitted). */
  nodes?: unknown[];
  edges?: unknown[];
}

/** A queued workflow run from {@link EvalGuard.runWorkflow} (POST /workflows/:id/run). */
export interface WorkflowRunRecord {
  id: string;
  status: string;
  created_at: string;
}

// ── Agent-observability types (list / submit traces) ───────────────────

/** One aggregated agent from {@link EvalGuard.listAgents} (GET /agents). */
export interface AgentSummary {
  agentName: string;
  totalCalls: number;
  avgLatencyMs: number;
  guardEvents: number;
  errors: number;
  estimatedCost: number;
  lastSeen: string | null;
  traceCount: number;
}

export interface AgentListResult {
  agents: AgentSummary[];
  total: number;
}

/** A step in an {@link CreateAgentParams} trace submission (heterogeneous). */
export type AgentTraceStep = Record<string, unknown>;

export interface CreateAgentParams {
  agentName: string;
  projectId?: string;
  sessionId?: string;
  steps?: AgentTraceStep[];
}

/** Result of {@link EvalGuard.createAgent} (POST /agents). */
export interface CreateAgentResult {
  traceId: string;
  sessionId: string;
  agentName: string;
  stepsReceived: number;
}

// ── Guardrails runtime-check types ─────────────────────────────────────

export interface RunGuardrailsParams {
  /** The text to check (input or output). */
  text: string;
  /** Optional project — loads that project's custom guardrail rules. */
  projectId?: string;
}

/** Result of {@link EvalGuard.runGuardrails} (POST /guardrails) — raw checkFirewall() shape. */
export interface GuardrailsCheckResult {
  action: "allow" | "redact" | "block" | string;
  reasons: Array<{ layer?: string; detail: string; score?: number }>;
  latencyMs: number;
  [key: string]: unknown;
}

// ── OpenAI-compatible chat-completions types ───────────────────────────

export interface ChatCompletionMessage {
  role: "system" | "user" | "assistant" | "tool" | "developer" | string;
  content: string | null | unknown[];
  name?: string;
  tool_call_id?: string;
  tool_calls?: unknown[];
}

export interface ChatCompletionsParams {
  model: string;
  messages: ChatCompletionMessage[];
  temperature?: number;
  top_p?: number;
  n?: number;
  max_tokens?: number;
  max_completion_tokens?: number;
  stop?: string | string[];
  tools?: unknown[];
  tool_choice?: unknown;
  response_format?: unknown;
  seed?: number;
  user?: string;
  /** EvalGuard vendor extension (e.g. DICL few-shot examples). */
  evalguard?: Record<string, unknown>;
  /** Other OpenAI fields are forwarded through. NOTE: streaming is not
   *  supported by this method — use the raw OpenAI SDK against the base URL. */
  [key: string]: unknown;
}

/** OpenAI-exact chat-completion response (returned RAW, not enveloped). */
export interface ChatCompletionsResult {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message: { role: string; content: string | null; tool_calls?: unknown[] };
    finish_reason: string | null;
  }>;
  usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
  [key: string]: unknown;
}

// ── Embedding store / similarity-search types ──────────────────────────

export interface StoreEmbeddingParams {
  projectId: string;
  id: string;
  vector: number[];
  label?: string;
  metadata?: Record<string, unknown>;
}

/** A stored embedding row from {@link EvalGuard.storeEmbedding}. */
export interface StoredEmbeddingRecord {
  id: string;
  project_id: string;
  content: string | null;
  metadata: Record<string, unknown> | null;
  created_at?: string;
  [key: string]: unknown;
}

export interface FindSimilarEmbeddingsParams {
  projectId: string;
  /** A raw query vector, OR a stored embedding id (queryId) to search by. */
  queryVector?: number[];
  queryId?: string;
  topK?: number;
}

export interface EmbeddingSimilarityHit {
  id: string;
  label: string | null;
  score: number;
}

// ── Provider-rerank types (BYO vendor key) ─────────────────────────────

export type RerankProvider = "cohere" | "voyage" | "together";

export interface RerankParams {
  orgId: string;
  query: string;
  documents: string[];
  /** Reranker model id — auto-detects provider unless overridden. */
  model: string;
  provider?: RerankProvider;
  topK?: number;
  baseUrl?: string;
  timeoutMs?: number;
}

export interface RerankResultItem {
  index: number;
  score: number;
  document?: string;
}

/** Raw provider-rerank response (NOT enveloped) from {@link EvalGuard.rerank}. */
export interface RerankResult {
  provider: RerankProvider | string;
  results: RerankResultItem[];
  [key: string]: unknown;
}

// ── Hybrid-retrieval types (BM25 / RRF / MMR) ──────────────────────────

export interface HybridRetrievalDocument {
  id: string;
  text?: string;
  vector?: number[];
  relevance?: number;
  payload?: unknown;
}

export interface HybridRetrievalParams {
  method: "bm25" | "hybrid" | "mmr";
  orgId?: string;
  query?: string;
  documents: HybridRetrievalDocument[];
  /** Required for `hybrid` — the dense ranking to fuse with BM25. */
  denseRanking?: Array<{ id: string }>;
  k1?: number;
  b?: number;
  rrfK?: number;
  lambda?: number;
  topK?: number;
}

export interface HybridRetrievalResult {
  method: "bm25" | "hybrid" | "mmr";
  results: Array<Record<string, unknown>>;
}

// ── Corpus-integrity types ─────────────────────────────────────────────

export interface CorpusIntegrityDocument {
  id?: string;
  text: string;
  embedding?: number[];
  updatedAt?: string;
  source?: string;
  trust?: number;
}

export interface CorpusIntegrityParams {
  documents: CorpusIntegrityDocument[];
  orgId?: string;
  projectId?: string;
  nearDuplicateThreshold?: number;
  conflictThreshold?: number;
  maxAgeDays?: number;
  minTrust?: number;
}

// ── Trace-assistant analysis types ─────────────────────────────────────

export interface AnalyzeTraceSpansParams {
  /** Look up spans from the store by id (requires projectId), OR pass `spans`. */
  traceId?: string;
  spans?: unknown[];
  /** Set false for fast rule-based-only analysis (no LLM). */
  callLLM?: boolean;
  projectId?: string;
}

// ── Trace → dataset curation types ─────────────────────────────────────

export interface TraceToDatasetParams {
  /** Single trace id, OR pass `traceIds` for a bulk conversion. */
  traceId?: string;
  traceIds?: string[];
  datasetId: string;
  projectId: string;
  /** Near-duplicate removal (default true). */
  deduplicate?: boolean;
}

export interface TraceToDatasetResult {
  created: number;
  duplicatesSkipped: number;
  skipped: number;
  skippedTraceIds?: string[];
  deduplicated: number;
  qualityDistribution: Record<string, number>;
  examples: unknown[];
}

// ── Trace import types ─────────────────────────────────────────────────

export type TraceImportSourcePlatform = "helicone" | "langfuse" | "portkey" | "huggingface";

export interface ImportTracesParams {
  platform: TraceImportSourcePlatform | string;
  projectId: string;
  /** The vendor-specific export JSON. */
  payload: unknown;
}

export interface ImportTracesResult {
  platform: string;
  inserted: number;
  failed: number;
  errors: unknown[];
  skippedDuplicates: number;
  total?: number;
  message?: string;
}

// ── Trace aggregate (analytics) types ──────────────────────────────────

export interface AggregateTracesParams {
  orgId: string;
  projectId?: string;
  model?: string;
  /** ISO 8601 lower bound. */
  since?: string;
  maxScanSpans?: number;
}

export interface AggregateTracesResult {
  buckets: Array<Record<string, unknown>>;
  bucketCount: number;
  source: string;
  fellBack: boolean;
  fallbackReason?: string;
  note?: string;
}

// ── Code-eval types ────────────────────────────────────────────────────

export interface EvalCodeParams {
  code: string;
  expected?: string;
  input?: string;
  /** Subset of the code scorers (default: all). */
  scorers?: string[];
  /** Per-scorer options keyed by scorer name. */
  options?: Record<string, Record<string, unknown>>;
}

export interface EvalCodeScorerResult {
  scorer: string;
  score: number;
  passed: boolean;
  reason?: string;
  data?: Record<string, unknown>;
}

export interface EvalCodeResult {
  results: EvalCodeScorerResult[];
  summary: { total: number; passed: number; failed: number; avg_score: number };
  latency_ms: number;
}

// ── MCP gateway tool-invocation types ──────────────────────────────────

export interface McpInvokeParams {
  serverId: string;
  toolName: string;
  arguments?: Record<string, unknown>;
  /** Bearer JWT when the server's auth_type is 'jwt'. */
  jwt?: string;
  /** Calling agent's task — constrains the dual-LLM quarantine summary. */
  taskGoal?: string;
  /** CIMD identity fields (only enforced when the org opts in). */
  clientId?: string;
  cimdJws?: string;
  cimdNonce?: string;
  /** Groups a multi-tool agent run for lateral-movement detection. */
  runId?: string;
}

export interface McpInvokeResult {
  decision: string;
  reason: string;
  response: unknown;
  latencyMs: number;
  failover?: { fromServerId: string; toServerId: string };
}

// ── Client ────────────────────────────────────────────────────────────

export class EvalGuard {
  private apiKey: string;
  private baseUrl: string;
  private subject: SubjectContext | null;
  /**
   * Per-instance registry of customer-defined plugins / strategies / scorers.
   * Promptfoo gap closer: lets callers extend the 249 built-in attack
   * plugins from their own TS code without forking the monorepo.
   * See packages/sdk/src/extensions.ts for the type surface.
   */
  private extensions: import("./extensions").ExtensionRegistry;
  /**
   * Default project resolved lazily from GET /project/current and cached for
   * the lifetime of this client instance, so methods that need a projectId can
   * be called without one and we only hit the network once. An explicitly
   * passed projectId always wins and skips this.
   */
  private resolvedProjectId?: string;

  constructor(config: EvalGuardConfig) {
    this.apiKey = config.apiKey;
    const baseUrl = config.baseUrl ?? "https://evalguard.ai/api/v1";

    // Enforce HTTPS for non-local URLs
    if (config.baseUrl) {
      try {
        const parsed = new URL(config.baseUrl);
        const isLocal =
          parsed.hostname === 'localhost' ||
          parsed.hostname === '127.0.0.1' ||
          parsed.hostname === '::1' ||
          parsed.hostname === '[::1]'; // IPv6 loopback (URL.hostname may keep brackets)
        if (parsed.protocol !== 'https:' && !isLocal) {
          throw new Error('EvalGuard: baseUrl must use HTTPS. Only localhost/127.0.0.1 may use HTTP.');
        }
      } catch (e) {
        if (e instanceof TypeError) {
          throw new Error(`EvalGuard: Invalid baseUrl: ${config.baseUrl}`, { cause: e });
        }
        throw e;
      }
    }

    this.baseUrl = baseUrl;
    this.subject = null;
    // Use static import (was a runtime require under CJS — broken in
    // vitest ESM with "Cannot find module './extensions'"). Cost is the
    // module evaluation, not the registry instantiation, and ESM
    // tree-shaking means consumers that never use() pay nothing in the
    // final bundle anyway.
    this.extensions = new ExtensionRegistry();
  }

  /**
   * Register a custom plugin, strategy, or scorer. Mirrors Promptfoo's
   * `redteam.Plugins / Strategies / Graders` extension surface — closes
   * the gap our competitor analysis flagged.
   *
   *   import { EvalGuard, definePlugin } from "@evalguard/sdk";
   *   const myPlugin = definePlugin({
   *     id: "my-injection", name: "...", severity: "high",
   *     generate: () => [{ input: "..." }],
   *     grade: ({ output }) => /* ... *\/ null,
   *   });
   *   client.use(myPlugin);
   */
  use(extension: import("./extensions").CustomPlugin
    | import("./extensions").CustomStrategy
    | import("./extensions").CustomScorer): this {
    this.extensions.use(extension);
    return this;
  }

  /**
   * Run the user's registered plugins (filtered by id) against `target`,
   * routing each probe through the supplied `complete` function. Findings
   * are returned client-side — no server roundtrip required, so this
   * works on isolated networks without an EvalGuard backend.
   */
  async runCustomScan(args: {
    target: string;
    pluginIds: string[];
    strategyIds?: string[];
    complete: (prompt: string, opts?: { model?: string }) => Promise<string>;
  }): Promise<import("./extensions").CustomScanResult[]> {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { runCustomScan } = require("./extensions") as typeof import("./extensions");
    return runCustomScan(this.extensions, args);
  }

  /** Read-only access to the registered extensions (for debugging/tests). */
  listRegisteredPlugins(): import("./extensions").CustomPlugin[] {
    return this.extensions.listPlugins();
  }
  listRegisteredStrategies(): import("./extensions").CustomStrategy[] {
    return this.extensions.listStrategies();
  }
  listRegisteredScorers(): import("./extensions").CustomScorer[] {
    return this.extensions.listScorers();
  }

  /**
   * Bind a subject (end-user) to this client. Returns a *new* client so
   * a single shared `EvalGuard` instance can fan out per-request scoped
   * clients without mutation. Typical use:
   *
   *   const client = new EvalGuard({ apiKey });
   *   const userClient = client.withSubject({ email: user.email, purpose: "support_chat" });
   *   await userClient.gatewayProxy(...);  // 451 if user has revoked consent
   */
  withSubject(subject: SubjectContext): EvalGuard {
    if (!subject.email && !subject.id) {
      throw new Error("EvalGuard.withSubject: at least one of email or id is required");
    }
    const next = new EvalGuard({ apiKey: this.apiKey, baseUrl: this.baseUrl });
    next.subject = { ...subject };
    return next;
  }

  /**
   * Consult the org's enterprise-managed client version-pinning policy and
   * decide whether THIS SDK version (SDK_VERSION) is allowed to run.
   *
   *   const v = await client.checkVersionPolicy();
   *   if (!v.allowed) throw new Error(v.reason);
   *
   * Returns `{ allowed: true }` (unpinned) when the org sets no version bounds —
   * the default, so existing integrations are unaffected. The check is purely
   * a READ; it never mutates anything. On a network/endpoint error it returns
   * `allowed: true` (fail-open: a transient policy-read blip must not brick the
   * customer's whole SDK fleet — the server ALSO sees the version header on every
   * request and can enforce there).
   */
  async checkVersionPolicy(): Promise<VersionPolicyResult> {
    let policy: { requiredMinimumVersion?: string | null; requiredMaximumVersion?: string | null } = {};
    try {
      // Best-effort + FAIL-OPEN: a version-policy read must never brick or even
      // stall the client, so this uses a 3s timeout and NO retry — bypassing
      // request()'s 3x exponential backoff (which can take several seconds on a
      // network blip and would hang an SDK init).
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      try {
        const res = await fetch(
          `${this.baseUrl}/client/policy?version=${encodeURIComponent(SDK_VERSION)}`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${this.apiKey}`,
              "x-evalguard-client-version": SDK_VERSION,
              ...this.subjectHeaders(),
            },
            signal: controller.signal,
          },
        );
        const json = (await res.json()) as { data?: typeof policy } & typeof policy;
        // API responses are enveloped as { success, data } — unwrap if present.
        // A non-2xx / error body simply yields no min/max → treated as unpinned
        // (fail-open), so no explicit res.ok gate is needed.
        policy = json && typeof json === "object" && json.data ? json.data : json;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch {
      // Unreachable / timeout / older server without the route → treat as unpinned.
      return { allowed: true, requiredMinimumVersion: null, requiredMaximumVersion: null };
    }

    const min = policy.requiredMinimumVersion ?? null;
    const max = policy.requiredMaximumVersion ?? null;
    const result: VersionPolicyResult = {
      allowed: true,
      requiredMinimumVersion: min,
      requiredMaximumVersion: max,
    };
    if (!min && !max) return result; // unpinned

    const ver = parseSemverTuple(SDK_VERSION);
    const minT = parseSemverTuple(min);
    const maxT = parseSemverTuple(max);
    if (ver && minT && cmpSemver(ver, minT) < 0) {
      result.allowed = false;
      result.reason = `@evalguard/sdk ${SDK_VERSION} is below the minimum version (${min}) required by this organization. Upgrade to continue.`;
    } else if (ver && maxT && cmpSemver(ver, maxT) > 0) {
      result.allowed = false;
      result.reason = `@evalguard/sdk ${SDK_VERSION} is above the maximum version (${max}) allowed by this organization. Downgrade to a supported release.`;
    }
    return result;
  }

  /**
   * Like `checkVersionPolicy()` but THROWS when this SDK version is outside the
   * org's pinned range — call it once at startup to hard-stop an out-of-policy
   * client before it issues any real requests.
   */
  async assertVersionAllowed(): Promise<void> {
    const v = await this.checkVersionPolicy();
    if (!v.allowed) throw new Error(v.reason ?? "EvalGuard client version not allowed by org policy");
  }

  /** Build the consent headers for the bound subject (if any). */
  private subjectHeaders(): Record<string, string> {
    if (!this.subject) return {};
    const h: Record<string, string> = {};
    if (this.subject.email) h["x-evalguard-subject-email"] = this.subject.email;
    if (this.subject.id) h["x-evalguard-subject-id"] = this.subject.id;
    if (this.subject.purpose) h["x-evalguard-purpose"] = this.subject.purpose;
    return h;
  }

  /**
   * Resolve (and cache) the default project for this API key.
   *
   * GETs /project/current — which returns RAW `{ projectId, orgId }` (not the
   * `{ success, data }` envelope) and auto-creates a default project on a fresh
   * org. The resolved id is cached on the instance so repeated project-scoped
   * calls never re-fetch. Throws a clear, actionable error when no project can
   * be resolved so the caller knows to pass `projectId` explicitly.
   *
   * Public so callers can pre-warm / inspect the resolved id; the param-scoped
   * methods use it automatically when `projectId` is omitted.
   */
  async resolveProjectId(): Promise<string> {
    if (this.resolvedProjectId) return this.resolvedProjectId;
    let data: { projectId?: string } | undefined;
    try {
      data = await this.request<{ projectId?: string; orgId?: string }>("/project/current", "GET");
    } catch (err) {
      throw new EvalGuardError(
        "Could not resolve a default project; pass projectId explicitly.",
        { code: "PROJECT_RESOLUTION_FAILED", cause: err },
      );
    }
    const projectId = data?.projectId;
    if (!projectId) {
      throw new EvalGuardError(
        "Could not resolve a default project; pass projectId explicitly.",
        { code: "PROJECT_RESOLUTION_FAILED" },
      );
    }
    this.resolvedProjectId = projectId;
    return projectId;
  }

  // ── Governance: intent classification ──────────────────────────────

  /**
   * Classify a prompt's intent, data-sensitivity, and governance risk via the
   * deterministic core classifier. Resolves the default org when `orgId` is
   * omitted. Powers intent-based routing + intent-conditioned policy.
   */
  async classifyIntent(
    prompt: string,
    opts?: {
      orgId?: string;
      sensitivityFloor?: "public" | "internal" | "confidential" | "restricted";
    },
  ): Promise<IntentClassification> {
    let orgId = opts?.orgId;
    if (!orgId) {
      const data = await this.request<{ orgId?: string }>("/project/current", "GET");
      orgId = data?.orgId;
      if (!orgId) {
        throw new EvalGuardError(
          "Could not resolve a default org; pass orgId explicitly.",
          { code: "ORG_RESOLUTION_FAILED" },
        );
      }
    }
    return this.request("/governance/intent/classify", "POST", {
      orgId,
      prompt,
      sensitivityFloor: opts?.sensitivityFloor,
    });
  }

  /**
   * List detected AI tools (shadow-AI), rolled up from ingested egress-log
   * sightings and ranked by request volume. Resolves the default project when
   * `projectId` is omitted.
   */
  async listShadowAiDetections(
    projectId?: string,
    opts?: { category?: string; risk?: string; status?: string; limit?: number },
  ): Promise<ShadowAiDetectionsResult> {
    const pid = projectId ?? (await this.resolveProjectId());
    const qs = new URLSearchParams({ projectId: pid });
    if (opts?.category) qs.set("category", opts.category);
    if (opts?.risk) qs.set("risk", opts.risk);
    if (opts?.status) qs.set("status", opts.status);
    if (opts?.limit) qs.set("limit", String(opts.limit));
    return this.request(`/shadow-ai/detections?${qs.toString()}`, "GET");
  }

  // ── Eval endpoints ─────────────────────────────────────────────────

  async eval(params: EvalParams): Promise<EvalResult> {
    // Resolve a default project only when none was passed — an explicit
    // projectId is sent verbatim (and skips the /project/current fetch).
    const body = params.projectId
      ? params
      : { ...params, projectId: await this.resolveProjectId() };
    return this.request("/evals", "POST", body);
  }

  async getEvalRun(id: string): Promise<EvalRun> {
    return this.request(`/evals/${id}`, "GET");
  }

  async listEvals(projectId?: string): Promise<EvalRun[]> {
    // Explicit empty string is a caller error; `undefined` means "resolve the
    // default project for this key".
    if (projectId !== undefined && !projectId) throw new Error("projectId is required");
    const resolved = projectId ?? (await this.resolveProjectId());
    return this.request(`/evals?projectId=${encodeURIComponent(resolved)}`, "GET");
  }

  /** Compare two eval runs (regressions / improvements / per-case diff). */
  async compareEvals(params: CompareEvalsParams): Promise<EvalComparison> {
    const { runA, runB, projectId } = params;
    if (!runA || !runB) throw new Error("runA and runB are required");
    if (!projectId) throw new Error("projectId is required");
    const query =
      `?runA=${encodeURIComponent(runA)}` +
      `&runB=${encodeURIComponent(runB)}` +
      `&projectId=${encodeURIComponent(projectId)}`;
    return this.request(`/evals/compare${query}`, "GET");
  }

  /**
   * Start an imperative, Weave-style {@link EvaluationLogger} bound to a new
   * eval run. Use this when your pipeline already produces model outputs and you
   * want to RECORD predictions/scores as you go, instead of handing a full
   * declarative config to `eval()` and letting the server run the model.
   *
   *   const logger = await client.startEvalLogger({ projectId, name: "smoke", model: "gpt-4o" });
   *   for (const c of cases) {
   *     const out = await myPipeline(c.input);
   *     const { index } = logger.logPrediction({ input: c.input, output: out, expected: c.gold });
   *     logger.logScore(index, "exact-match", out === c.gold ? 1 : 0, out === c.gold);
   *   }
   *   await logger.finish({ status: "passed", score: 0.92, passRate: 0.9 });
   *
   * Creates the run via POST /evals in EXTERNAL mode (status=running, the model
   * is NOT executed server-side), then the logger streams rows through the
   * existing POST /evals/[runId]/results batch-upsert and closes the run via
   * PATCH /evals/[runId].
   */
  async startEvalLogger(params: EvalLoggerParams): Promise<EvaluationLogger> {
    if (!params.projectId) throw new Error("startEvalLogger: projectId is required");
    if (!params.name) throw new Error("startEvalLogger: name is required");
    if (!params.model) throw new Error("startEvalLogger: model is required");

    const created = await this.request<{ id: string }>("/evals", "POST", {
      name: params.name,
      projectId: params.projectId,
      model: params.model,
      // Recorded as run context; the server does not execute the model in
      // external mode, so an empty prompt / scorers / cases is valid.
      prompt: params.prompt ?? "",
      cases: [],
      scorers: params.scorers ?? [],
      external: true,
    });

    if (!created?.id) {
      throw new Error("startEvalLogger: server did not return a run id");
    }

    // Bind the client's private transport (idempotency-key + retry + envelope
    // unwrap) without exposing request() publicly.
    const boundRequest = <T = unknown>(path: string, method: string, body?: unknown): Promise<T> =>
      this.request<T>(path, method, body);

    return new EvaluationLogger({
      runId: created.id,
      request: boundRequest,
      flushAt: params.flushAt,
    });
  }

  // ── Security scan endpoints ────────────────────────────────────────

  async securityScan(params: SecurityScanParams): Promise<SecurityScanResult> {
    // Resolve a default project only when none was passed — an explicit
    // projectId is sent verbatim (and skips the /project/current fetch).
    const body = params.projectId
      ? params
      : { ...params, projectId: await this.resolveProjectId() };
    return this.request("/security", "POST", body);
  }

  async getScan(id: string): Promise<SecurityScanResult> {
    return this.request(`/security/${id}`, "GET");
  }

  /**
   * Fetch the OpenSSF Scorecard project-health signal (0-10) for a repository,
   * plus the derived supply-chain risk contribution. Best-effort — unavailable
   * projects return `available: false`.
   * @example client.getScorecard("github.com/lodash/lodash")
   */
  async getScorecard(repo: string): Promise<ScorecardLookupResult> {
    if (!repo || typeof repo !== "string") throw new Error("repo is required");
    return this.request("/supply-chain/scorecard", "POST", { repo });
  }

  /** List recent security scans for a project (most-recent first). */
  async listScans(projectId: string): Promise<ScanSummary[]> {
    if (!projectId) throw new Error("projectId is required");
    return this.request(`/security?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Regression auto-trigger (continuous red-team on change) ──────────

  /**
   * Fire the regression-rerun decision for a change event — the CI/webhook
   * entry point. Plans which suites to re-run and, when the project has opted
   * in, nudges the project's enabled red-team campaigns to run now. Always
   * records the decision to the ledger.
   *
   * @example client.triggerRegressionRerun({ orgId, projectId, changeType: "model_change", riskLevel: "high" })
   */
  async triggerRegressionRerun(params: {
    orgId: string;
    projectId: string;
    changeType: string;
    riskLevel?: "low" | "medium" | "high" | "critical";
    resourceId?: string;
  }): Promise<{
    evaluated: boolean;
    enabled?: boolean;
    shouldRerun?: boolean;
    suites?: string[];
    enqueued?: boolean;
    triggeredCampaignIds?: string[];
    reason?: string;
    logId?: string | null;
  }> {
    if (!params.orgId || !params.projectId) throw new Error("orgId and projectId are required");
    if (!params.changeType) throw new Error("changeType is required");
    return this.request("/regression-tests/trigger", "POST", params);
  }

  /** Read a project's regression auto-trigger config (synthetic defaults when unset). */
  async getRegressionAutoTriggerConfig(params: {
    orgId: string;
    projectId: string;
  }): Promise<{
    project_id: string;
    enabled: boolean;
    min_risk_level: string;
    trigger_change_types: string[] | null;
    configured: boolean;
  }> {
    if (!params.orgId || !params.projectId) throw new Error("orgId and projectId are required");
    const qs = new URLSearchParams({ orgId: params.orgId, projectId: params.projectId });
    return this.request(`/regression-tests/config?${qs.toString()}`, "GET");
  }

  /** Enable/configure a project's regression auto-trigger (admin-only server-side). */
  async setRegressionAutoTriggerConfig(params: {
    orgId: string;
    projectId: string;
    enabled?: boolean;
    minRiskLevel?: "low" | "medium" | "high" | "critical";
    triggerChangeTypes?: string[] | null;
  }): Promise<{
    project_id: string;
    enabled: boolean;
    min_risk_level: string;
    trigger_change_types: string[] | null;
    configured: boolean;
  }> {
    if (!params.orgId || !params.projectId) throw new Error("orgId and projectId are required");
    return this.request("/regression-tests/config", "PUT", params);
  }

  /** List a project's regression auto-trigger decision ledger (newest first, max 200). */
  async listRegressionRerunLog(params: {
    orgId: string;
    projectId: string;
    limit?: number;
  }): Promise<
    Array<{
      id: string;
      change_type: string;
      risk_level: string;
      resource_id: string | null;
      should_rerun: boolean;
      suites: string[];
      reason: string;
      enqueued: boolean;
      triggered_campaign_ids: string[];
      source: string;
      created_at: string;
    }>
  > {
    if (!params.orgId || !params.projectId) throw new Error("orgId and projectId are required");
    const qs = new URLSearchParams({ orgId: params.orgId, projectId: params.projectId });
    if (params.limit) qs.set("limit", String(params.limit));
    return this.request(`/regression-tests/log?${qs.toString()}`, "GET");
  }

  // ── Shadow guardrail A/B (RB-9) ──────────────────────────────────────

  /**
   * Create a shadow guardrail config — pin an ENFORCING snapshot (mirror your
   * live firewall settings) + a SHADOW candidate, then feed traffic through
   * {@link evaluateShadowGuardrail} to compare. Observation-only.
   *
   * @example client.createShadowGuardrailConfig({ orgId, projectId, name: "stricter-pii", shadowSensitivity: "strict", shadowRules: ["pii"] })
   */
  async createShadowGuardrailConfig(params: {
    orgId: string;
    projectId: string;
    name: string;
    enforcingSensitivity?: "monitor" | "balanced" | "strict" | "lockdown";
    enforcingRules?: string[];
    shadowSensitivity?: "monitor" | "balanced" | "strict" | "lockdown";
    shadowRules?: string[];
  }): Promise<{ id: string; name: string; enabled: boolean }> {
    if (!params.orgId || !params.projectId || !params.name) {
      throw new Error("orgId, projectId and name are required");
    }
    return this.request("/gateway/guardrails/shadow", "POST", params);
  }

  /** List a project's shadow guardrail configs with aggregated divergence stats. */
  async listShadowGuardrailConfigs(params: {
    orgId: string;
    projectId: string;
  }): Promise<
    Array<{
      id: string;
      name: string;
      enabled: boolean;
      enforcing_sensitivity: string;
      shadow_sensitivity: string;
      stats: {
        total: number;
        divergenceRate: number;
        shadowStricterRate: number;
        shadowLooserRate: number;
        avgLatencyOverheadMs: number;
        recommendation: string;
      };
    }>
  > {
    if (!params.orgId || !params.projectId) throw new Error("orgId and projectId are required");
    const qs = new URLSearchParams({ orgId: params.orgId, projectId: params.projectId });
    return this.request(`/gateway/guardrails/shadow?${qs.toString()}`, "GET");
  }

  /** Enable/disable or retune a shadow guardrail config (admin server-side). */
  async updateShadowGuardrailConfig(params: {
    orgId: string;
    id: string;
    enabled?: boolean;
    name?: string;
    enforcingSensitivity?: "monitor" | "balanced" | "strict" | "lockdown";
    enforcingRules?: string[];
    shadowSensitivity?: "monitor" | "balanced" | "strict" | "lockdown";
    shadowRules?: string[];
  }): Promise<{ id: string; enabled: boolean }> {
    if (!params.orgId || !params.id) throw new Error("orgId and id are required");
    return this.request("/gateway/guardrails/shadow", "PUT", params);
  }

  /** Delete a shadow guardrail config. */
  async deleteShadowGuardrailConfig(params: { orgId: string; id: string }): Promise<{ deleted: boolean }> {
    if (!params.orgId || !params.id) throw new Error("orgId and id are required");
    const qs = new URLSearchParams({ orgId: params.orgId, id: params.id });
    return this.request(`/gateway/guardrails/shadow?${qs.toString()}`, "DELETE");
  }

  /**
   * Evaluate one content sample against a shadow config's enforcing + shadow
   * settings and return how they diverge (and record it when the config is on).
   *
   * @example client.evaluateShadowGuardrail({ orgId, projectId, configId, content: "my SSN is 123-45-6789" })
   */
  async evaluateShadowGuardrail(params: {
    orgId: string;
    projectId: string;
    configId: string;
    content: string;
    field?: "input" | "output";
  }): Promise<{
    divergence: "agree-block" | "agree-allow" | "shadow-stricter" | "shadow-looser";
    enforcing: { blocked: boolean; category: string | null; latencyMs: number };
    shadow: { blocked: boolean; category: string | null; latencyMs: number };
    latencyOverheadMs: number;
    recorded: boolean;
  }> {
    if (!params.orgId || !params.projectId || !params.configId) {
      throw new Error("orgId, projectId and configId are required");
    }
    if (!params.content) throw new Error("content is required");
    return this.request("/gateway/guardrails/shadow/evaluate", "POST", params);
  }

  // ── Supply chain ────────────────────────────────────────────────────

  /**
   * Look up known vulnerabilities for a list of Package URLs (PURLs) via
   * OSV.dev. Supported ecosystems: npm, PyPI, Go. Invalid/unsupported PURLs are
   * reported in-band (never silently dropped).
   *
   * @example client.lookupVulnerabilities(["pkg:npm/lodash@4.17.21", "pkg:pypi/requests@2.31.0"])
   */
  async lookupVulnerabilities(purls: string[]): Promise<PurlLookupResult> {
    if (!Array.isArray(purls) || purls.length === 0) {
      throw new Error("purls must be a non-empty array");
    }
    return this.request("/supply-chain/lookup", "POST", { purls });
  }

  // ── Per-CVE waivers (G2) ────────────────────────────────────────────

  /**
   * List a project's CVE waivers. A waiver suppresses a specific (CVE, package)
   * tuple from the supply-chain CI gate while keeping the finding visible.
   * GET /supply-chain/waivers?projectId=
   */
  async listCveWaivers(projectId: string): Promise<{ waivers: CveWaiverRecord[]; total: number }> {
    if (!projectId) throw new Error("projectId is required");
    return this.request(
      `/supply-chain/waivers?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /**
   * Create (or upsert) a CVE waiver for a (CVE, package) tuple. Owner/admin only.
   * Set `expiresAt` so the CVE re-surfaces and re-fails the gate once it lapses.
   * POST /supply-chain/waivers
   */
  async addCveWaiver(input: CveWaiverInput): Promise<{ waiver: CveWaiverRecord }> {
    if (!input?.projectId) throw new Error("projectId is required");
    if (!input?.cveId) throw new Error("cveId is required");
    if (!input?.affectedPackage) throw new Error("affectedPackage is required");
    if (!input?.reason) throw new Error("reason is required");
    return this.request("/supply-chain/waivers", "POST", input);
  }

  /**
   * Revoke a CVE waiver by id, re-exposing its (CVE, package) to the gate.
   * Owner/admin only. DELETE /supply-chain/waivers/:id
   */
  async removeCveWaiver(id: string): Promise<{ deleted: boolean }> {
    if (!id) throw new Error("id is required");
    return this.request(`/supply-chain/waivers/${encodeURIComponent(id)}`, "DELETE");
  }

  // ── Continuous SBOM monitoring (G1) ─────────────────────────────────

  /**
   * Read a project's SBOM monitor config + its recent snapshot history. The
   * monitor is null when the project has never been configured. Any org member.
   * GET /sbom-monitor?projectId=
   */
  async listSbomMonitors(
    projectId: string,
  ): Promise<{ monitor: SbomMonitorRecord | null; snapshots: SbomSnapshotSummary[] }> {
    if (!projectId) throw new Error("projectId is required");
    return this.request(
      `/sbom-monitor?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /**
   * Enable / configure continuous SBOM monitoring for a project. Owner/admin
   * only. Once enabled the worker re-runs the supply-chain scan every 24h and
   * alerts on newly-disclosed KEV / high-EPSS CVEs. POST /sbom-monitor
   */
  async configureSbomMonitor(input: SbomMonitorInput): Promise<{ monitor: SbomMonitorRecord }> {
    if (!input?.projectId) throw new Error("projectId is required");
    return this.request("/sbom-monitor", "POST", input);
  }

  /**
   * Run the SBOM monitor for a project NOW (synchronous inline scan) and return
   * the diff vs the last snapshot. Owner/admin only. POST /sbom-monitor/run
   */
  async runSbomMonitorNow(projectId: string): Promise<SbomMonitorRunResult> {
    if (!projectId) throw new Error("projectId is required");
    return this.request("/sbom-monitor/run", "POST", { projectId });
  }

  // ── Idempotent issue sync ──────────────────────────────────────────

  /**
   * Sync a project's security findings to its configured bug tracker (GitHub
   * Issues / Jira) idempotently (G5). Each finding maps to ONE tracker issue
   * via a stable dedup fingerprint (CVE/rule + file), so re-syncing UPDATES the
   * same issue instead of creating a duplicate; a finding marked `resolved` (or
   * one that disappeared since the last sync) CLOSES its issue. Owner/admin
   * only. The tracker token comes from the org's integration config (never the
   * request). POST /integrations/issue-sync.
   *
   * @example
   * await client.syncIssues({
   *   projectId, provider: "github",
   *   findings: [{ cveId: "CVE-2024-1", file: "lodash@4.17.20", title: "Proto pollution", severity: "high" }],
   * });
   */
  async syncIssues(input: IssueSyncInput): Promise<IssueSyncResponse> {
    if (!input?.projectId) throw new Error("projectId is required");
    if (input.provider !== "github" && input.provider !== "jira") {
      throw new Error('provider must be "github" or "jira"');
    }
    if (!Array.isArray(input.findings) || input.findings.length === 0) {
      throw new Error("findings must be a non-empty array");
    }
    return this.request("/integrations/issue-sync", "POST", input);
  }

  // ── Governance risk ────────────────────────────────────────────────

  /**
   * Composite multi-axis AI governance risk score (G12). Combines the per-axis
   * risk signals you provide (security findings, supply-chain/vulnerability
   * scores, compliance coverage, firewall hits, eval pass rate) into one
   * weighted 0-100 score with a per-axis breakdown + recommendations. Missing
   * axes are excluded from the composite (not penalized). POST /governance/risk.
   *
   * @example client.governanceRisk({ securityFindings: { critical: 1 }, complianceCoverage: 80 })
   */
  async governanceRisk(input: GovernanceRiskRequest): Promise<GovernanceRiskResult> {
    return this.request("/governance/risk", "POST", input);
  }

  // ── Multi-LLM consensus ─────────────────────────────────────────────

  /**
   * Reach consensus over N model responses to the same prompt (G13). You
   * generate the completions (via any provider/the gateway); this clusters them
   * and returns the agreed answer + an agreement score to gate high-stakes
   * actions on. POST /gateway/consensus.
   *
   * @example client.consensus({ candidates: [{ model: "gpt-4o", content: a }, { model: "claude", content: b }] })
   */
  async consensus(input: ConsensusRequest): Promise<ConsensusResponse> {
    if (!Array.isArray(input.candidates) || input.candidates.length === 0) {
      throw new Error("candidates must be a non-empty array");
    }
    return this.request("/gateway/consensus", "POST", input);
  }

  // ── Committed-secret detection (G10) ────────────────────────────────

  /**
   * Detect committed secrets (API keys, private keys, cloud/SaaS tokens) in
   * file contents — gitleaks-style, in-product. Pass a single `content` blob
   * or a `files` array (e.g. a PR's changed files). Findings carry only the
   * REDACTED match (never the raw secret). POST /security/secret-scan.
   *
   * @example client.scanSecrets({ content: "AKIA…", path: "config.ts" })
   * @example client.scanSecrets({ files: [{ path: ".env", content }], minSeverity: "high" })
   */
  async scanSecrets(input: SecretScanParams): Promise<SecretScanResult> {
    if (!input.content && !(Array.isArray(input.files) && input.files.length > 0)) {
      throw new Error("Provide `content` or a non-empty `files` array");
    }
    return this.request("/security/secret-scan", "POST", input);
  }

  // ── Data quality ───────────────────────────────────────────────────

  /** Run cleanlab-style data-quality detectors over a dataset (class imbalance,
   *  kNN-OOD outliers, near-duplicates, spurious feature correlations, non-IID
   *  ordering, + Confident-Learning label-error). POST /datasets/health. */
  async datasetHealth(params: DatasetHealthParams): Promise<DatasetHealthResult> {
    if (!params.labels && !params.embeddings && !params.features) {
      throw new Error("Provide at least one of: labels, embeddings, features");
    }
    return this.request("/datasets/health", "POST", params);
  }

  // ── Red-team planning ──────────────────────────────────────────────

  /** Capability-driven red-team plan: the attack categories + concrete plugins
   *  that apply to an agent's described capabilities. POST /security/red-team-plan. */
  async planRedTeam(params: RedTeamPlanParams = {}): Promise<RedTeamPlanResult> {
    return this.request("/security/red-team-plan", "POST", params);
  }

  // ── RAG ingest ─────────────────────────────────────────────────────

  /** Managed chunk(+embed) pipeline: chunk a batch of documents and, when
   *  `embed: true`, attach embeddings — retriever-agnostic (you store the result
   *  in your own vector DB). POST /rag/ingest. */
  async ragIngest(params: RagIngestParams): Promise<RagIngestResult> {
    if (!params.documents || params.documents.length === 0) {
      throw new Error("At least one document is required");
    }
    return this.request("/rag/ingest", "POST", params);
  }

  // ── Trace endpoint ─────────────────────────────────────────────────

  async trace(params: TraceParams): Promise<{ id: string }> {
    return this.request("/traces", "POST", params);
  }

  // ── Scorers & plugins ──────────────────────────────────────────────

  async listScorers(): Promise<Scorer[]> {
    return this.request("/scorers", "GET");
  }

  async listPlugins(): Promise<Plugin[]> {
    return this.request("/plugins", "GET");
  }

  // ── Firewall ───────────────────────────────────────────────────────

  async checkFirewall(params: FirewallCheckParams): Promise<FirewallResult> {
    // The /firewall/check route's `rules` field is a string[] of attack-category
    // names. Accept either bare strings or full FirewallRule objects (using each
    // rule's id) so existing callers that pass FirewallRule[] keep working.
    const rules = Array.isArray(params.rules)
      ? params.rules.map((r) => (typeof r === "string" ? r : r.id))
      : undefined;
    const body: Record<string, unknown> = { input: params.input };
    if (rules && rules.length > 0) body.rules = rules;
    if (params.sensitivity !== undefined) body.sensitivity = params.sensitivity;
    if (params.projectId) body.projectId = params.projectId;
    if (params.subjectEmail) body.subjectEmail = params.subjectEmail;
    if (params.subjectId) body.subjectId = params.subjectId;
    return this.request("/firewall/check", "POST", body);
  }

  // ── Visual workflows ───────────────────────────────────────────────

  /**
   * List workflows for a project (GET /workflows). Resolves the default
   * project when `projectId` is omitted.
   */
  async listWorkflows(projectId?: string): Promise<WorkflowSummary[]> {
    const pid = projectId ?? (await this.resolveProjectId());
    const res = await this.request<{ workflows: WorkflowSummary[] }>(
      `/workflows?projectId=${encodeURIComponent(pid)}`,
      "GET",
    );
    return res.workflows;
  }

  /**
   * Create a workflow (POST /workflows) — empty, or from a node/edge graph.
   */
  async createWorkflow(params: CreateWorkflowParams): Promise<WorkflowRecord> {
    return this.request("/workflows", "POST", {
      projectId: params.projectId,
      name: params.name,
      ...(params.description !== undefined ? { description: params.description } : {}),
      ...(params.tags ? { tags: params.tags } : {}),
      ...(params.nodes ? { nodes: params.nodes } : {}),
      ...(params.edges ? { edges: params.edges } : {}),
    });
  }

  /**
   * Enqueue a workflow run (POST /workflows/:id/run). Returns the pending
   * run record immediately; the worker executes it asynchronously, so poll
   * the run status separately.
   */
  async runWorkflow(
    workflowId: string,
    params: { projectId: string; inputs?: Record<string, unknown> },
  ): Promise<WorkflowRunRecord> {
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/run`,
      "POST",
      {
        projectId: params.projectId,
        ...(params.inputs ? { inputs: params.inputs } : {}),
      },
    );
  }

  // ── Agent observability ────────────────────────────────────────────

  /**
   * List agents with aggregated call/latency/guard/cost stats, rolled up
   * from ingested trace spans (GET /agents). Resolves the default project
   * when `projectId` is omitted.
   */
  async listAgents(
    projectId?: string,
    opts?: { agentName?: string; limit?: number; offset?: number },
  ): Promise<AgentListResult> {
    const pid = projectId ?? (await this.resolveProjectId());
    const qs = new URLSearchParams({ projectId: pid });
    if (opts?.agentName) qs.set("agentName", opts.agentName);
    if (opts?.limit !== undefined) qs.set("limit", String(opts.limit));
    if (opts?.offset !== undefined) qs.set("offset", String(opts.offset));
    return this.request(`/agents?${qs.toString()}`, "GET");
  }

  /**
   * Submit agent trace data (POST /agents) — converts the supplied steps into
   * trace spans. Resolves the default project when `projectId` is omitted.
   */
  async createAgent(params: CreateAgentParams): Promise<CreateAgentResult> {
    const projectId = params.projectId ?? (await this.resolveProjectId());
    return this.request("/agents", "POST", {
      projectId,
      agentName: params.agentName,
      ...(params.sessionId ? { sessionId: params.sessionId } : {}),
      ...(params.steps ? { steps: params.steps } : {}),
    });
  }

  // ── Guardrails (runtime input/output check) ─────────────────────────

  /**
   * Run a runtime guardrail check on `text` (POST /guardrails). When a
   * `projectId` is supplied the route applies that project's custom rules,
   * otherwise the default rule set. Returns the raw checkFirewall() result
   * ({ action, reasons, latencyMs }).
   */
  async runGuardrails(params: RunGuardrailsParams): Promise<GuardrailsCheckResult> {
    return this.request("/guardrails", "POST", {
      text: params.text,
      ...(params.projectId ? { projectId: params.projectId } : {}),
    });
  }

  // ── OpenAI-compatible chat completions ──────────────────────────────

  /**
   * OpenAI-compatible chat completion (POST /chat/completions). Routes to any
   * supported provider (resolving the caller's BYOK key server-side) and
   * returns the OpenAI-exact response body. Streaming is NOT supported by this
   * helper — point the OpenAI SDK at `${baseUrl}/chat/completions` for streams.
   */
  async chatCompletions(params: ChatCompletionsParams): Promise<ChatCompletionsResult> {
    if (params.stream) {
      throw new Error(
        "EvalGuard.chatCompletions does not support streaming; use the OpenAI SDK against the gateway base URL for SSE streams.",
      );
    }
    // The route returns the RAW OpenAI body (no { success, data } envelope);
    // request()'s envelope-unwrap is a no-op for it, so the response passes
    // through unchanged.
    return this.request("/chat/completions", "POST", { ...params, stream: false });
  }

  // ── Embeddings (store + similarity search) ──────────────────────────

  /**
   * Store an embedding vector (POST /embeddings, action="store").
   */
  async storeEmbedding(params: StoreEmbeddingParams): Promise<StoredEmbeddingRecord> {
    return this.request("/embeddings", "POST", {
      action: "store",
      projectId: params.projectId,
      id: params.id,
      vector: params.vector,
      ...(params.label !== undefined ? { label: params.label } : {}),
      ...(params.metadata ? { metadata: params.metadata } : {}),
    });
  }

  /**
   * Find the top-K most similar stored embeddings (POST /embeddings,
   * action="similar"). Pass either a raw `queryVector` or a stored `queryId`.
   */
  async findSimilarEmbeddings(
    params: FindSimilarEmbeddingsParams,
  ): Promise<EmbeddingSimilarityHit[]> {
    if (!params.queryVector?.length && !params.queryId) {
      throw new Error("findSimilarEmbeddings: either queryVector or queryId is required");
    }
    return this.request("/embeddings", "POST", {
      action: "similar",
      projectId: params.projectId,
      ...(params.queryVector ? { queryVector: params.queryVector } : {}),
      ...(params.queryId ? { queryId: params.queryId } : {}),
      ...(params.topK !== undefined ? { topK: params.topK } : {}),
    });
  }

  // ── Provider rerank (BYO vendor key) ────────────────────────────────

  /**
   * Rerank `documents` against `query` via a vendor reranker
   * (POST /retrieval/rerank). The vendor API key is passed via the
   * `x-provider-api-key` header and never stored. Returns the raw provider
   * result (NOT enveloped).
   */
  async rerank(params: RerankParams, vendorApiKey: string): Promise<RerankResult> {
    if (!vendorApiKey || vendorApiKey.length < 4) {
      throw new Error("rerank: a vendor API key (x-provider-api-key) is required");
    }
    const body: Record<string, unknown> = {
      orgId: params.orgId,
      query: params.query,
      documents: params.documents,
      model: params.model,
    };
    if (params.provider) body.provider = params.provider;
    if (params.topK !== undefined) body.topK = params.topK;
    if (params.baseUrl) body.baseUrl = params.baseUrl;
    if (params.timeoutMs !== undefined) body.timeoutMs = params.timeoutMs;
    return this.request("/retrieval/rerank", "POST", body, {
      "x-provider-api-key": vendorApiKey,
    });
  }

  // ── Hybrid retrieval (BM25 / RRF / MMR) ─────────────────────────────

  /**
   * Local lexical/hybrid/diversity reranking (POST /retrieval/hybrid):
   *   - "bm25":   query + documents[{id,text}]
   *   - "hybrid": query + documents[{id,text}] + denseRanking[{id}]
   *   - "mmr":    documents[{id,relevance,vector}]
   */
  async hybridRetrieval(params: HybridRetrievalParams): Promise<HybridRetrievalResult> {
    return this.request("/retrieval/hybrid", "POST", params);
  }

  // ── Corpus integrity ────────────────────────────────────────────────

  /**
   * Audit a RAG corpus for duplicates, conflicting knowledge, stale docs, and
   * low-trust sources (POST /retrieval/corpus-integrity). Returns the core
   * CorpusIntegrityReport. Requires editor role.
   */
  async corpusIntegrity(params: CorpusIntegrityParams): Promise<unknown> {
    const body: Record<string, unknown> = { documents: params.documents };
    if (params.orgId) body.orgId = params.orgId;
    if (params.projectId) body.projectId = params.projectId;
    if (params.nearDuplicateThreshold !== undefined) body.nearDuplicateThreshold = params.nearDuplicateThreshold;
    if (params.conflictThreshold !== undefined) body.conflictThreshold = params.conflictThreshold;
    if (params.maxAgeDays !== undefined) body.maxAgeDays = params.maxAgeDays;
    if (params.minTrust !== undefined) body.minTrust = params.minTrust;
    return this.request("/retrieval/corpus-integrity", "POST", body);
  }

  // ── Trace assistant: analyze spans ──────────────────────────────────

  /**
   * Analyze a trace's spans for issues + recommendations
   * (POST /traces/analyze). Pass `spans` directly, OR a `traceId` (which
   * requires `projectId` so the store read fail-closes to your tenant). Set
   * `callLLM: false` for fast rule-based-only analysis.
   *
   * NOTE: distinct from {@link EvalGuard.analyzeTrace}, which asks the debug
   * agent for a fix on a persisted trace.
   */
  async analyzeTraceSpans(params: AnalyzeTraceSpansParams): Promise<unknown> {
    if (params.traceId === undefined && params.spans === undefined) {
      throw new Error("analyzeTraceSpans: either traceId or spans is required");
    }
    const body: Record<string, unknown> = {};
    if (params.traceId !== undefined) body.traceId = params.traceId;
    if (params.spans !== undefined) body.spans = params.spans;
    if (params.callLLM !== undefined) body.callLLM = params.callLLM;
    if (params.projectId !== undefined) body.projectId = params.projectId;
    return this.request("/traces/analyze", "POST", body);
  }

  // ── Trace → dataset curation ────────────────────────────────────────

  /**
   * Convert one or more traces into dataset cases (POST /traces/to-dataset),
   * with near-duplicate removal + quality classification. Requires editor role.
   */
  async traceToDataset(params: TraceToDatasetParams): Promise<TraceToDatasetResult> {
    if (params.traceId === undefined && (!params.traceIds || params.traceIds.length === 0)) {
      throw new Error("traceToDataset: either traceId or a non-empty traceIds is required");
    }
    const body: Record<string, unknown> = {
      datasetId: params.datasetId,
      projectId: params.projectId,
    };
    if (params.traceIds && params.traceIds.length > 0) body.traceIds = params.traceIds;
    else body.traceId = params.traceId;
    if (params.deduplicate !== undefined) body.deduplicate = params.deduplicate;
    return this.request("/traces/to-dataset", "POST", body);
  }

  // ── Trace export / import ───────────────────────────────────────────

  /**
   * Export trace spans as OpenInference-shaped OTLP-JSON
   * (GET /traces/export). Returns the RAW OTLP-JSON object (not enveloped),
   * ready to POST into Phoenix / Datadog / any OTLP-JSON receiver. Resolves
   * the default project when `projectId` is omitted.
   */
  async exportTraces(
    projectId?: string,
    opts?: { traceId?: string; since?: string; limit?: number; format?: "otlp-json" },
  ): Promise<unknown> {
    const pid = projectId ?? (await this.resolveProjectId());
    const qs = new URLSearchParams({ projectId: pid });
    if (opts?.format) qs.set("format", opts.format);
    if (opts?.traceId) qs.set("traceId", opts.traceId);
    if (opts?.since) qs.set("since", opts.since);
    if (opts?.limit !== undefined) qs.set("limit", String(opts.limit));
    return this.request(`/traces/export?${qs.toString()}`, "GET");
  }

  /**
   * Import a trace export from Helicone / Langfuse / Portkey / HuggingFace
   * (POST /traces/import). Requires editor role.
   */
  async importTraces(params: ImportTracesParams): Promise<ImportTracesResult> {
    return this.request("/traces/import", "POST", {
      platform: params.platform,
      projectId: params.projectId,
      payload: params.payload,
    });
  }

  // ── Trace aggregate (analytics) ─────────────────────────────────────

  /**
   * Aggregate trace analytics (GET /traces/aggregate): per-minute span volume,
   * error rate, and p50/p95/p99 latency by model. `orgId` is required; pass a
   * `projectId` for the Postgres fallback path.
   */
  async aggregateTraces(params: AggregateTracesParams): Promise<AggregateTracesResult> {
    const qs = new URLSearchParams({ orgId: params.orgId });
    if (params.projectId) qs.set("projectId", params.projectId);
    if (params.model) qs.set("model", params.model);
    if (params.since) qs.set("since", params.since);
    if (params.maxScanSpans !== undefined) qs.set("maxScanSpans", String(params.maxScanSpans));
    return this.request(`/traces/aggregate?${qs.toString()}`, "GET");
  }

  // ── Code evaluation ─────────────────────────────────────────────────

  /**
   * Score LLM-generated code with the code scorers (POST /eval/code):
   * correctness, security, style, type-safety (heuristic) + mypy / pyright /
   * E2B runs when the external binaries/keys are available (fail-soft).
   */
  async evalCode(params: EvalCodeParams): Promise<EvalCodeResult> {
    const body: Record<string, unknown> = { code: params.code };
    if (params.expected !== undefined) body.expected = params.expected;
    if (params.input !== undefined) body.input = params.input;
    if (params.scorers) body.scorers = params.scorers;
    if (params.options) body.options = params.options;
    return this.request("/eval/code", "POST", body);
  }

  // ── MCP gateway tool invocation ─────────────────────────────────────

  /**
   * Invoke an MCP tool through the gateway (POST /mcp/invoke). The decision
   * pipeline (RBAC → CIMD → agent-authz → firewall → rate-limit → dispatch →
   * quarantine → audit) runs server-side; this returns the structured result.
   */
  async mcpInvoke(params: McpInvokeParams): Promise<McpInvokeResult> {
    const body: Record<string, unknown> = {
      serverId: params.serverId,
      toolName: params.toolName,
    };
    if (params.arguments) body.arguments = params.arguments;
    if (params.jwt) body.jwt = params.jwt;
    if (params.taskGoal) body.taskGoal = params.taskGoal;
    if (params.clientId) body.clientId = params.clientId;
    if (params.cimdJws) body.cimdJws = params.cimdJws;
    if (params.cimdNonce) body.cimdNonce = params.cimdNonce;
    const extraHeaders = params.runId
      ? { "x-evalguard-mcp-run-id": params.runId }
      : undefined;
    return this.request("/mcp/invoke", "POST", body, extraHeaders);
  }

  // ── Benchmarks ─────────────────────────────────────────────────────

  /**
   * Submit a completed benchmark run to the leaderboard.
   * `POST /v1/benchmarks` records a result — `{ benchmark, model, totalScore, scores? }`.
   * (Contract verified against the live API 2026-06-17.)
   */
  async submitBenchmark(params: BenchmarkParams): Promise<BenchmarkResult> {
    return this.request("/benchmarks", "POST", params);
  }

  /**
   * @deprecated The old `{ suites, model }` payload was rejected by the API (400).
   * Use {@link submitBenchmark} with `{ benchmark, model, totalScore }` instead.
   */
  async runBenchmarks(_params: { suites: string[]; model: string }): Promise<never> {
    throw new Error(
      "runBenchmarks({ suites, model }) is not supported by the API — it records a " +
        "benchmark result. Use submitBenchmark({ benchmark, model, totalScore, scores }).",
    );
  }

  // ── Export ─────────────────────────────────────────────────────────

  /**
   * Export an eval run as DPO (Direct Preference Optimization) JSONL.
   * @param evalId  the eval RUN id
   * @param projectId  the project the run belongs to (required by the export API)
   *
   * (Repointed to the real `/exports` contract — the old `/evals/{id}/export/dpo`
   * path 404'd; audit 2026-06-14 #7.)
   */
  async exportDpo(evalId: string, projectId: string): Promise<string> {
    const q = `?runId=${encodeURIComponent(evalId)}&format=dpo&projectId=${encodeURIComponent(projectId)}`;
    return this.requestText(`/exports${q}`, "GET");
  }

  /**
   * Export a security scan as a Burp Suite issue-definition XML.
   * @param scanId  the security SCAN id
   * @param projectId  the project the scan belongs to (required by the export API)
   *
   * (Repointed to the real `/exports` contract — the old `/scans/{id}/export/burp`
   * path 404'd; audit 2026-06-14 #7.)
   */
  async exportBurp(scanId: string, projectId: string): Promise<string> {
    const q = `?runId=${encodeURIComponent(scanId)}&format=burp&projectId=${encodeURIComponent(projectId)}`;
    return this.requestText(`/exports${q}`, "GET");
  }

  // ── Compliance ─────────────────────────────────────────────────────

  /**
   * Map a security scan's findings onto a compliance framework.
   * Backed by `GET /api/v1/security/{scanId}/compliance` (audit 2026-06-14 #7).
   */
  async getComplianceReport(params: ComplianceReportParams): Promise<ComplianceReport> {
    const { scanId, framework } = params;
    const query = `?framework=${encodeURIComponent(framework)}`;
    return this.request(`/security/${encodeURIComponent(scanId)}/compliance${query}`, "GET");
  }

  // ── Drift detection ────────────────────────────────────────────────

  /**
   * Detect performance drift between a baseline and a current eval run (z-score
   * over per-case score/latency). Backed by `POST /api/v1/monitoring/drift/detect`
   * (audit 2026-06-14 #7).
   */
  async detectDrift(params: DriftDetectParams): Promise<DriftReport> {
    return this.request("/monitoring/drift/detect", "POST", params);
  }

  // ── Smart routing ─────────────────────────────────────────────────

  async smartRoute(testCases: { input: string; scorers?: string[] }[]): Promise<unknown> {
    return this.request("/smart-routing/test-cases", "POST", { testCases });
  }

  // ── Autopilot ─────────────────────────────────────────────────────

  async autopilot(params: { description: string; depth: "quick" | "standard" | "deep"; projectId: string; complianceFrameworks?: string[] }): Promise<unknown> {
    return this.request("/autopilot", "POST", params);
  }

  async getAutopilotConfig(): Promise<unknown> {
    return this.request("/autopilot", "GET");
  }

  // ── Pipeline builder ──────────────────────────────────────────────

  async createPipeline(params: { templateId?: string; projectId: string; config?: unknown }): Promise<unknown> {
    return this.request("/pipelines", "POST", params);
  }

  async listPipelines(): Promise<unknown> {
    return this.request("/pipelines", "GET");
  }

  // ── Leaderboard ───────────────────────────────────────────────────

  async getLeaderboard(category?: string): Promise<unknown> {
    const q = category ? `?category=${encodeURIComponent(category)}` : "";
    return this.request(`/leaderboard${q}`, "GET");
  }

  // ── Cost & FinOps ─────────────────────────────────────────────────

  async getCost(projectId: string, period: string = "30d"): Promise<unknown> {
    // The server REQUIRES period (one of 7d/30d/90d) and 400s without it, so we
    // default it here instead of leaving it optional-but-unsent (live E2E 2026-06-15).
    const q = `?projectId=${encodeURIComponent(projectId)}&period=${encodeURIComponent(period)}`;
    return this.request(`/cost${q}`, "GET");
  }

  async getCostSavings(projectId: string, period?: string): Promise<unknown> {
    const q = `?projectId=${encodeURIComponent(projectId)}${period ? `&period=${period}` : ""}`;
    return this.request(`/cost/savings${q}`, "GET");
  }

  async getCostForecast(projectId: string): Promise<unknown> {
    return this.request(`/cost/forecast?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getCostBudget(projectId: string): Promise<unknown> {
    return this.request(`/cost/budget?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Security effectiveness ────────────────────────────────────────

  async getSecurityEffectiveness(projectId: string): Promise<unknown> {
    return this.request(`/security/effectiveness?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getSecurityReport(scanId: string): Promise<unknown> {
    return this.request(`/security/report?scanId=${encodeURIComponent(scanId)}`, "GET");
  }

  // ── Support ───────────────────────────────────────────────────────

  async submitTicket(params: { type: string; subject: string; description: string; priority?: string; metadata?: Record<string, unknown> }): Promise<unknown> {
    return this.request("/support", "POST", params);
  }

  async listTickets(status?: string): Promise<unknown> {
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    return this.request(`/support${q}`, "GET");
  }

  // ── Traces & Observability ────────────────────────────────────────

  async listTraces(projectId: string): Promise<unknown> {
    return this.request(`/traces?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getTrace(traceId: string): Promise<unknown> {
    return this.request(`/traces/${encodeURIComponent(traceId)}`, "GET");
  }

  async searchTraces(projectId: string, query: string): Promise<unknown> {
    return this.request(`/traces/search?projectId=${encodeURIComponent(projectId)}&q=${encodeURIComponent(query)}`, "GET");
  }

  async ingestOTLP(resourceSpans: unknown[]): Promise<unknown> {
    return this.request("/ingest/otlp/traces", "POST", { resourceSpans });
  }

  // ── Monitoring ────────────────────────────────────────────────────

  async getMonitoringAnalytics(projectId: string): Promise<unknown> {
    return this.request(`/monitoring/analytics?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getMonitoringAlerts(projectId: string): Promise<unknown> {
    return this.request(`/monitoring/alerts?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getMonitoringDrift(projectId: string): Promise<unknown> {
    return this.request(`/monitoring/drift?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getMonitoringSLA(projectId: string): Promise<unknown> {
    return this.request(`/monitoring/sla?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Compliance (extended) ─────────────────────────────────────────

  async checkCompliance(projectId: string, framework?: string): Promise<unknown> {
    const q = `?projectId=${encodeURIComponent(projectId)}${framework ? `&framework=${framework}` : ""}`;
    return this.request(`/compliance/check${q}`, "GET");
  }

  /**
   * Gap analysis for a compliance `framework`. The GET route REQUIRES a
   * framework (it returns that framework's requirement set with an empty gap
   * report) and 400s without one, so `framework` is forwarded when supplied.
   * `projectId` is kept for forward-compat / tenant context.
   */
  async getComplianceGaps(projectId: string, framework?: string): Promise<unknown> {
    const q = `?projectId=${encodeURIComponent(projectId)}${framework ? `&framework=${encodeURIComponent(framework)}` : ""}`;
    return this.request(`/compliance/gaps${q}`, "GET");
  }

  async exportCompliance(projectId: string, format?: string): Promise<unknown> {
    const q = `?projectId=${encodeURIComponent(projectId)}${format ? `&format=${format}` : ""}`;
    return this.request(`/compliance/export${q}`, "GET");
  }

  async getModelCards(projectId: string): Promise<unknown> {
    return this.request(`/compliance/model-cards?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Prompts ───────────────────────────────────────────────────────

  async createPrompt(params: { projectId: string; name: string; content: string; model?: string; tags?: string[] }): Promise<unknown> {
    return this.request("/prompts", "POST", params);
  }

  async listPrompts(projectId: string): Promise<unknown> {
    return this.request(`/prompts?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Datasets ──────────────────────────────────────────────────────

  async createDataset(params: { projectId: string; name: string; cases?: unknown[]; description?: string }): Promise<unknown> {
    return this.request("/datasets", "POST", params);
  }

  async listDatasets(projectId: string): Promise<unknown> {
    return this.request(`/datasets?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Dataset versioning (Phase 6b, 2026-05-22) ─────────────────────
  //
  // Mirrors the Python SDK (7b30f31e) + Java SDK (cc2bb744). Same loose
  // unknown return type — callers cast into their own DTO if they want
  // typed access; the JSON shape is documented in /docs/dataset-versioning.

  async listDatasetVersions(datasetId: string): Promise<unknown> {
    return this.request(`/datasets/${encodeURIComponent(datasetId)}/versions`, "GET");
  }

  async snapshotDataset(datasetId: string, description?: string): Promise<unknown> {
    return this.request(
      `/datasets/${encodeURIComponent(datasetId)}/versions`,
      "POST",
      description !== undefined ? { description } : {},
    );
  }

  async getDatasetVersion(datasetId: string, versionId: string): Promise<unknown> {
    return this.request(
      `/datasets/${encodeURIComponent(datasetId)}/versions/${encodeURIComponent(versionId)}`,
      "GET",
    );
  }

  async restoreDatasetVersion(datasetId: string, versionId: string): Promise<unknown> {
    return this.request(
      `/datasets/${encodeURIComponent(datasetId)}/versions/${encodeURIComponent(versionId)}/restore`,
      "POST",
      {},
    );
  }

  async diffDatasetVersions(
    datasetId: string,
    fromVersionId: string,
    toVersionId: string,
  ): Promise<unknown> {
    return this.request(
      `/datasets/${encodeURIComponent(datasetId)}/versions/${encodeURIComponent(fromVersionId)}/diff?to=${encodeURIComponent(toVersionId)}`,
      "GET",
    );
  }

  // ── Visual workflow versioning (snapshot / diff / restore) ─────────
  //
  // Brings visual workflows to parity with datasets: immutable nodes+edges
  // snapshots, content-hash deduped, with diff + revert. Mirrors the
  // /api/v1/workflows/:id/versions routes. Workflows are project-scoped so
  // every call takes projectId. Loose `unknown` return — callers cast into
  // their own DTO; the JSON shape is documented in the OpenAPI spec.

  /** List a workflow's version snapshots (newest-first; nodes/edges omitted). */
  async listWorkflowVersions(workflowId: string, projectId: string): Promise<unknown> {
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/versions?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /** Snapshot a workflow's current nodes+edges. Deduped — returns unchanged:true if no change. */
  async snapshotWorkflow(workflowId: string, projectId: string, description?: string): Promise<unknown> {
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/versions`,
      "POST",
      description !== undefined ? { projectId, description } : { projectId },
    );
  }

  /** Fetch one snapshot in full (nodes + edges included). */
  async getWorkflowVersion(workflowId: string, versionId: string, projectId: string): Promise<unknown> {
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/versions/${encodeURIComponent(versionId)}?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /** Diff a snapshot against the live workflow, or against another snapshot via toVersionId. */
  async diffWorkflowVersion(
    workflowId: string,
    versionId: string,
    projectId: string,
    toVersionId?: string,
  ): Promise<unknown> {
    const to = toVersionId ? `&to=${encodeURIComponent(toVersionId)}` : "";
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/versions/${encodeURIComponent(versionId)}/diff?projectId=${encodeURIComponent(projectId)}${to}`,
      "GET",
    );
  }

  /** Revert the live workflow to a snapshot (copies its nodes+edges back). */
  async restoreWorkflowVersion(workflowId: string, versionId: string, projectId: string): Promise<unknown> {
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/versions/${encodeURIComponent(versionId)}/restore`,
      "POST",
      { projectId },
    );
  }

  // ── Evaluator Hub (versioned, reusable evaluator registry) ────────
  //
  // Arize-parity registry: one row per (project, name, version), content-hash
  // deduped. Mirrors the CLI (`evalguard evaluators list|diff`) + the
  // /api/v1/evaluators routes. Loose `unknown` return — callers cast into their
  // own DTO; the JSON shape is documented in the OpenAPI spec.

  /** List evaluator versions (all, newest-first). Pass `name` for one evaluator's history. */
  async listEvaluators(projectId: string, name?: string): Promise<unknown> {
    if (!projectId) throw new Error("projectId is required");
    const q = new URLSearchParams({ projectId });
    if (name) q.set("name", name);
    return this.request(`/evaluators?${q.toString()}`, "GET");
  }

  /** Create a new evaluator version (content-hash deduped against the latest). */
  async createEvaluator(params: {
    projectId: string;
    name: string;
    definition: {
      kind: "llm-judge" | "code" | "heuristic" | "composite";
      config?: Record<string, unknown>;
      threshold?: number;
    };
    notes?: string;
    activate?: boolean;
  }): Promise<unknown> {
    return this.request("/evaluators", "POST", params);
  }

  /** Field-level diff between two versions of a named evaluator. */
  async diffEvaluatorVersions(params: {
    projectId: string;
    name: string;
    fromVersion: number;
    toVersion: number;
  }): Promise<unknown> {
    return this.request("/evaluators/diff", "POST", params);
  }

  // ── Scorer calibration (CLHF — continuous learning from human feedback) ──
  //
  // Quantifies evaluator/human agreement (chance-corrected Cohen's kappa) and
  // recommends the score threshold that maximizes agreement. Galileo/Patronus
  // parity. Supply `pairs` (human/machine labels) and/or `scored`
  // (humanPass + machineScore).

  async calibrateScorer(params: {
    projectId?: string;
    scorerId?: string;
    pairs?: Array<{ human: boolean; machine: boolean }>;
    scored?: Array<{ humanPass: boolean; machineScore: number }>;
    currentThreshold?: number;
  }): Promise<{
    scorerId: string | null;
    agreement?: { kappa: number; accuracy: number; confusion: Record<string, number> };
    threshold?: { best: number; agreementAtBest: number; improvement: number };
  }> {
    if (
      (!params.pairs || params.pairs.length === 0) &&
      (!params.scored || params.scored.length === 0)
    ) {
      throw new Error("calibrateScorer: provide at least one of `pairs` or `scored`");
    }
    return this.request("/scorers/calibrate", "POST", params);
  }

  // ── NL Pipeline ───────────────────────────────────────────────────

  async ask(question: string, projectId?: string): Promise<unknown> {
    return this.request("/ask", "POST", { question, projectId });
  }

  async generateEvalSuite(description: string, projectId?: string): Promise<unknown> {
    return this.request("/generate-eval-suite", "POST", { description, projectId });
  }

  // ── AI SBOM ───────────────────────────────────────────────────────

  async getAISBOM(projectId: string): Promise<unknown> {
    return this.request(`/ai-sbom?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  /**
   * Generate an AI-SBOM from project manifests with a supply-chain scan:
   * live OSV.dev CVE lookups (default on) over the full resolved dependency
   * graph, plus typosquat detection. Pass lockfiles for transitive coverage.
   * (Previously sent `{projectId}`, which the API rejected — projectName is
   * the required field.)
   */
  async generateAISBOM(
    projectName: string,
    options: {
      projectVersion?: string;
      format?: "json" | "cyclonedx" | "spdx";
      packageJson?: Record<string, unknown>;
      packageLockJson?: Record<string, unknown>;
      pythonRequirements?: string;
      poetryLock?: string;
      evalguardConfig?: Record<string, unknown>;
      providerKeys?: string[];
      liveCveScan?: boolean;
    } = {},
  ): Promise<unknown> {
    return this.request("/ai-sbom/generate", "POST", { projectName, ...options });
  }

  // ── Gateway ───────────────────────────────────────────────────────

  async getGatewayConfig(projectId: string): Promise<unknown> {
    return this.request(`/gateway?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async getGatewayHealth(): Promise<unknown> {
    return this.request("/gateway/health", "GET");
  }

  async getGatewayStats(projectId: string): Promise<unknown> {
    return this.request(`/gateway/stats?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Guardrails ────────────────────────────────────────────────────

  async listGuardrails(projectId: string): Promise<unknown> {
    return this.request(`/guardrails?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async generateGuardrails(params: { description: string; projectId: string }): Promise<unknown> {
    return this.request("/guardrails/generate", "POST", params);
  }

  // ── Threat Intelligence ───────────────────────────────────────────

  async getThreatIntelligence(projectId: string): Promise<unknown> {
    return this.request(`/threat-intelligence?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── SIEM ──────────────────────────────────────────────────────────

  async getSIEMConnectors(projectId: string): Promise<unknown> {
    return this.request(`/siem?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Annotations ───────────────────────────────────────────────────

  async listAnnotations(projectId: string): Promise<unknown> {
    return this.request(`/annotations?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async createAnnotation(params: { projectId: string; logId: string; label: string; score?: number; notes?: string }): Promise<unknown> {
    return this.request("/annotations", "POST", params);
  }

  // ── Eval Schedules ────────────────────────────────────────────────

  async listEvalSchedules(projectId: string): Promise<unknown> {
    return this.request(`/eval-schedules?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Incidents ─────────────────────────────────────────────────────

  async listIncidents(projectId: string): Promise<unknown> {
    return this.request(`/incidents?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  /**
   * Run the alert-triggered RCA loop (G6) on demand over a trace window.
   * Composes the error-classifier + trace-assistant (the same orchestrator the
   * worker fires automatically on error_spike / sla_breach alerts) and returns
   * a structured RCA: probable cause, evidence trace ids, recommendations.
   */
  async runIncidentRca(input: {
    projectId: string;
    trigger?: "error_spike" | "sla_breach";
    windowMinutes?: number;
    alertMessage?: string;
    metric?: string;
    value?: number;
    threshold?: number;
    useLLM?: boolean;
  }): Promise<unknown> {
    return this.request(`/incidents/rca`, "POST", input);
  }

  // ── Feature Flags ─────────────────────────────────────────────────

  async listFeatureFlags(projectId: string): Promise<unknown> {
    return this.request(`/feature-flags?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Exports ───────────────────────────────────────────────────────

  async exportResults(runId: string, format: string, projectId: string): Promise<unknown> {
    return this.request(`/exports?runId=${encodeURIComponent(runId)}&format=${encodeURIComponent(format)}&projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Audit Logs ────────────────────────────────────────────────────

  async getAuditLogs(orgId: string): Promise<unknown> {
    return this.request(`/audit-logs?orgId=${encodeURIComponent(orgId)}`, "GET");
  }

  // ── Team ──────────────────────────────────────────────────────────

  async listTeam(orgId: string): Promise<unknown> {
    return this.request(`/team?orgId=${encodeURIComponent(orgId)}`, "GET");
  }

  // ── Webhooks ──────────────────────────────────────────────────────

  async listWebhooks(orgId: string): Promise<unknown> {
    return this.request(`/webhooks?orgId=${encodeURIComponent(orgId)}`, "GET");
  }

  // ── Notifications ─────────────────────────────────────────────────

  async listNotifications(): Promise<unknown> {
    return this.request("/notifications", "GET");
  }

  // ── Settings ──────────────────────────────────────────────────────

  async getSettings(projectId: string): Promise<unknown> {
    return this.request(`/settings?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Marketplace ───────────────────────────────────────────────────

  async getMarketplace(): Promise<unknown> {
    return this.request("/marketplace", "GET");
  }

  // ── Templates ─────────────────────────────────────────────────────

  async listTemplates(): Promise<unknown> {
    return this.request("/templates", "GET");
  }

  // ── Provider keys (BYOK vault) ────────────────────────────────────
  //
  // Plaintext API keys submitted here are encrypted via Supabase Vault
  // (libsodium envelope) and never returned in responses. The `.list()`
  // and `.delete()` paths use only the vault_secret_id pointer + last-4
  // chars for display.

  async listProviderKeys(orgId: string, projectId?: string): Promise<{
    keys: Array<{
      id: string;
      provider: string;
      project_id: string | null;
      label: string | null;
      key_last4: string | null;
      created_at: string;
      rotated_at: string | null;
    }>;
    total: number;
  }> {
    const q = projectId
      ? `?orgId=${encodeURIComponent(orgId)}&projectId=${encodeURIComponent(projectId)}`
      : `?orgId=${encodeURIComponent(orgId)}`;
    return this.request(`/provider-keys${q}`, "GET");
  }

  async upsertProviderKey(params: {
    orgId: string;
    provider: string;
    apiKey: string;
    projectId?: string | null;
    label?: string;
  }): Promise<{
    key: {
      id: string;
      provider: string;
      project_id: string | null;
      label: string | null;
      key_last4: string | null;
      created_at: string;
      rotated_at: string | null;
    };
    rotated: boolean;
  }> {
    return this.request("/provider-keys", "POST", params);
  }

  async deleteProviderKey(orgId: string, keyId: string): Promise<{ id: string; deleted: true }> {
    return this.request(
      `/provider-keys?id=${encodeURIComponent(keyId)}&orgId=${encodeURIComponent(orgId)}`,
      "DELETE",
    );
  }

  // ── Models registry (custom pricing) ──────────────────────────────

  async listModels(orgId: string, projectId?: string): Promise<{
    models: Array<{
      id: string;
      model_name: string;
      provider: string | null;
      display_name: string | null;
      input_price_per_1m_usd: number;
      output_price_per_1m_usd: number;
      context_window: number | null;
      notes: string | null;
    }>;
    total: number;
  }> {
    const q = projectId
      ? `?orgId=${encodeURIComponent(orgId)}&projectId=${encodeURIComponent(projectId)}`
      : `?orgId=${encodeURIComponent(orgId)}`;
    return this.request(`/models/registry${q}`, "GET");
  }

  async upsertModel(params: {
    orgId: string;
    modelName: string;
    inputPricePer1mUsd: number;
    outputPricePer1mUsd: number;
    projectId?: string | null;
    provider?: string;
    displayName?: string;
    contextWindow?: number;
    notes?: string;
  }): Promise<{ model: Record<string, unknown>; created: boolean }> {
    return this.request("/models/registry", "POST", params);
  }

  async deleteModel(orgId: string, modelId: string): Promise<{ id: string; deleted: true }> {
    return this.request(
      `/models/registry?id=${encodeURIComponent(modelId)}&orgId=${encodeURIComponent(orgId)}`,
      "DELETE",
    );
  }

  // ── API-key budget caps ───────────────────────────────────────────

  async getApiKeyBudget(keyId: string): Promise<{
    keyId: string;
    name: string;
    monthlyBudgetUsd: number | null;
    /** Cadence at which the spend counter auto-resets: daily | weekly | monthly. */
    resetPeriod: ApiKeyBudgetResetPeriod;
    currentPeriodSpentUsd: number;
    currentPeriodStartedAt: string;
    remainingUsd: number | null;
    percentUsed: number | null;
    staleReset: boolean;
  }> {
    return this.request(`/api-keys/${encodeURIComponent(keyId)}/budget`, "GET");
  }

  /**
   * Set a virtual key's spend cap and/or its reset cadence.
   *
   * @param monthlyBudgetUsd  number = set/update the cap, null = remove it,
   *                          undefined = leave the cap unchanged (only change cadence).
   * @param resetPeriod       optional: 'daily' | 'weekly' | 'monthly' (default monthly).
   */
  async setApiKeyBudget(
    keyId: string,
    monthlyBudgetUsd: number | null | undefined,
    resetPeriod?: ApiKeyBudgetResetPeriod,
  ): Promise<{
    keyId: string;
    monthlyBudgetUsd: number | null;
    resetPeriod: ApiKeyBudgetResetPeriod;
    currentPeriodSpentUsd: number;
    currentPeriodStartedAt: string;
  }> {
    const payload: { monthlyBudgetUsd?: number | null; resetPeriod?: ApiKeyBudgetResetPeriod } = {};
    if (monthlyBudgetUsd !== undefined) payload.monthlyBudgetUsd = monthlyBudgetUsd;
    if (resetPeriod !== undefined) payload.resetPeriod = resetPeriod;
    return this.request(`/api-keys/${encodeURIComponent(keyId)}/budget`, "PATCH", payload);
  }

  async removeApiKeyBudget(keyId: string): Promise<{ keyId: string; monthlyBudgetUsd: null }> {
    return this.request(`/api-keys/${encodeURIComponent(keyId)}/budget`, "DELETE");
  }

  // ── Async batch inference (discounted tier) ───────────────────────
  // Submit many chat requests as one async batch processed off the gateway hot
  // path. The batch tier is billed at a discount off the synchronous list price
  // (default 50%, like OpenAI/Fireworks); cost is surfaced as observability on
  // the batch (list_cost_usd vs cost_usd). See POST/GET /api/v1/batches.

  /**
   * Submit an async batch of chat requests.
   * @param opts.discountPct  % off the list price for this batch's recorded cost
   *                          (default = platform BATCH_DISCOUNT_PCT, else 50).
   */
  async createBatch(opts: {
    projectId: string;
    requests: Array<BatchInferenceRequest>;
    model?: string;
    endpoint?: string;
    completionWindow?: string;
    discountPct?: number;
    metadata?: Record<string, unknown>;
  }): Promise<{
    id: string;
    status: string;
    endpoint: string;
    total_requests: number;
    created_at: string;
    expires_at: string;
    discount_pct: number;
  }> {
    const body: Record<string, unknown> = {
      projectId: opts.projectId,
      requests: opts.requests,
    };
    if (opts.model !== undefined) body.model = opts.model;
    if (opts.endpoint !== undefined) body.endpoint = opts.endpoint;
    if (opts.completionWindow !== undefined) body.completion_window = opts.completionWindow;
    if (opts.discountPct !== undefined) body.discount_pct = opts.discountPct;
    if (opts.metadata !== undefined) body.metadata = opts.metadata;
    return this.request("/batches", "POST", body);
  }

  /** Poll a batch's status, counts, results, and cost (list vs discounted). */
  async getBatch(batchId: string): Promise<BatchInferenceView> {
    return this.request(`/batches/${encodeURIComponent(batchId)}`, "GET");
  }

  /** List recent batches for a project (newest first, capped at 50). */
  async listBatches(projectId: string): Promise<BatchInferenceView[]> {
    return this.request(`/batches?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  /** Cancel an in-flight batch. Completed requests keep their results + cost. */
  async cancelBatch(batchId: string): Promise<{ id: string; status: string }> {
    return this.request(`/batches/${encodeURIComponent(batchId)}/cancel`, "POST");
  }

  // ── Per-key governance limits (G4) ────────────────────────────────
  // TPM / RPM / max-parallel rate limits + a model allow-list, all enforced
  // server-side at the gateway proxy. Limits are OPTIONAL on create and PATCHable
  // afterward; null clears a rate limit, [] clears the allow-list.

  /**
   * Create a new platform API key. The full key (rawKey) is returned ONLY here.
   * Optionally seed per-key limits (TPM/RPM/max-parallel/model allow-list).
   */
  async createApiKey(params: {
    orgId: string;
    name: string;
    scopes?: string[];
    expiresAt?: string | null;
    tpmLimit?: number | null;
    rpmLimit?: number | null;
    maxParallel?: number | null;
    modelAllowlist?: string[] | null;
  }): Promise<{ id: string; name: string; key_prefix: string; created_at: string; rawKey: string }> {
    return this.request("/api-keys", "POST", params);
  }

  /**
   * Update the per-key governance limits for an existing key. Only the provided
   * fields change; pass `null` to clear a rate limit, `[]` to clear the model
   * allow-list. Requires editor role.
   */
  async setApiKeyLimits(
    keyId: string,
    limits: {
      tpmLimit?: number | null;
      rpmLimit?: number | null;
      maxParallel?: number | null;
      modelAllowlist?: string[] | null;
    },
  ): Promise<{
    id: string;
    name: string;
    key_prefix: string;
    tpmLimit: number | null;
    rpmLimit: number | null;
    maxParallel: number | null;
    modelAllowlist: string[] | null;
  }> {
    return this.request(`/api-keys/${encodeURIComponent(keyId)}`, "PATCH", limits);
  }

  // ── Trace attachments (inline blob storage) ───────────────────────

  async listTraceAttachments(traceId: string, projectId: string): Promise<{
    attachments: Array<{
      id: string;
      span_id: string;
      name: string;
      mime_type: string;
      size_bytes: number;
      metadata: Record<string, unknown>;
      created_at: string;
    }>;
    total: number;
  }> {
    return this.request(
      `/traces/${encodeURIComponent(traceId)}/attachments?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /**
   * Upload a blob (image / audio / text / json / pdf) attached to a span.
   * Accepts base64 string, ArrayBuffer, or Uint8Array. Enforces a 1 MB
   * payload limit client-side so the server doesn't waste a round-trip
   * on oversized uploads.
   */
  async uploadTraceAttachment(params: {
    traceId: string;
    projectId: string;
    spanId: string;
    name: string;
    mimeType: string;
    data: string | ArrayBuffer | Uint8Array;
    metadata?: Record<string, unknown>;
  }): Promise<{ attachment: Record<string, unknown> }> {
    let b64: string;
    if (typeof params.data === "string") {
      b64 = params.data;
    } else {
      const bytes = params.data instanceof Uint8Array
        ? params.data
        : new Uint8Array(params.data);
      // Browser + Node both support btoa via bytes → Latin1 string path.
      let s = "";
      for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      b64 = typeof btoa === "function" ? btoa(s) : Buffer.from(bytes).toString("base64");
    }

    const paddingCount = (b64.match(/=/g) ?? []).length;
    const decodedBytes = Math.floor(b64.length * 3 / 4) - paddingCount;
    if (decodedBytes > 1_048_576) {
      throw new Error(`Attachment exceeds 1 MB (got ${decodedBytes} bytes). V1 only supports inline storage.`);
    }

    return this.request(`/traces/${encodeURIComponent(params.traceId)}/attachments`, "POST", {
      projectId: params.projectId,
      spanId: params.spanId,
      name: params.name,
      mimeType: params.mimeType,
      dataBase64: b64,
      metadata: params.metadata,
    });
  }

  async deleteTraceAttachment(traceId: string, attachmentId: string, projectId: string): Promise<{
    id: string;
    deleted: true;
  }> {
    return this.request(
      `/traces/${encodeURIComponent(traceId)}/attachments?id=${encodeURIComponent(attachmentId)}&projectId=${encodeURIComponent(projectId)}`,
      "DELETE",
    );
  }

  // ── Model-scan promotion gate + CycloneDX-ML attestation ──────────

  /**
   * Promote a scanned model to a deployment environment.
   * Default: 403 unless scan.verdict === 'safe'. Pass override=true +
   * reason to force-promote suspicious/malicious scans (audit-logged).
   */
  async promoteModelScan(scanId: string, params: {
    toEnv: string;
    fromEnv?: string;
    override?: boolean;
    reason?: string;
  }): Promise<{ scanId: string; decision: "promoted" | "override"; toEnv: string; fromEnv: string | null; gateStatus: string }> {
    return this.request(
      `/security/model-scan/${encodeURIComponent(scanId)}/promote`,
      "POST",
      params,
    );
  }

  /**
   * Fetch a CycloneDX-ML attestation for a model scan. Cached on first
   * call; subsequent calls return the stored document unchanged.
   */
  async getModelScanAttestation(scanId: string): Promise<{
    scanId: string;
    attestation: Record<string, unknown>;
    cached: boolean;
  }> {
    return this.request(
      `/security/model-scan/${encodeURIComponent(scanId)}/attestation`,
      "GET",
    );
  }

  // ── Agent-run metering (per-run budget + end-customer chargeback) ──

  /**
   * Start a metered agent run. Returns a runId that can be passed to the
   * gateway proxy via `x-evalguard-run-id` header so all downstream LLM
   * calls roll into the same run's cost.
   *
   * The apiKeyId field defaults to the key used for auth when omitted —
   * server derives it from the Bearer token.
   */
  async startAgentRun(params: {
    apiKeyId?: string;
    endCustomerId?: string;
    traceId?: string;
    metadata?: Record<string, unknown>;
  } = {}): Promise<{ runId: string; status: string; startedAt: string }> {
    return this.request("/agent-runs/start", "POST", params);
  }

  /**
   * End a metered agent run. Cost rolls into the api_key's monthly spent
   * meter. Idempotent — calling end twice returns the prior values.
   */
  async endAgentRun(runId: string, params: {
    costUsd: number;
    tokensIn?: number;
    tokensOut?: number;
    status?: "completed" | "failed" | "budget_exceeded";
    metadata?: Record<string, unknown>;
  }): Promise<{ runId: string; costUsd: number; status: string; endedAt: string }> {
    return this.request(`/agent-runs/${encodeURIComponent(runId)}/end`, "POST", params);
  }

  /** List agent runs — raw rows newest-first, or grouped when groupBy is set. */
  async listAgentRuns(params: {
    apiKeyId?: string;
    agentTag?: string;
    endCustomerId?: string;
    since?: string;
    limit?: number;
    groupBy?: "agent_tag" | "end_customer_id" | "api_key_id";
  } = {}): Promise<{
    runs?: Array<Record<string, unknown>>;
    groups?: Array<Record<string, unknown>>;
    total: number;
    since: string;
    groupBy?: string;
  }> {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) q.set(k, String(v));
    }
    const qs = q.toString() ? `?${q.toString()}` : "";
    return this.request(`/agent-runs${qs}`, "GET");
  }

  // ── Shadow-AI discovery ────────────────────────────────────────────

  /**
   * Ingest external egress / SSO / CASB logs. Classifies each row's domain
   * against the AI-tool catalog and accumulates per-(domain, user, source)
   * sighting counts. The server uses an additive merge RPC so re-ingesting
   * the same rows on a daily cron does NOT overwrite prior counts.
   */
  async ingestShadowAISightings(params: {
    source: "zscaler" | "netskope" | "cloudflare" | "okta" | "generic";
    rows: Array<Record<string, unknown>>;
    projectId?: string;
  }): Promise<{ ingested: number; newSightings: number; updatedSightings: number; parsedRows: number; skipped: number; byReason: Record<string, number> }> {
    return this.request("/shadow-ai/ingest", "POST", params);
  }

  async setShadowAIPolicy(params: {
    domain: string;
    status: "approved" | "blocked" | "pending";
    rationale?: string;
    projectId?: string;
  }): Promise<{ policy: { id: string; domain: string; status: string; rationale: string | null; updated_at: string } }> {
    return this.request("/shadow-ai/policy", "POST", params);
  }

  async listShadowAIPolicies(projectId: string): Promise<{
    policies: Array<{ id: string; domain: string; status: string; rationale: string | null; updated_at: string }>;
    total: number;
  }> {
    return this.request(`/shadow-ai/policy?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async deleteShadowAIPolicy(domain: string, projectId: string): Promise<{ domain: string; deleted: true }> {
    return this.request(
      `/shadow-ai/policy?domain=${encodeURIComponent(domain)}&projectId=${encodeURIComponent(projectId)}`,
      "DELETE",
    );
  }

  // ── SIEM inbound token admin ──────────────────────────────────────

  /**
   * Create an HMAC token a SIEM (Splunk / Sentinel / QRadar / generic)
   * will use to sign inbound webhooks. The `hmacSecret` in the response
   * is shown ONCE — copy it into the SIEM playbook immediately. Lost
   * secrets require revoke + re-issue.
   */
  async createSiemInboundToken(params: {
    source: "splunk" | "sentinel" | "qradar" | "generic_webhook";
    label: string;
    allowedActions?: Array<"quarantine_key" | "unquarantine_key" | "escalate_review" | "block_user" | "force_rotate" | "custom" | "*">;
    rateLimitPerMin?: number;
    projectId?: string;
  }): Promise<{ token: { id: string; source: string; label: string; allowedActions: string[]; rateLimitPerMin: number; createdAt: string; hmacSecret: string }; note: string }> {
    return this.request("/siem/inbound/tokens", "POST", params);
  }

  async listSiemInboundTokens(projectId: string): Promise<{
    tokens: Array<{ id: string; source: string; label: string; allowed_actions: string[]; rate_limit_per_min: number; last_used_at: string | null; revoked: boolean; created_at: string }>;
    total: number;
  }> {
    return this.request(`/siem/inbound/tokens?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  async revokeSiemInboundToken(tokenId: string, projectId: string): Promise<{ id: string; revoked: true }> {
    return this.request(
      `/siem/inbound/tokens?id=${encodeURIComponent(tokenId)}&projectId=${encodeURIComponent(projectId)}`,
      "DELETE",
    );
  }

  // ── Debug agent (AI-proposed fixes for failing traces) ─────────────

  /**
   * Ask the debug agent to analyze a failing trace + its scorer failures
   * and propose a structured fix. Returns a session id + the fix plan
   * (promptDiff / toolSchemaPatch / paramChanges / providerSwap) with
   * confidence and rationale. The analyzer LLM call uses BYOK when the
   * org has stored an OpenAI provider key, else falls back to the server
   * fallback.
   */
  async analyzeTrace(params: {
    traceId: string;
    scorerResultIds?: string[];
    analyzerModel?: string;
    analyzerProvider?: string;
    expectedOutput?: string;
    projectId?: string;
  }): Promise<{
    sessionId: string;
    fixKind: "prompt_diff" | "tool_schema" | "param_change" | "provider_swap" | "no_fix_identified";
    confidence: number;
    rationale: string;
    suggestedFix: Record<string, unknown>;
    analyzerModel: string;
    analyzerCostUsd: number;
  }> {
    return this.request("/debug-agent", "POST", params);
  }

  // ── Privacy Center: DSR / consent / RoPA / DPIA / vendors ────────

  async listDSRs(params?: { status?: string; type?: string }): Promise<unknown[]> {
    const q = new URLSearchParams();
    if (params?.status) q.set("status", params.status);
    if (params?.type) q.set("type", params.type);
    return this.request(`/privacy/dsr?${q.toString()}`, "GET");
  }
  async createDSR(params: { request_type: "access" | "delete" | "correct" | "restrict" | "object" | "portability"; subject_email?: string; subject_id?: string; subject_name?: string; legal_basis?: string; notes?: string; }): Promise<unknown> {
    return this.request("/privacy/dsr", "POST", params);
  }
  async getDSR(id: string): Promise<{ request: unknown; items: unknown[] }> {
    return this.request(`/privacy/dsr/${encodeURIComponent(id)}`, "GET");
  }
  async searchDSR(id: string): Promise<{ found: number; summary: Record<string, number>; next: string }> {
    return this.request(`/privacy/dsr/${encodeURIComponent(id)}/search`, "POST");
  }
  async exportDSR(id: string): Promise<unknown> {
    return this.request(`/privacy/dsr/${encodeURIComponent(id)}/export`, "POST");
  }
  async updateDSR(id: string, patch: { status?: string; notes?: string; rejected_reason?: string }): Promise<unknown> {
    return this.request(`/privacy/dsr/${encodeURIComponent(id)}`, "PATCH", patch);
  }

  async listConsents(params?: { subject_email?: string; subject_id?: string; purpose?: string; active_only?: boolean }): Promise<unknown[]> {
    const q = new URLSearchParams();
    if (params?.subject_email) q.set("subject_email", params.subject_email);
    if (params?.subject_id) q.set("subject_id", params.subject_id);
    if (params?.purpose) q.set("purpose", params.purpose);
    if (params?.active_only) q.set("active_only", "true");
    return this.request(`/privacy/consent?${q.toString()}`, "GET");
  }
  async recordConsent(params: { purpose: string; granted: boolean; subject_email?: string; subject_id?: string; scope?: string[]; policy_version?: string; }): Promise<unknown> {
    return this.request("/privacy/consent", "POST", params);
  }
  async revokeConsent(id: string): Promise<unknown> {
    return this.request(`/privacy/consent?id=${encodeURIComponent(id)}`, "PATCH");
  }

  async listProcessingActivities(): Promise<unknown[]> {
    return this.request("/privacy/activities", "GET");
  }
  async createProcessingActivity(params: Record<string, unknown> & { name: string }): Promise<unknown> {
    return this.request("/privacy/activities", "POST", params);
  }
  async updateProcessingActivity(id: string, patch: Record<string, unknown>): Promise<unknown> {
    return this.request(`/privacy/activities?id=${encodeURIComponent(id)}`, "PATCH", patch);
  }

  async listPrivacyAssessments(): Promise<unknown[]> {
    return this.request("/privacy/assessments", "GET");
  }
  async createPrivacyAssessment(params: { assessment_type: "dpia" | "tia" | "lia" | "ai_ia" | "pia"; title: string; ai_risk_class?: string; overall_risk?: string; conclusion?: string; }): Promise<unknown> {
    return this.request("/privacy/assessments", "POST", params);
  }
  async approvePrivacyAssessment(id: string): Promise<unknown> {
    return this.request(`/privacy/assessments?id=${encodeURIComponent(id)}`, "PATCH", { status: "approved" });
  }

  async listVendors(): Promise<unknown[]> {
    return this.request("/privacy/vendors", "GET");
  }
  async addVendor(params: Record<string, unknown> & { vendor_name: string }): Promise<unknown> {
    return this.request("/privacy/vendors", "POST", params);
  }
  async updateVendor(id: string, patch: Record<string, unknown>): Promise<unknown> {
    return this.request(`/privacy/vendors?id=${encodeURIComponent(id)}`, "PATCH", patch);
  }

  // ── Auto-Remediation Playbooks ────────────────────────────────────

  async listPlaybooks(): Promise<{ playbooks: unknown[]; builtIn: unknown[] }> {
    return this.request("/playbooks", "GET");
  }
  async createPlaybook(params: { name: string; trigger_type: string; actions: { type: string; config: Record<string, unknown> }[]; description?: string; match_filter?: Record<string, unknown>; enabled?: boolean; }): Promise<unknown> {
    return this.request("/playbooks", "POST", params);
  }
  async updatePlaybook(id: string, patch: Record<string, unknown>): Promise<unknown> {
    return this.request(`/playbooks/${encodeURIComponent(id)}`, "PATCH", patch);
  }
  async deletePlaybook(id: string): Promise<unknown> {
    return this.request(`/playbooks/${encodeURIComponent(id)}`, "DELETE");
  }
  async testPlaybook(id: string, event?: Record<string, unknown>): Promise<unknown> {
    return this.request(`/playbooks/${encodeURIComponent(id)}/test`, "POST", { event });
  }
  async listPlaybookRuns(id: string, limit = 50): Promise<unknown[]> {
    return this.request(`/playbooks/${encodeURIComponent(id)}/runs?limit=${limit}`, "GET");
  }

  // ── Data Discovery & Classification ───────────────────────────────

  async listDataSources(): Promise<unknown[]> {
    return this.request("/data-discovery/sources", "GET");
  }
  async createDataSource(params: { name: string; connector_type: "s3" | "snowflake" | "http" | string; config: Record<string, unknown>; classifier_mode?: "dlp_only" | "dlp_plus_llm" | "llm_only"; vault_entry_id?: string; }): Promise<unknown> {
    return this.request("/data-discovery/sources", "POST", params);
  }
  async startDataScan(sourceId: string): Promise<unknown> {
    return this.request(`/data-discovery/sources/${encodeURIComponent(sourceId)}/scan`, "POST", {});
  }
  async listDataScans(params?: { source_id?: string; status?: string }): Promise<unknown[]> {
    const q = new URLSearchParams();
    if (params?.source_id) q.set("source_id", params.source_id);
    if (params?.status) q.set("status", params.status);
    return this.request(`/data-discovery/scans?${q.toString()}`, "GET");
  }
  async listDataFindings(params?: { scan_id?: string; source_id?: string; status?: string; risk_level?: string; classification?: string; }): Promise<unknown[]> {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params ?? {})) if (v) q.set(k, String(v));
    return this.request(`/data-discovery/findings?${q.toString()}`, "GET");
  }
  async resolveDataFinding(id: string, status: "remediated" | "false_positive" | "accepted_risk", notes?: string): Promise<unknown> {
    return this.request(`/data-discovery/findings?id=${encodeURIComponent(id)}`, "PATCH", { status, resolution_notes: notes });
  }

  // ── Gateway routing-config management + router-aware chat ─────────
  //
  // The /api/v1/gateway PUT route persists a per-org `gateway_routing_config`
  // row (org-scoped RLS, NEVER stores raw provider keys) that the hosted proxy
  // reads to do REAL learned routing (priority / weighted / least-latency /
  // least-cost / least-load / quality-cost / thompson) with per-provider
  // failover. The POST route runs a chat completion through the router with
  // optional fallback models. These complement the existing read-only
  // getGatewayConfig() / getGatewayStats() / getGatewayHealth().

  /**
   * Upsert this org's gateway routing config (admin-only server-side).
   * Providers carry only non-secret routing knobs — API keys resolve from
   * your stored Provider Keys (Vault) at request time, never from this call.
   */
  async setGatewayRoutingConfig(params: {
    orgId: string;
    routingStrategy?: GatewayRoutingStrategy;
    enabled?: boolean;
    cacheEnabled?: boolean;
    cacheTtlSec?: number;
    rateLimitEnabled?: boolean;
    requestsPerMinute?: number;
    tokensPerMinute?: number;
    circuitBreakerEnabled?: boolean;
    providers?: GatewayRoutingProvider[];
  }): Promise<GatewayRoutingConfig> {
    if (!params.orgId) throw new Error("setGatewayRoutingConfig: orgId is required");
    return this.request("/gateway", "PUT", params);
  }

  /**
   * Run a chat completion through the gateway router. When the hosted proxy's
   * router is enabled for the org, this exercises learned routing + failover;
   * otherwise it falls back to a direct single-provider call. `fallbackModels`
   * are tried in order if the primary model's provider has no resolvable key.
   */
  async gatewayChat(params: {
    messages: ChatMessage[];
    model: string;
    tenantId?: string;
    temperature?: number;
    maxTokens?: number;
    fallbackModels?: string[];
  }): Promise<GatewayChatResponse> {
    if (!params.messages || params.messages.length === 0) {
      throw new Error("gatewayChat: at least one message is required");
    }
    const { fallbackModels, ...rest } = params;
    const payload: Record<string, unknown> = { ...rest };
    if (fallbackModels && fallbackModels.length > 0) {
      payload.options = { fallbackModels };
    }
    return this.request("/gateway", "POST", payload);
  }

  // ── Firewall advanced rails (client-side, opt-in) ─────────────────
  //
  // The hosted /firewall/check route runs the FirewallEngine's 5 base layers.
  // The OPT-IN advanced rails (GCG adversarial-suffix perplexity, embedding
  // paraphrase recall, YARA declarative output rails, RAG retrieval-grounding)
  // are not exposed on that route, so this helper runs the SAME core
  // `FirewallEngine` LOCALLY — re-using @evalguard/core, never reimplementing
  // detection — exactly like runCustomScan() runs client-side. Sync layers
  // (pattern/token/semantic/GCG/YARA-output) run with no network; the async
  // rails (embeddingSemantic, retrievalGrounding) require an embedder / RAG
  // context and use the engine's async scan paths.

  /**
   * Run a firewall INPUT check locally through the core FirewallEngine, with
   * optional advanced rails. Use `advancedRails.embeddingSemantic` (needs an
   * embedder) to opt into the async paraphrase-recall layer; otherwise the
   * check is synchronous over the base + GCG layers.
   */
  async checkFirewallAdvanced(params: {
    input: string;
    config?: FirewallEngineConfig;
    advancedRails?: AdvancedRailsConfig;
    history?: { role: string; content: string }[];
  }): Promise<DetectionResult> {
    if (!params.input) throw new Error("checkFirewallAdvanced: input is required");
    const { FirewallEngine } = await import("@evalguard/core");
    const engine = new FirewallEngine({
      ...(params.config ?? {}),
      advancedRails: params.advancedRails,
    });
    // Use the async path when an async rail (embedding-semantic) is enabled so
    // it actually runs; otherwise the sync scan is sufficient and avoids an
    // unnecessary microtask. scanAsync collapses to scan() when no async rail
    // is active, so this is always safe.
    if (params.advancedRails?.embeddingSemantic?.enabled) {
      return engine.scanAsync(params.input, params.history);
    }
    return params.history && params.history.length > 0
      ? engine.scanWithContext(params.input, params.history)
      : engine.scan(params.input);
  }

  /**
   * Run a firewall OUTPUT check locally through the core FirewallEngine, with
   * optional YARA output rails + RAG retrieval-grounding. Pass `context`
   * (retrieved RAG chunks) to opt the async retrieval-grounding rail in.
   */
  async checkFirewallOutputAdvanced(params: {
    output: string;
    config?: FirewallEngineConfig;
    advancedRails?: AdvancedRailsConfig;
    systemPrompt?: string;
    context?: string[];
  }): Promise<DetectionResult> {
    if (!params.output) throw new Error("checkFirewallOutputAdvanced: output is required");
    const { FirewallEngine } = await import("@evalguard/core");
    const engine = new FirewallEngine({
      ...(params.config ?? {}),
      advancedRails: params.advancedRails,
    });
    if (
      params.advancedRails?.retrievalGrounding?.enabled &&
      params.context &&
      params.context.length > 0
    ) {
      return engine.scanOutputAsync(params.output, {
        systemPrompt: params.systemPrompt,
        context: params.context,
      });
    }
    return engine.scanOutput(params.output, params.systemPrompt);
  }

  // ── RAG AutoML (combinatorial RAG search → reproducible IR leaderboard) ──

  /**
   * Run a combinatorial RAG-pipeline search. For each enumerated config in the
   * Cartesian product of `searchSpace`, submit the candidate retrieval ranking
   * under `runs[configKey]` (configKey = JSON of the config with keys SORTED).
   * The server scores each ranking against `qrels` and returns a ranked
   * nDCG/MAP/MRR leaderboard, persisted for replay.
   */
  async runRagAutoML(params: {
    projectId: string;
    name: string;
    searchSpace: Record<string, Array<number | string | boolean>>;
    qrels: Record<string, Record<string, number>>;
    runs: Record<string, Record<string, string[]>>;
    objective?: "ndcg" | "map" | "mrr" | "precision" | "recall" | "hitRate";
    objectiveK?: number;
    ks?: number[];
    maxConfigs?: number;
  }): Promise<RagAutoMLStudyResult> {
    if (!params.projectId) throw new Error("runRagAutoML: projectId is required");
    return this.request("/experiments/rag-automl", "POST", params);
  }

  /** List RAG AutoML studies for a project (newest-first). */
  async listRagAutoMLStudies(projectId: string): Promise<unknown> {
    if (!projectId) throw new Error("projectId is required");
    return this.request(
      `/experiments/rag-automl?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /** Fetch one RAG AutoML study + its full ranked leaderboard (replay). */
  async getRagAutoMLStudy(projectId: string, studyId: string): Promise<RagAutoMLStudyResult> {
    if (!projectId || !studyId) throw new Error("projectId and studyId are required");
    return this.request(
      `/experiments/rag-automl?projectId=${encodeURIComponent(projectId)}&studyId=${encodeURIComponent(studyId)}`,
      "GET",
    );
  }

  // ── Decision-BOM (signed, tamper-evident "why was this allowed/blocked") ──

  /**
   * Fetch a signed Decision Bill-of-Materials by id. The server RE-VERIFIES the
   * Ed25519 signature and returns the BOM plus a `verification` block. The BOM
   * is also independently verifiable client-side via the exported
   * `verifyDecisionBOM` helper (re-exported from @evalguard/core).
   */
  async getDecisionBOM(id: string): Promise<DecisionBOMResponse> {
    if (!id) throw new Error("getDecisionBOM: id is required");
    return this.request(`/compliance/decision-bom/${encodeURIComponent(id)}`, "GET");
  }

  // ── FinOps cost export (FOCUS / OpenMeter / Lago interchange) ─────
  //
  // Row-level interchange export of an org's cost_entries in the standard
  // formats a FinOps / procurement team ingests directly. focus → FOCUS 1.0
  // columnar CSV; openmeter / lago → NDJSON usage events. The response is the
  // raw file body as text (the route streams CSV/NDJSON, not a JSON envelope).

  /**
   * Export an org's LLM cost data as a FinOps interchange file. Returns the
   * raw text body: FOCUS 1.0 CSV for `focus`, NDJSON events for
   * `openmeter` / `lago`.
   */
  async exportCostFinOps(params: {
    orgId: string;
    format: FinOpsCostExportFormat;
    projectId?: string;
    startDate?: string;
    endDate?: string;
    currency?: string;
  }): Promise<string> {
    if (!params.orgId) throw new Error("exportCostFinOps: orgId is required");
    const q = new URLSearchParams({ orgId: params.orgId, format: params.format });
    if (params.projectId) q.set("projectId", params.projectId);
    if (params.startDate) q.set("startDate", params.startDate);
    if (params.endDate) q.set("endDate", params.endDate);
    if (params.currency) q.set("currency", params.currency);
    return this.requestText(`/cost/export?${q.toString()}`, "GET");
  }

  // ── Agent-tool builder (headline agent-builder feature) ───────────
  //
  // Full CRUD + a dry-run test over a customer-authored agent tool (REST /
  // inline-code / MCP). The `tool` payload mirrors the {@link AgentTool}
  // shape; secrets (e.g. rest.auth.value) are write-only and never returned —
  // reads expose only a `hasSecret` flag. All routes are project-scoped.

  /** List the agent tools defined in a project. GET /agent-tools. */
  async listAgentTools(projectId: string): Promise<{ tools: AgentTool[] }> {
    if (!projectId) throw new Error("projectId is required");
    return this.request(`/agent-tools?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  /** Create a new agent tool. POST /agent-tools → 201 with the created tool. */
  async createAgentTool(params: { projectId: string; tool: AgentTool }): Promise<AgentTool> {
    if (!params.projectId) throw new Error("createAgentTool: projectId is required");
    if (!params.tool) throw new Error("createAgentTool: tool is required");
    return this.request("/agent-tools", "POST", params);
  }

  /** Fetch a single agent tool by id. GET /agent-tools/{id}. */
  async getAgentTool(id: string, projectId: string): Promise<AgentTool> {
    if (!id) throw new Error("getAgentTool: id is required");
    if (!projectId) throw new Error("getAgentTool: projectId is required");
    return this.request(
      `/agent-tools/${encodeURIComponent(id)}?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /** Update an agent tool (partial — pass only the fields to change). PATCH /agent-tools/{id}. */
  async updateAgentTool(
    id: string,
    params: { projectId: string; tool: Partial<AgentTool> },
  ): Promise<AgentTool> {
    if (!id) throw new Error("updateAgentTool: id is required");
    if (!params.projectId) throw new Error("updateAgentTool: projectId is required");
    return this.request(`/agent-tools/${encodeURIComponent(id)}`, "PATCH", params);
  }

  /** Delete an agent tool. DELETE /agent-tools/{id}. */
  async deleteAgentTool(id: string, projectId: string): Promise<{ id: string; deleted: true }> {
    if (!id) throw new Error("deleteAgentTool: id is required");
    if (!projectId) throw new Error("deleteAgentTool: projectId is required");
    return this.request(
      `/agent-tools/${encodeURIComponent(id)}?projectId=${encodeURIComponent(projectId)}`,
      "DELETE",
    );
  }

  /**
   * Dry-run an agent tool with concrete `args`. For a `rest` tool this issues
   * the configured HTTP call (resolving the stored secret server-side); for a
   * `code` tool it sandbox-executes the source; for `mcp` it invokes the
   * server. Returns whether the call succeeded plus the stage/status/body.
   */
  async testAgentTool(
    id: string,
    params: { projectId: string; args: Record<string, unknown> },
  ): Promise<AgentToolTestResult> {
    if (!id) throw new Error("testAgentTool: id is required");
    if (!params.projectId) throw new Error("testAgentTool: projectId is required");
    return this.request(`/agent-tools/${encodeURIComponent(id)}/test`, "POST", params);
  }

  // ── Abuse reports (defense-in-depth trust-&-safety intake) ────────
  //
  // Inbound abuse reports against agent activity. POST runs an auto-triage
  // (severity + dedup + escalation + detector-feedback) returned alongside
  // the persisted report. GET lists a project's reports, optionally by status.

  /** List abuse reports for a project, optionally filtered by status. GET /abuse-reports. */
  async listAbuseReports(
    projectId: string,
    status?: AbuseReportStatus,
  ): Promise<{ reports: AbuseReport[] }> {
    if (!projectId) throw new Error("projectId is required");
    const q = new URLSearchParams({ projectId });
    if (status) q.set("status", status);
    return this.request(`/abuse-reports?${q.toString()}`, "GET");
  }

  /**
   * File an abuse report. The server auto-triages it (severity, dedup key,
   * auto-escalation, detector feedback) and returns both the stored report and
   * the {@link AbuseReportTriage} decision. POST /abuse-reports → 201.
   */
  async reportAbuse(params: {
    projectId: string;
    category: AbuseReportCategory;
    description?: string;
    subjectId?: string;
    reporterId?: string;
    evidence?: Record<string, unknown>;
  }): Promise<{ report: AbuseReport; triage: AbuseReportTriage }> {
    if (!params.projectId) throw new Error("reportAbuse: projectId is required");
    if (!params.category) throw new Error("reportAbuse: category is required");
    return this.request("/abuse-reports", "POST", params);
  }

  // ── Agent deployments (publish a workflow as a chat widget) ───────
  //
  // Publish a saved workflow as a deployable chat widget across channels
  // (web / slack / whatsapp / api). The deploy/list routes are nested under
  // the workflow; status/origin/greeting updates + teardown act on the
  // deployment id directly.

  /** List a workflow's deployments. GET /workflows/{workflowId}/deploy. */
  async listAgentDeployments(
    workflowId: string,
    projectId: string,
  ): Promise<{ deployments: AgentDeployment[] }> {
    if (!workflowId) throw new Error("listAgentDeployments: workflowId is required");
    if (!projectId) throw new Error("listAgentDeployments: projectId is required");
    return this.request(
      `/workflows/${encodeURIComponent(workflowId)}/deploy?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
  }

  /**
   * Publish a workflow as a chat widget on a channel. Returns the created
   * deployment including its `public_id` (the embeddable widget handle).
   * POST /workflows/{workflowId}/deploy → 201.
   */
  async deployAgent(
    workflowId: string,
    params: {
      projectId: string;
      channel: AgentDeploymentChannel;
      allowedOrigins?: string[];
      greeting?: string;
    },
  ): Promise<AgentDeployment> {
    if (!workflowId) throw new Error("deployAgent: workflowId is required");
    if (!params.projectId) throw new Error("deployAgent: projectId is required");
    if (!params.channel) throw new Error("deployAgent: channel is required");
    return this.request(`/workflows/${encodeURIComponent(workflowId)}/deploy`, "POST", params);
  }

  /** Update a deployment (pause/resume, greeting, allowed origins). PATCH /deployments/{id}. */
  async updateAgentDeployment(
    id: string,
    params: {
      projectId: string;
      status?: AgentDeploymentStatus;
      greeting?: string;
      allowedOrigins?: string[];
    },
  ): Promise<AgentDeployment> {
    if (!id) throw new Error("updateAgentDeployment: id is required");
    if (!params.projectId) throw new Error("updateAgentDeployment: projectId is required");
    return this.request(`/deployments/${encodeURIComponent(id)}`, "PATCH", params);
  }

  /** Tear down a deployment. DELETE /deployments/{id}. */
  async deleteAgentDeployment(
    id: string,
    projectId: string,
  ): Promise<{ id: string; deleted: true }> {
    if (!id) throw new Error("deleteAgentDeployment: id is required");
    if (!projectId) throw new Error("deleteAgentDeployment: projectId is required");
    return this.request(
      `/deployments/${encodeURIComponent(id)}?projectId=${encodeURIComponent(projectId)}`,
      "DELETE",
    );
  }

  // ── Agent memory (two-tier: long-term semantic recall) ────────────

  /** Remember durable facts, or a conversation to extract facts from, for a
   *  session (cross-session long-term memory). POST /agent-memory. */
  async rememberMemory(params: {
    projectId: string;
    sessionKey: string;
    facts?: string[];
    turns?: { role: string; content: string }[];
    agentId?: string;
  }): Promise<{ written: string[]; skipped: string[] }> {
    if (!params.projectId) throw new Error("rememberMemory: projectId is required");
    if (!params.sessionKey) throw new Error("rememberMemory: sessionKey is required");
    if (!params.facts?.length && !params.turns?.length) {
      throw new Error("rememberMemory: provide facts[] or turns[]");
    }
    return this.request("/agent-memory", "POST", params);
  }

  /** Recall a session's long-term memory by semantic similarity to a query
   *  (omit query to list recent facts). GET /agent-memory. */
  async recallMemory(params: {
    projectId: string;
    sessionKey: string;
    query?: string;
    limit?: number;
    minScore?: number;
  }): Promise<{ semantic: { id?: string; content: string; score: number | null; createdAt?: string }[] }> {
    if (!params.projectId) throw new Error("recallMemory: projectId is required");
    if (!params.sessionKey) throw new Error("recallMemory: sessionKey is required");
    const q = new URLSearchParams({ projectId: params.projectId, sessionKey: params.sessionKey });
    if (params.query) q.set("query", params.query);
    if (params.limit != null) q.set("limit", String(params.limit));
    if (params.minScore != null) q.set("minScore", String(params.minScore));
    return this.request(`/agent-memory?${q.toString()}`, "GET");
  }

  /** Forget a session's long-term memory. DELETE /agent-memory. */
  async forgetMemory(params: { projectId: string; sessionKey: string }): Promise<{ forgotten: number }> {
    if (!params.projectId) throw new Error("forgetMemory: projectId is required");
    if (!params.sessionKey) throw new Error("forgetMemory: sessionKey is required");
    const q = new URLSearchParams({ projectId: params.projectId, sessionKey: params.sessionKey });
    return this.request(`/agent-memory?${q.toString()}`, "DELETE");
  }

  // ── Voice ML (word-level ASR + deepfake detection via sidecar) ─────

  /** Transcribe audio with WORD-LEVEL timestamps. POST /voice/transcribe.
   *  `audioBase64` is a WAV file, base64-encoded. Requires the operator-deployed
   *  voice-ML sidecar (503 otherwise). */
  async transcribeVoice(params: {
    projectId: string;
    audioBase64: string;
    language?: string;
  }): Promise<{
    language?: string;
    durationMs?: number;
    text: string;
    words: { word: string; startMs: number; endMs: number; confidence?: number }[];
    segments?: { startMs: number; endMs: number; text: string }[];
  }> {
    if (!params.projectId) throw new Error("transcribeVoice: projectId is required");
    if (!params.audioBase64) throw new Error("transcribeVoice: audioBase64 is required");
    return this.request("/voice/transcribe", "POST", params);
  }

  /** Score audio for synthetic-speech / deepfake probability in [0,1].
   *  POST /voice/deepfake-score. `audioBase64` is a WAV file, base64-encoded. */
  async scoreVoiceDeepfake(params: {
    projectId: string;
    audioBase64: string;
  }): Promise<{ probability: number; model?: string; scores?: { label: string; score: number }[] }> {
    if (!params.projectId) throw new Error("scoreVoiceDeepfake: projectId is required");
    if (!params.audioBase64) throw new Error("scoreVoiceDeepfake: audioBase64 is required");
    return this.request("/voice/deepfake-score", "POST", params);
  }

  // ── Vision moderation (BYO vision model) ──────────────────────────

  /** Moderate an image for harmful content via the project's BYO vision model.
   *  POST /moderation/image. Runs the moderation engine (threshold, fail-closed)
   *  against the project's configured vendor (OpenAI omni-moderation today) using
   *  its BYOK key. Provide `imageUrl` OR `imageBase64`. Fails CLOSED (flagged) on
   *  backend error. Returns harm `score` (0..1), matched `categories`, per-category
   *  scores. 400 PROVIDER_KEY_UNAVAILABLE if no provider key is configured. */
  async moderateImage(params: {
    orgId: string;
    projectId: string;
    imageUrl?: string;
    imageBase64?: string;
    mimeType?: string;
    threshold?: number;
    provider?: "openai";
  }): Promise<{
    flagged: boolean;
    score: number;
    categories: string[];
    categoryScores?: Record<string, number>;
    provider?: string;
    latencyMs?: number;
  }> {
    if (!params.orgId) throw new Error("moderateImage: orgId is required");
    if (!params.projectId) throw new Error("moderateImage: projectId is required");
    if (!params.imageUrl && !params.imageBase64) {
      throw new Error("moderateImage: imageUrl or imageBase64 is required");
    }
    return this.request("/moderation/image", "POST", params);
  }

  /** Moderate a video by sampling caller-supplied frames through the project's
   *  BYO vision model. POST /moderation/video. Frame extraction needs ffmpeg, so
   *  you pass the frames (URLs or base64); the engine samples + aggregates to a
   *  clip verdict (worst-frame score, union categories, first flagged frame).
   *  Fails CLOSED per frame. Each frame needs imageUrl OR imageBase64. */
  async moderateVideo(params: {
    orgId: string;
    projectId: string;
    frames: { imageUrl?: string; imageBase64?: string; mimeType?: string; timestampMs?: number }[];
    threshold?: number;
    maxFrames?: number;
    sampleEveryN?: number;
    provider?: "openai";
  }): Promise<{
    flagged: boolean;
    score: number;
    categories: string[];
    firstFlaggedFrame?: number;
    framesTotal: number;
    framesEvaluated: number;
    frames: { index: number; timestampMs?: number; flagged: boolean; score: number; categories: string[] }[];
    provider?: string;
    latencyMs?: number;
  }> {
    if (!params.orgId) throw new Error("moderateVideo: orgId is required");
    if (!params.projectId) throw new Error("moderateVideo: projectId is required");
    if (!params.frames || params.frames.length === 0) throw new Error("moderateVideo: at least one frame is required");
    return this.request("/moderation/video", "POST", params);
  }

  /** Detect a visual deepfake / synthetic media (image or video) via the
   *  operator's BYO forensic ML sidecar. POST /moderation/deepfake. For an image
   *  pass imageUrl|imageBase64; for a video pass frames[] (engine samples +
   *  aggregates). Fails CLOSED (synthetic) on detector error. 503 when no sidecar
   *  is configured (DEEPFAKE_ML_SIDECAR_URL). */
  async detectDeepfake(params: {
    orgId: string;
    projectId: string;
    kind?: "image" | "video";
    imageUrl?: string;
    imageBase64?: string;
    mimeType?: string;
    frames?: { imageUrl?: string; imageBase64?: string; mimeType?: string; timestampMs?: number }[];
    threshold?: number;
    maxFrames?: number;
    sampleEveryN?: number;
  }): Promise<{
    kind: "image" | "video";
    synthetic: boolean;
    probability: number;
    label?: string;
    [k: string]: unknown;
  }> {
    if (!params.orgId) throw new Error("detectDeepfake: orgId is required");
    if (!params.projectId) throw new Error("detectDeepfake: projectId is required");
    if (!params.imageUrl && !params.imageBase64 && !(params.frames && params.frames.length > 0)) {
      throw new Error("detectDeepfake: provide imageUrl/imageBase64 (image) or frames[] (video)");
    }
    return this.request("/moderation/deepfake", "POST", params);
  }

  // ── Language detection (text → language) ──────────────────────────

  /** Identify the language of a text snippet (franc-min, 82 languages).
   *  POST /language/detect. Returns { iso6393, iso6391, name, confidence, reliable }. */
  async detectLanguage(params: {
    projectId: string;
    text: string;
    minLength?: number;
    only?: string[];
  }): Promise<{ iso6393: string; iso6391: string | null; name: string | null; confidence: number; reliable: boolean }> {
    if (!params.projectId) throw new Error("detectLanguage: projectId is required");
    if (!params.text) throw new Error("detectLanguage: text is required");
    return this.request("/language/detect", "POST", params);
  }

  // ── MCP security (pre-deploy audit) ───────────────────────────────

  /** Pre-deploy security audit of an MCP server config — scans tool/parameter
   *  descriptions for injection, validates auth + encryption, flags dangerous
   *  tools without RBAC. Returns a severity report + approve/block verdict.
   *  POST /security/mcp-predeployment-audit. */
  async auditMcpServer(params: {
    projectId: string;
    server: Record<string, unknown>;
    tools?: Array<Record<string, unknown>>;
    signoff?: { signedBy: string; note?: string };
  }): Promise<{
    server: { id: string; name?: string; url?: string };
    toolCount: number;
    findings: Array<{ severity: string; category: string; target: string; title: string; detail: string; remediation: string }>;
    summary: { critical: number; high: number; medium: number; low: number; total: number };
    riskScore: number;
    verdict: "block" | "review" | "pass";
    attestation: { signedOff: boolean; signedBy?: string; signedAt?: string; note?: string };
  }> {
    if (!params.projectId) throw new Error("auditMcpServer: projectId is required");
    if (!params.server) throw new Error("auditMcpServer: server is required");
    return this.request("/security/mcp-predeployment-audit", "POST", { ...params, tools: params.tools ?? [] });
  }

  /** Run an execution-layer red-team against a target agent: drive it with
   *  injections, intercept attempted tool calls, and report whether a dangerous
   *  call (e.g. delete_account(all=true)) slipped past the firewall.
   *  POST /security/agent-exec-redteam (uses your BYOK provider key). */
  async runAgentExecRedTeam(params: {
    projectId: string;
    targetProvider: string;
    targetModel: string;
    systemPrompt?: string;
    attackPrompts?: string[];
    tools?: Array<Record<string, unknown>>;
  }): Promise<{
    totalAttacks: number;
    dangerousAttempts: number;
    breaches: number;
    verdict: "breached" | "attempted" | "safe";
    attacks: Array<{ prompt: string; response: string; attemptedDangerous: boolean; breached: boolean; toolCalls: unknown[] }>;
    tools: string[];
  }> {
    if (!params.projectId) throw new Error("runAgentExecRedTeam: projectId is required");
    if (!params.targetProvider || !params.targetModel) throw new Error("runAgentExecRedTeam: targetProvider and targetModel are required");
    return this.request("/security/agent-exec-redteam", "POST", {
      projectId: params.projectId,
      target_provider: params.targetProvider,
      target_model: params.targetModel,
      system_prompt: params.systemPrompt,
      attack_prompts: params.attackPrompts,
      tools: params.tools,
    });
  }

  // ── Observability (agent-to-agent communication graph) ────────────

  /** Agent-to-agent (A2A) communication graph — who-calls-whom, aggregated from
   *  traces over a window. GET /traces/graph. */
  async getAgentGraph(params: {
    projectId: string;
    windowHours?: number;
  }): Promise<{
    services: string[];
    edges: Array<{ from: string; to: string; callCount: number; errorCount: number; avgLatencyMs: number }>;
    totalCalls: number;
    totalErrors: number;
    windowHours: number;
    spanCount: number;
  }> {
    if (!params.projectId) throw new Error("getAgentGraph: projectId is required");
    const q = new URLSearchParams({ projectId: params.projectId });
    if (params.windowHours != null) q.set("windowHours", String(params.windowHours));
    return this.request(`/traces/graph?${q.toString()}`, "GET");
  }

  // ── Data-boundary façade (G11) — unified four-boundary data-exposure policy ──
  // A single clearance-aware policy ties data classification to all four exposure
  // boundaries (user-can-see / workflow-can-use / model-can-receive /
  // output-can-reveal). CRUD over /data-boundary + evaluate via /data-boundary/evaluate.

  /** List the org's data-boundary policies. GET /data-boundary?orgId=. */
  async getDataBoundaryPolicies(params: {
    orgId: string;
  }): Promise<{ policies: DataBoundaryPolicyRecord[]; total: number }> {
    if (!params.orgId) throw new Error("getDataBoundaryPolicies: orgId is required");
    const q = new URLSearchParams({ orgId: params.orgId });
    return this.request(`/data-boundary?${q.toString()}`, "GET");
  }

  /** Create or update a data-boundary policy (keyed by org+name). POST /data-boundary. */
  async upsertDataBoundaryPolicy(params: {
    orgId: string;
    name: string;
    projectId?: string | null;
    classificationLevels?: string[];
    boundaryRules?: Record<string, unknown>;
    enabled?: boolean;
  }): Promise<{ policy: DataBoundaryPolicyRecord }> {
    if (!params.orgId) throw new Error("upsertDataBoundaryPolicy: orgId is required");
    if (!params.name) throw new Error("upsertDataBoundaryPolicy: name is required");
    return this.request("/data-boundary", "POST", params);
  }

  /** Evaluate one boundary crossing against a stored policy. POST /data-boundary/evaluate.
   *  Composes the four existing engines (intent / per-agent authz / DLP / clearance
   *  ladder) server-side into one allow/redactions/reason verdict. */
  async evaluateDataBoundary(params: {
    orgId: string;
    boundary: "user-can-see" | "workflow-can-use" | "model-can-receive" | "output-can-reveal";
    policyId?: string;
    policyName?: string;
    content?: string;
    classification?: "public" | "internal" | "confidential" | "restricted";
    clearance?: "public" | "internal" | "confidential" | "restricted";
    agentClientId?: string | null;
    tool?: string;
    action?: string;
    provider?: string;
    model?: string;
    dataScope?: string;
  }): Promise<{ policyId: string; policyName: string; decision: DataBoundaryEvalDecision }> {
    if (!params.orgId) throw new Error("evaluateDataBoundary: orgId is required");
    if (!params.boundary) throw new Error("evaluateDataBoundary: boundary is required");
    return this.request("/data-boundary/evaluate", "POST", params);
  }

  // ── AI-infra IaC / manifest static scan (G8) ──────────────────────

  /** Statically scan IaC / deployment manifests (Dockerfile, Kubernetes,
   *  Helm, docker-compose, Terraform) for AI-infra-scoped misconfigurations:
   *  a model server bound 0.0.0.0 with no auth, an exposed AI-service port
   *  (MLflow / Ray / Jupyter / Triton / vLLM / TGI …), a secret baked into an
   *  image, or a privileged GPU container without resource limits. Stateless
   *  compute — no storage. POST /security/iac-scan. */
  async scanIac(params: {
    files: Array<{ filename: string; content: string }>;
  }): Promise<{
    scannedFiles: number;
    findingsCount: number;
    bySeverity: { critical: number; high: number; medium: number; low: number };
    findings: Array<{
      ruleId: string;
      severity: "critical" | "high" | "medium" | "low";
      file: string;
      line: number;
      title: string;
      recommendation: string;
    }>;
  }> {
    if (!params.files || params.files.length === 0) {
      throw new Error("scanIac: at least one file is required");
    }
    return this.request("/security/iac-scan", "POST", { files: params.files });
  }

  // ── Internal helpers ───────────────────────────────────────────────

  private async request<T = unknown>(
    path: string,
    method: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<T> {
    const maxRetries = 3;
    let lastError: Error | null = null;

    // Generate ONE Idempotency-Key per logical call (not per attempt) and reuse
    // it across every retry of a non-idempotent write. A transient 502/network
    // blip then dedups server-side (idempotency.ts keys on `idempotency-key`)
    // instead of creating duplicate scans/runs and double-billing the customer.
    // GET/DELETE are naturally idempotent and need no key.
    const isWrite = method === "POST" || method === "PUT" || method === "PATCH";
    const idempotencyKey = isWrite ? newIdempotencyKey() : undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);
      try {
        const res = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "Content-Type": "application/json",
            "x-evalguard-client-version": SDK_VERSION,
            ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}),
            ...this.subjectHeaders(),
            ...(extraHeaders ?? {}),
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: controller.signal,
        });

        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get('retry-after') || '0', 10);
          const delay = retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * Math.pow(2, attempt), 60000);
          if (attempt < maxRetries) {
            await new Promise(r => setTimeout(r, delay));
            continue;
          }
        }

        if (res.status >= 500 && attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
          continue;
        }

        if (res.status >= 400 && res.status !== 429 && res.status < 500) {
          const errBody = await res.json().catch(() => null) as
            | { error?: { code?: string; message?: string; requestId?: string }; message?: string }
            | null;
          const apiErr = errBody?.error;
          throw new EvalGuardError(
            `EvalGuard API error ${res.status}: ${apiErr?.message ?? errBody?.message ?? (errBody === null ? (res.statusText || "Unknown error") : "Unknown error")}`,
            { code: apiErr?.code ?? `HTTP_${res.status}`, status: res.status, requestId: apiErr?.requestId },
          );
        }

        if (!res.ok) {
          const errBody = await res.json().catch(() => null) as
            | { error?: { code?: string; message?: string; requestId?: string }; message?: string }
            | null;
          const apiErr = errBody?.error;
          throw new EvalGuardError(
            `EvalGuard API error ${res.status}: ${apiErr?.message ?? errBody?.message ?? (errBody === null ? (res.statusText || "Unknown error") : "Unknown error")}`,
            { code: apiErr?.code ?? `HTTP_${res.status}`, status: res.status, requestId: apiErr?.requestId },
          );
        }

        // Unwrap the standard { success, data } API envelope so typed methods
        // resolve to T (the payload), not the envelope (audit TS-SDK-ENVELOPE).
        const json = (await res.json()) as unknown;
        return (json && typeof json === "object" && "success" in json && "data" in json
          ? (json as { data: T }).data
          : (json as T));
      } catch (err) {
        lastError = err as Error;
        // HTTP errors are already typed + non-retryable; let them through
        // unchanged (the retry decision below is for transient network blips).
        if (err instanceof EvalGuardError) {
          throw err;
        }
        if (attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
          continue;
        }
        // Retries exhausted on a network/transport failure (the raw
        // `TypeError: fetch failed` for no-server/DNS/connection-refused, or an
        // AbortError on timeout). Surface it as a typed, catchable error instead
        // of letting the raw TypeError escape (audit: sdk-untyped-network-error).
        throw new EvalGuardError(
          `Request to ${path} failed: ${err instanceof Error ? err.message : String(err)}`,
          { code: "NETWORK_ERROR", cause: err },
        );
      } finally {
        clearTimeout(timeoutId);
      }
    }

    // Unreachable in practice (the loop either returns, throws a typed HTTP
    // error, or throws NETWORK_ERROR on the last attempt), but keep a typed
    // fallback so nothing untyped can ever escape request().
    throw new EvalGuardError(
      `Request to ${path} failed after ${maxRetries + 1} attempts`,
      { code: "NETWORK_ERROR", cause: lastError },
    );
  }

  private async requestText(path: string, method: string): Promise<string> {
    const maxRetries = 3;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);
      try {
        const res = await fetch(`${this.baseUrl}${path}`, {
          method,
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "x-evalguard-client-version": SDK_VERSION,
            ...this.subjectHeaders(),
          },
          signal: controller.signal,
        });

        if (res.status === 429) {
          const retryAfter = parseInt(res.headers.get('retry-after') || '0', 10);
          const delay = retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * Math.pow(2, attempt), 60000);
          if (attempt < maxRetries) {
            await new Promise(r => setTimeout(r, delay));
            continue;
          }
        }

        if (res.status >= 500 && attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
          continue;
        }

        if (!res.ok) {
          // requestText() bodies are normally non-JSON (JSONL/XML exports), but
          // ERROR responses still come back as the standard
          // { success:false, error:{ code, message, requestId } } envelope. Parse
          // it so the thrown EvalGuardError carries the server's stable error
          // code + requestId — same as request() — instead of always falling back
          // to HTTP_<status> (audit TS-SDK-ENVELOPE: requestText error path).
          const rawText = await res.text().catch(() => res.statusText);
          let apiErr: { code?: string; message?: string; requestId?: string } | undefined;
          let envelopeMessage: string | undefined;
          try {
            const parsed = JSON.parse(rawText) as
              | { error?: { code?: string; message?: string; requestId?: string }; message?: string }
              | null;
            apiErr = parsed?.error;
            envelopeMessage = apiErr?.message ?? parsed?.message;
          } catch {
            // Non-JSON error body (e.g. a plain-text upstream/proxy error) → keep
            // the raw text in the message and fall back to HTTP_<status>.
          }
          throw new EvalGuardError(
            `EvalGuard API error ${res.status}: ${envelopeMessage ?? rawText}`,
            { code: apiErr?.code ?? `HTTP_${res.status}`, status: res.status, requestId: apiErr?.requestId },
          );
        }

        return res.text();
      } catch (err) {
        lastError = err as Error;
        if (err instanceof EvalGuardError) {
          throw err;
        }
        if (attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
          continue;
        }
        throw new EvalGuardError(
          `Request to ${path} failed: ${err instanceof Error ? err.message : String(err)}`,
          { code: "NETWORK_ERROR", cause: err },
        );
      } finally {
        clearTimeout(timeoutId);
      }
    }

    throw new EvalGuardError(
      `Request to ${path} failed after ${maxRetries + 1} attempts`,
      { code: "NETWORK_ERROR", cause: lastError },
    );
  }
}
