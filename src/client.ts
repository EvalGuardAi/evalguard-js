import { ExtensionRegistry } from "./extensions";
import { warnIfSandboxBlocks } from "./sandbox";
import { SDK_VERSION } from "./version";
import { EvaluationLogger } from "./eval-logger";
import type { EvalLoggerParams } from "./eval-logger";
import type {
  FirewallEngineConfig,
  AdvancedRailsConfig,
  DetectionResult,
  PromptConfig,
  PromptTemplate,
  TemplateLanguage,
  ToolConfig,
  ToolEnvironmentVariable,
  EnvironmentTag,
  MemoryGovernanceMode,
  MemoryGovernanceConfig,
  GuardrailFlagAction,
} from "@evalguard/core";
// SENSITIVITY_LEVELS is the single source of truth for the clearance ladder
// (packages/core/src/intent/index.ts) — imported rather than re-listed so the
// classifyIntent verdict check cannot drift from the classifier that produces it.
import { validatePromptConfig, validateToolConfig, SENSITIVITY_LEVELS } from "@evalguard/core";
// SEC-051 follow-up (2026-08-12). THE same-host redirect rule, imported rather
// than re-implemented — `@evalguard/wrapper-core` is already a dependency of
// this package, and a second copy of a security control is how the two drift.
// See packages/wrapper-core/src/same-host-redirect.ts.
import { followSameHostRedirects } from "@evalguard/wrapper-core";

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
  /** Server-provided request id for support correlation, resolved from the
   *  {success:false,error:{requestId}} envelope or the `X-Request-Id` response
   *  header (populated for every error status, not only 401). */
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

// ── Indeterminate verdicts (fail-CLOSED response validation) ──────────
//
// 2026-08-03. Three fail-open classes were confirmed in SHIPPED EvalGuard
// clients on one night, two of them independently in two languages:
//
//   Java 1.0.8  `FirewallCheckResult.blocked` is a primitive `boolean`, so
//               Jackson defaults an ABSENT field to false → "not blocked".
//   Python 2.1.5 `guardrails.py::_translate` defaults an absent `action` to
//               "allow" at 14 call sites.
//
// This SDK shipped the SAME defect in TypeScript's shape. Every
// verdict-returning method resolved to whatever JSON came back, `request()`
// unwraps `{success,data}` blindly, and the documented caller pattern
//
//     const r = await client.checkFirewall({ input });
//     if (r.blocked) refuse();          // README + FirewallResult docstring
//
// reads `undefined` as "not blocked". Measured against the shipped code
// (probe, 2026-08-03): a 200 whose verdict field is ABSENT, `{}`,
// `{success:true,data:null}`, a 200 apiError envelope (`{success:false,…}`),
// a bare array, a bare string, and `blocked: 0` ALL resolved to ALLOW on
// checkFirewall / runGuardrails / evaluateDataBoundary. A corporate proxy
// that rewrites a 502 into a 200 `{"error":"upstream timeout"}`, a
// differently-versioned server, or a renamed field is enough.
//
// THE RULE: a response the client cannot INTERPRET must DENY. An
// indeterminate verdict is neither "allowed" nor "blocked" — it is "the
// control did not run" — and it is raised as an `EvalGuardError` with code
// `INDETERMINATE_VERDICT` so no caller can read it as clean. This is the same
// fail-closed route `@evalguard/wrapper-core` already takes for the wrappers
// (`FirewallResponseParseError`, firewall-response.ts).
//
// Diagnostics carry key NAMES only, never values: a firewall body echoes
// fragments of the caller's prompt in `hits[].details`, and this message lands
// in operator logs.

/** Stable machine code for an unreadable verdict. */
export const INDETERMINATE_VERDICT_CODE = "INDETERMINATE_VERDICT" as const;

// ── Own-property reads (prototype-pollution containment) ──────────────
//
// 2026-08-03 (audit js-requireverdict-own-properties). Every read this module
// makes on a response body used to be a plain `cursor[key]` / `"key" in obj`,
// and BOTH walk the PROTOTYPE CHAIN. A single prototype-pollution primitive
// anywhere in the consumer's process — a vulnerable transitive dependency, a
// `lodash.merge`-shaped deep-merge over attacker-influenced JSON, a query-string
// parser — therefore let an EMPTY 200 body present a complete, well-typed
// verdict to a fail-CLOSED check:
//
//     Object.prototype.decision = "allow";
//     await client.mcpInvoke(...)   // 200 `{}` → resolved as an AUTHORISED allow
//
// Proven in a clean consumer against the packed 3.0.0 tarball. The whole point
// of requireVerdict is that the SDK must not accept a verdict the SERVER did
// not send; a value the JS runtime synthesised from Object.prototype is the
// purest form of that. So the reads are own-only, everywhere, unconditionally.
//
// TWO surfaces, not one — fixing either alone leaves the bypass fully intact:
//
//   1. requireVerdict's traversal (`cursor[key]`) — reads the verdict itself.
//   2. request()'s apiSuccess unwrap (`"success" in json && "data" in json`) —
//      with `Object.prototype.data = { decision: "allow" }`, a 200 `{}` makes
//      request() RETURN that inherited object, whose `decision` is a genuine
//      OWN property. An own-only requireVerdict validates it happily. Measured:
//      `unwrapped = {"decision":"allow"}`, `Object.hasOwn(unwrapped,"decision")
//      === true`. The verdict check and the envelope unwrap are own-only
//      together or neither is.
//
// `OWN` is resolved ONCE at module load, because the obvious counter-move to
// this very fix is to pollute the test itself: `Object.prototype.hasOwnProperty
// = () => true` re-opens every `Object.prototype.hasOwnProperty.call(o, k)` site
// in the process. `Object.hasOwn` is an own property of the `Object`
// constructor, which a prototype-pollution gadget (which writes through
// `__proto__`/`constructor.prototype` onto Object.PROTOTYPE) cannot reach at
// all; capturing it at load additionally survives later direct tampering.

/** Own-property test, resolved at module load (see block comment above). */
const OWN: (obj: object, key: string) => boolean = (() => {
  const hasOwn = (Object as { hasOwn?: (o: object, k: PropertyKey) => boolean }).hasOwn;
  if (typeof hasOwn === "function") return (obj, key) => hasOwn(obj, key);
  const hop = Object.prototype.hasOwnProperty; // ES2021-and-older runtimes
  return (obj, key) => hop.call(obj, key);
})();

/**
 * Read `obj[key]` ONLY when it is `obj`'s OWN property. An inherited value
 * reads as `undefined`, i.e. exactly as ABSENT — which every caller here
 * already treats as fail-closed. Total: never throws, never consults the
 * prototype chain.
 */
function readOwn(obj: object, key: string): unknown {
  return OWN(obj, key) ? (obj as Record<string, unknown>)[key] : undefined;
}

/**
 * Unwrap the standard `{ success, data }` apiSuccess envelope, tolerating a
 * raw (un-enveloped) payload.
 *
 * Both membership tests are OWN-property tests. `"data" in json` follows the
 * prototype chain, so it is a payload-FABRICATION primitive under prototype
 * pollution — see the block comment above. Single source of truth for the two
 * unwrap sites (request() and checkVersionPolicy()) so they cannot drift.
 */
function unwrapApiEnvelope(json: unknown): unknown {
  if (json === null || typeof json !== "object") return json;
  return OWN(json, "success") && OWN(json, "data") ? (json as { data: unknown }).data : json;
}

/** What a verdict field must look like for the response to be interpretable. */
type VerdictFieldKind = "boolean" | "number" | "array" | "enum";

interface VerdictFieldSpec {
  /** Property path to the verdict field, e.g. `["decision", "allow"]`. */
  path: readonly string[];
  kind: VerdictFieldKind;
  /** For `kind: "enum"` — the complete set of values this client understands. */
  values?: readonly string[];
}

/**
 * Structural summary used in diagnostics — key NAMES only, no values. Mirrors
 * `describeResponseShape` in wrapper-core/src/firewall-response.ts.
 */
function describeVerdictShape(v: unknown): string {
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (Array.isArray(v)) return `array(${v.length})`;
  const t = typeof v;
  if (t !== "object") return t;
  const keys = Object.keys(v as Record<string, unknown>);
  const shown = keys.slice(0, 12);
  return `object{${shown.join(",")}${keys.length > shown.length ? ",…" : ""}}`;
}

function indeterminateVerdict(endpoint: string, reason: string, shape: string): EvalGuardError {
  return new EvalGuardError(
    `EvalGuard ${endpoint} returned 2xx with a body that carries no usable verdict, so the ` +
      `check could not be evaluated (INDETERMINATE — treated as a failure, never as "allowed"): ` +
      `${reason}. Response shape: ${shape}`,
    { code: INDETERMINATE_VERDICT_CODE },
  );
}

/**
 * Assert that `body` carries every verdict field the caller will branch on,
 * with the right RUNTIME type, and return it typed. Throws
 * `EvalGuardError { code: "INDETERMINATE_VERDICT" }` otherwise.
 *
 * Wrong-type is rejected as hard as absent, deliberately: `blocked: 0` and
 * `blocked: "false"` are the two shapes a JS truthiness test gets exactly
 * backwards, and `action: 0` is not an action.
 */
function requireVerdict<T>(
  body: unknown,
  endpoint: string,
  specs: readonly VerdictFieldSpec[],
): T {
  // NOTE: there is deliberately NO env-var / config escape hatch here. An
  // opt-out on a fail-closed control is the next bypass — the flag ends up set
  // in the one deployment that needed it and never unset.
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw indeterminateVerdict(
      endpoint,
      "response body is not a JSON object",
      describeVerdictShape(body),
    );
  }
  for (const spec of specs) {
    let cursor: unknown = body;
    // Diagnostics only — never part of the decision. Distinguishes "the server
    // omitted this field" from "this process has prototype pollution", which
    // are the same fail-closed outcome but very different incidents.
    let inheritedOnly = false;
    for (let i = 0; i < spec.path.length; i++) {
      const key = spec.path[i];
      if (cursor === null || typeof cursor !== "object" || Array.isArray(cursor)) {
        throw indeterminateVerdict(
          endpoint,
          `\`${spec.path.slice(0, i).join(".") || "<root>"}\` is not an object, so the ` +
            `\`${spec.path.join(".")}\` verdict could not be read` +
            // Same distinction as the leaf case below: an intermediate segment
            // that exists ONLY on the prototype chain is a pollution symptom,
            // not a server that omitted a field.
            (inheritedOnly
              ? ` — it was ABSENT from the response body and present ONLY on the ` +
                `prototype chain (inherited values are never accepted as a verdict; ` +
                `your process almost certainly has a prototype-pollution primitive)`
              : ""),
          describeVerdictShape(cursor),
        );
      }
      // OWN properties only. `cursor[key]` walks the prototype chain, so
      // `Object.prototype.<key> = <a value of the right type>` satisfied this
      // check on a body that carried nothing — see the block comment above
      // readOwn. An inherited value reads as ABSENT, which is fail-closed.
      inheritedOnly = !OWN(cursor, key) && key in cursor;
      cursor = readOwn(cursor, key);
    }
    const field = spec.path.join(".");
    const ok =
      spec.kind === "boolean"
        ? typeof cursor === "boolean"
        : spec.kind === "number"
          ? typeof cursor === "number" && Number.isFinite(cursor)
          : spec.kind === "array"
            ? Array.isArray(cursor)
            : typeof cursor === "string" && (spec.values ?? []).includes(cursor);
    if (!ok) {
      const expected =
        spec.kind === "enum"
          ? `one of ${(spec.values ?? []).map((v) => `"${v}"`).join(" | ")}`
          : `a ${spec.kind}`;
      throw indeterminateVerdict(
        endpoint,
        `\`${field}\` must be ${expected} — this route always returns one — but it was ` +
          `${
            cursor === undefined
              ? inheritedOnly
                ? "ABSENT from the response body and present ONLY on the prototype chain " +
                  "(inherited values are never accepted as a verdict; your process almost " +
                  "certainly has a prototype-pollution primitive)"
                : "ABSENT"
              : `of type ${Array.isArray(cursor) ? "array" : typeof cursor}`
          }`,
        describeVerdictShape(body),
      );
    }
  }
  return body as T;
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

/**
 * Hard ceiling on any single retry sleep, in ms.
 *
 * AUDIT 2026-07-25 (availability). The 429 branch used to be
 * `retryAfter > 0 ? retryAfter * 1000 : Math.min(1000 * 2 ** attempt, 60_000)` —
 * the 60s cap guarded ONLY the exponential fallback, so a server-supplied
 * `Retry-After: 3600` was honoured verbatim. With maxRetries = 3 that parks a
 * single `await client.checkFirewall(...)` for up to three hours inside the
 * caller's request handler, with no cancellation and no error: the
 * AbortController bounds the fetch, never the sleep. An edge/CDN under load
 * shedding (Cloudflare, nginx `limit_req`) emits large Retry-After values
 * routinely, so this turns OUR rate limit into THEIR outage.
 */
export const MAX_RETRY_DELAY_MS = 60_000;

/**
 * Compute the sleep before the next attempt, bounded and jittered.
 *
 * - Honours `Retry-After` (delta-seconds or the HTTP-date form) but CLAMPS it
 *   to {@link MAX_RETRY_DELAY_MS}; the server hint can shorten a wait, never
 *   extend it past the ceiling.
 * - Falls back to exponential backoff when the header is absent/unparseable.
 * - Applies ±50% jitter so a fleet that rate-limits together does not retry in
 *   lockstep and re-stampede the recovering origin.
 *
 * Exported for tests; not part of the supported public surface.
 */
export function computeRetryDelayMs(
  retryAfterHeader: string | null,
  attempt: number,
  now: number = Date.now(),
): number {
  let base: number | null = null;
  if (retryAfterHeader) {
    const raw = retryAfterHeader.trim();
    const seconds = /^\d+$/.test(raw) ? Number(raw) : NaN;
    if (Number.isFinite(seconds) && seconds > 0) {
      base = seconds * 1000;
    } else {
      // HTTP-date form (RFC 9110 §10.2.3). parseInt() yielded NaN here and the
      // hint was silently dropped.
      const at = Date.parse(raw);
      if (Number.isFinite(at)) base = Math.max(0, at - now);
    }
  }
  if (base === null) base = 1000 * Math.pow(2, attempt);
  const bounded = Math.min(base, MAX_RETRY_DELAY_MS);
  return Math.round(bounded * (0.5 + Math.random() * 0.5));
}

// ── Retry safety ──────────────────────────────────────────────────────
//
// The SDK sends an `Idempotency-Key` on every write, but the SERVER only
// honours it on routes that opt in with `idempotent: true` in
// apps/web/src/lib/api-handler.ts — a handful, not the ~340 write routes. So a
// blind 5xx/network retry of a POST whose row already committed (nginx 502 with
// the response in flight is routine during a deploy) creates a DUPLICATE: two
// api keys, two team invites, two of whatever the route mints. The caller
// cannot tell, because the SDK returns the second response.
//
// Retry rules:
//   • GET / HEAD / OPTIONS / DELETE / PUT — idempotent by RFC 9110 §9.2.2;
//     always safe to retry.
//   • POST / PATCH — retried ONLY on the routes that honour Idempotency-Key
//     server-side (below), where a retry replays the first response instead of
//     re-executing. Everything else surfaces the 5xx to the caller, who knows
//     whether re-issuing is safe.
//
// Keep this list in sync with the `idempotent: true` route options.
const IDEMPOTENT_WRITE_ROUTES: readonly (string | RegExp)[] = [
  "/evals",
  "/security",
  "/batches",
  "/team",
  "/billing",
  "/billing/activate",
  "/chargeback",
  /^\/verticals\/[^/]+\/scan$/,
];

const ALWAYS_IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS", "DELETE", "PUT"]);

/**
 * May a failed attempt at `method path` be retried without risking a duplicate
 * side effect? Conservative by construction: an unknown verb or an unlisted
 * POST/PATCH route answers `false`.
 */
export function isRetriableRequest(method: string, path: string): boolean {
  const m = method.toUpperCase();
  if (ALWAYS_IDEMPOTENT_METHODS.has(m)) return true;
  if (m !== "POST" && m !== "PATCH") return false;
  const route = (path.split("?")[0] || "/").replace(/\/+$/, "") || "/";
  return IDEMPOTENT_WRITE_ROUTES.some((r) =>
    typeof r === "string" ? r === route : r.test(route),
  );
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

// ── Base-URL normalization ─────────────────────────────────────────────

/**
 * Normalize a user-supplied API base URL to the versioned API root the SDK
 * calls against (`.../api/v1`). The rest of the EvalGuard ecosystem documents
 * the base WITHOUT the `/v1` segment — the tracing module, the
 * `EVALGUARD_BASE_URL` env var, and the docs all use `https://evalguard.ai/api`
 * — so a consumer who copies that value into `new EvalGuard({ baseUrl })` would
 * otherwise hit `https://evalguard.ai/api/<path>` and 404 on every call
 * (live E2E 2026-07-16 #5). The CLI already normalizes on `login` (CHANGELOG
 * 2.3.2); this applies the same fix at the SDK boundary. We strip trailing
 * slashes, leave a URL that already ends in `/api/v1` untouched, append the
 * missing `/v1` to a `.../api` base, and append the full `/api/v1` to a bare
 * origin.
 */
export function normalizeApiBaseUrl(rawUrl: string): string {
  const trimmed = rawUrl.replace(/\/+$/, "");
  if (/\/api\/v1$/.test(trimmed)) return trimmed; // already the versioned root
  if (/\/api$/.test(trimmed)) return `${trimmed}/v1`; // `.../api` → `.../api/v1`
  return `${trimmed}/api/v1`; // bare origin → `.../api/v1`
}

// ── Server request-id correlation ──────────────────────────────────────

/** Minimal shape of the standard `{ success:false, error:{ requestId } }`
 *  error envelope, plus a legacy top-level `requestId`, that an error body may
 *  carry. */
interface ErrorEnvelope {
  error?: { code?: string; message?: string; requestId?: string };
  message?: string;
  requestId?: string;
}

/**
 * Resolve the server request id for support correlation from an error
 * response. The auth layer inlines `requestId` in the `{success:false,error}`
 * envelope (so 401s carried it), but most route-level errors (400/422/500) omit
 * it from the body — yet the api-handler stamps `X-Request-Id` on EVERY response
 * (including the 500 fallback). Preferring the body then falling back to the
 * header means the id is populated for ALL error statuses, not just 401
 * (live E2E 2026-07-16 #6). `res.headers` is optional-chained so partial test
 * doubles that omit a `Headers` object don't throw.
 */
function extractRequestId(
  res: { headers?: { get(name: string): string | null } },
  body: ErrorEnvelope | null | undefined,
): string | undefined {
  const fromBody = body?.error?.requestId ?? body?.requestId;
  if (fromBody) return fromBody;
  const fromHeader =
    res.headers?.get("x-evalguard-request-id") ?? res.headers?.get("x-request-id");
  return fromHeader ?? undefined;
}

/** Stable machine code for "the version policy could not be read". */
export const VERSION_POLICY_INDETERMINATE_CODE = "VERSION_POLICY_INDETERMINATE" as const;

export interface VersionPolicyResult {
  allowed: boolean;
  requiredMinimumVersion: string | null;
  requiredMaximumVersion: string | null;
  reason?: string;
  /**
   * The policy could NOT be read — the endpoint was unreachable/timed out,
   * answered non-2xx, or returned a 2xx body carrying no policy (a 200
   * `{success:false,…}` envelope, `data:null`, HTML from a captive proxy).
   *
   * `allowed` is `false` in that case, because the client cannot prove this
   * version is inside the org's pinned range — NOT because a pin was violated.
   * Branch on this field when you need to tell the two apart; the previous
   * behaviour (silently reporting `allowed: true` on every failure shape) meant
   * anyone who could black-hole `/client/policy` turned enterprise version
   * pinning off, and nothing else enforces it: no server route consults
   * `gateway_managed_policy.required_min_version` on ordinary API calls — only
   * `/client/policy` itself does.
   */
  indeterminate?: boolean;
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

// ── Agent memory-governance policy types (Wave 3) ───────────────────────
// The admin-managed policy that governs durable agent-memory writes org-wide
// (or per-project): mode off/monitor/enforce + config knobs (poisoning-screen
// confidence threshold, HITL-on-rewrite, provenance-required). CRUD over
// /agent-memory/governance. The core MemoryGovernanceMode / MemoryGovernanceConfig
// types are re-exported from @evalguard/core (via `export type * from` in index.ts).

/** A stored agent-memory-governance policy, exactly as GET/PUT/POST
 *  /api/v1/agent-memory/governance returns it (camelCase, from the store's
 *  snake_case → app mapping). `config` is a partial of the core
 *  {@link MemoryGovernanceConfig} (`thresholds.poisonMinConfidence`,
 *  `requireApprovalOnRewrite`, `requireProvenance`). */
export interface MemoryGovernancePolicyRecord {
  id: string;
  orgId: string;
  /** null = the org-wide policy; a value = a project-scoped policy. */
  projectId: string | null;
  enabled: boolean;
  mode: MemoryGovernanceMode;
  config: Partial<MemoryGovernanceConfig>;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

// ── Gateway guardrail-config types (Wave 2) ─────────────────────────────
// Per-project, opt-in `gateway_guardrail_config` rows: the inline guardrails
// the gateway proxy wires into the hot path (partner-vendor adapters + the
// local presets). CRUD over /gateway/guardrails. Admin role required (same gate
// as the route). Mirrors the memory-governance policy CRUD above.

/** The local guardrail presets that make NO external call and therefore MUST
 *  NOT carry a `secretRef`: the two content presets (`local-firewall` /
 *  `moderated-firewall`) and the two Wave-2 agent guardrails
 *  (`data-not-instructions` / `tool-call-circuit-breaker`). Every other vendor
 *  (`aporia` / `lakera` / …) resolves a stored key and REQUIRES a `secretRef`.
 *  Canonical source: `ALLOWED_GUARDRAIL_VENDORS`'s local half in
 *  apps/web/src/lib/gateway-guardrail-config.ts. */
export const LOCAL_GUARDRAIL_VENDORS = [
  "local-firewall",
  "moderated-firewall",
  "data-not-instructions",
  "tool-call-circuit-breaker",
] as const;
export type LocalGuardrailVendor = (typeof LOCAL_GUARDRAIL_VENDORS)[number];

/** True when `vendor` is a dependency-free local preset (no external call, no
 *  `secretRef`). Used to model the local-vs-vendor secretRef rule client-side
 *  so a bad config fails fast instead of round-tripping to a 400. */
export function isLocalGuardrailVendor(vendor: string): vendor is LocalGuardrailVendor {
  return (LOCAL_GUARDRAIL_VENDORS as readonly string[]).includes(vendor);
}

/** A stored gateway guardrail-config row, normalized to camelCase from the raw
 *  snake_case row GET/POST /api/v1/gateway/guardrails returns (the route
 *  projects the DB columns directly, unlike the memory-governance route which
 *  maps in its store). `secretRef` points at a stored `provider_keys` row and is
 *  ALWAYS `null` for a {@link LocalGuardrailVendor}. */
export interface GuardrailConfigRecord {
  id: string;
  orgId: string;
  projectId: string;
  vendor: string;
  /** Ordered failover chain; `[vendor]` for a single-vendor row. */
  vendorChain: string[] | null;
  /** GuardrailError categories that advance the chain to the next vendor. */
  fallbackOnErrors: string[] | null;
  /** Non-secret vendor knobs (endpoint / profile / baseUrl) — never a raw key. */
  config: Record<string, unknown>;
  /** A `provider_keys` row id for vendor adapters; `null` for local presets. */
  secretRef: string | null;
  onFlag: GuardrailFlagAction;
  checkRequest: boolean;
  checkResponse: boolean;
  tokenizePii: boolean;
  enabled: boolean;
  priority: number;
  createdAt: string;
  updatedAt: string;
}

/**
 * Raw snake_case `gateway_guardrail_config` row exactly as GET/POST
 * /gateway/guardrails returns it (the route projects DB columns directly).
 * {@link mapGuardrailConfigRow} normalizes it into the camelCase
 * {@link GuardrailConfigRecord} the SDK's typed surface promises, mirroring the
 * {@link mapEvalRunRow} pattern (raw rows would otherwise leave
 * `orgId`/`onFlag`/`secretRef`/… `undefined` at runtime).
 */
interface GuardrailConfigWireRow {
  id: string;
  org_id: string;
  project_id: string;
  vendor: string;
  vendor_chain?: string[] | null;
  fallback_on_errors?: string[] | null;
  config?: Record<string, unknown> | null;
  secret_ref?: string | null;
  on_flag: GuardrailFlagAction;
  check_request: boolean;
  check_response: boolean;
  tokenize_pii: boolean;
  enabled: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
}

/** Map a raw {@link GuardrailConfigWireRow} to the declared camelCase
 *  {@link GuardrailConfigRecord}. */
function mapGuardrailConfigRow(row: GuardrailConfigWireRow): GuardrailConfigRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    projectId: row.project_id,
    vendor: row.vendor,
    vendorChain: row.vendor_chain ?? null,
    fallbackOnErrors: row.fallback_on_errors ?? null,
    config: row.config ?? {},
    secretRef: row.secret_ref ?? null,
    onFlag: row.on_flag,
    checkRequest: row.check_request,
    checkResponse: row.check_response,
    tokenizePii: row.tokenize_pii,
    enabled: row.enabled,
    priority: row.priority,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Params for {@link EvalGuard.upsertGuardrailConfig}. Idempotent on
 *  (projectId, vendor). For a {@link LocalGuardrailVendor}, omit `secretRef`
 *  (the client throws if one is passed); for every other vendor, `secretRef` is
 *  required. */
export interface UpsertGuardrailConfigParams {
  orgId: string;
  projectId: string;
  vendor: string;
  /** Non-secret vendor knobs (endpoint / profile / baseUrl). */
  config?: Record<string, unknown>;
  /** Optional vendor failover chain; `vendorChain[0]` MUST equal `vendor`. */
  vendorChain?: string[];
  /** GuardrailError categories that advance the chain to the next vendor. */
  fallbackOnErrors?: string[];
  /** A stored `provider_keys` row id. Required for vendor adapters; MUST be
   *  omitted / null for a {@link LocalGuardrailVendor}. */
  secretRef?: string | null;
  onFlag?: GuardrailFlagAction;
  checkRequest?: boolean;
  checkResponse?: boolean;
  tokenizePii?: boolean;
  enabled?: boolean;
  priority?: number;
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
  /**
   * Maximum achievable score. Optional because the list endpoint (GET /evals,
   * backing {@link EvalGuard.listEvals}) does NOT project `max_score` — so it is
   * genuinely absent on list rows rather than fabricated. Present when a
   * response carries it.
   */
  maxScore?: number;
  duration: number | null;
  createdAt: string;
  completedAt?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Raw snake_case eval-run row exactly as GET /evals returns it (the DB row
 * projection). {@link mapEvalRunRow} normalizes it into the camelCase
 * {@link EvalRun} the SDK's typed surface promises. (Live E2E 2026-07-16 #2:
 * `listEvals()` returned these raw rows, so `createdAt`/`completedAt`/
 * `projectId`/`metadata` were all `undefined` at runtime.)
 */
interface EvalRunWireRow {
  id: string;
  name: string;
  model?: string | null;
  status: EvalRun["status"];
  score?: number | null;
  config?: Record<string, unknown> | null;
  created_at: string;
  completed_at?: string | null;
  created_by?: string | null;
  duration?: number | null;
  /** Present only if a future/other endpoint projects it (list route omits it). */
  max_score?: number | null;
  /** Present only if a future/other endpoint projects it (list route omits it). */
  project_id?: string | null;
}

/**
 * Map a raw {@link EvalRunWireRow} to the declared camelCase {@link EvalRun}.
 * `projectId` falls back to the query-scoped project id when the row omits
 * `project_id` (the list route filters by it but does not select it), so every
 * returned run is correctly scoped. Optional wire fields (`completed_at`,
 * `config`, `max_score`) are only set when present, keeping the runtime object
 * honest with the declared optional-ness.
 */
function mapEvalRunRow(row: EvalRunWireRow, scopedProjectId: string): EvalRun {
  const run: EvalRun = {
    id: row.id,
    projectId: row.project_id ?? scopedProjectId,
    name: row.name,
    status: row.status,
    score: row.score ?? null,
    duration: row.duration ?? null,
    createdAt: row.created_at,
  };
  if (row.max_score != null) run.maxScore = row.max_score;
  if (row.completed_at) run.completedAt = row.completed_at;
  if (row.config) run.metadata = row.config;
  return run;
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

/**
 * What POST /evals actually returns: a "started" run STUB, not a finished
 * {@link EvalResult}. The server inserts the run as `running` and fires the
 * model execution in the background (fire-and-forget), returning 201 with just
 * the run id + counts immediately. Poll {@link EvalGuard.getEvalRun} for the
 * scored result. (Audit 2026-07-15 #2: `eval()` was mistyped `EvalResult`, so
 * consumers reading `.score`/`.passRate` off the returned stub got undefined/NaN.)
 */
export interface EvalStartedRun {
  /** The created run id — pass to {@link EvalGuard.getEvalRun}. */
  id: string;
  /** Always "running" on create (the model runs in the background). */
  status: "running" | "pending" | string;
  /** Number of test cases queued (0 for external / imperative-logger runs). */
  totalTests: number;
  model: string;
  /** True for external (imperative {@link EvaluationLogger}) runs. */
  external?: boolean;
  message?: string;
}

/** One mapped per-case result row from GET /evals/{runId}. */
export interface EvalRunCaseResult {
  id: string;
  test_case_index: number;
  input: string;
  expected: string | null;
  output: string;
  scores: Record<string, { score: number; passed: boolean; reason?: string }>;
  score: number;
  latency_ms: number;
  cost: number;
  passed: boolean;
}

/** Aggregated summary block from GET /evals/{runId}. */
export interface EvalRunSummary {
  totalCases: number;
  passedCases: number;
  failedCases: number;
  /** Fraction of cases that passed, 0..1. */
  passRate: number;
  /** Mean per-case score, 0..1. */
  avgScore: number;
  totalLatency: number;
  totalCost: number;
}

/**
 * Full result of {@link EvalGuard.getEvalRun}. The endpoint returns the
 * eval_run row (`run`) + per-case `results` + an aggregate `summary`, and —
 * since the 2026-07 backend fix — ALSO the run's `status`/`score`/`passRate`
 * FLAT at the top level. The SDK reads those flat fields when present and
 * otherwise derives them from `run`/`summary`, so `status`/`score`/`passRate`
 * are always populated regardless of backend version (back-compat). (Audit
 * 2026-07-15 #2: `getEvalRun()` was mistyped `EvalRun`, but the wire shape is
 * `{ run, results, summary }`, so `.status`/`.score` were always undefined.)
 */
export interface EvalRunDetail {
  /** Terminal / most-recent run status (flat). */
  status: EvalRun["status"] | null;
  /** Aggregate score on a 0..1 scale, null until scored (flat). */
  score: number | null;
  /** Fraction of cases that passed, 0..1, null when not computable (flat). */
  passRate: number | null;
  /** The full eval_run row (null on a malformed / legacy response). */
  run: EvalRun | null;
  /** Per-case results (empty array when none). */
  results: EvalRunCaseResult[];
  /** Aggregated summary (null on older servers that omit it). */
  summary: EvalRunSummary | null;
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

/**
 * What POST /security actually returns: a started-scan STUB, not a finished
 * {@link SecurityScanResult}. The route inserts the scan, runs the probes, and
 * returns 201 with just the id + summary counts — the per-finding detail lives
 * behind {@link EvalGuard.getScan}. Poll `getScan(id)` for {@link SecurityFinding}
 * rows. (Live E2E 2026-07-16 #4: `securityScan()` was mistyped
 * `SecurityScanResult`, so consumers reading `.findings`/`.passRate` off the
 * returned stub got `undefined`/`NaN` — the identical class of bug already fixed
 * for `eval()` → {@link EvalStartedRun}.)
 */
export interface SecurityScanStartedRun {
  /** The created scan id — pass to {@link EvalGuard.getScan}. */
  id: string;
  /** Terminal status assigned on completion (e.g. "passed" | "failed" | "error"). */
  status: string;
  /** Pass score on a 0–100 scale. */
  score: number;
  /** Number of attack probes executed. */
  totalTests: number;
  /** Wall-clock scan duration in milliseconds. */
  duration: number;
  /** Failing-finding counts bucketed by severity. */
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Total number of findings recorded (fetch them via {@link EvalGuard.getScan}). */
  findingsCount: number;
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
// Waiver-file model: waive a (CVE, package) tuple so it stops failing the
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
  /**
   * COUNT of newly-seen CVEs this run — the numeric sibling of `newVulns`,
   * equal to `newVulns.length`.
   *
   * Added 2026-08-09 to TYPE a field the route already emits
   * (`apps/web/src/app/api/v1/sbom-monitor/run/route.ts`). `newVulns` stays
   * the ARRAY and is deliberately NOT renamed: `apps/cli` iterates it and the
   * PUBLISHED @evalguard/sdk types it as `SbomMonitorAlertableCve[]`, so a
   * rename would break a shipped surface to fix one dashboard page. The count
   * instead takes the name its three neighbours already establish.
   *
   * OPTIONAL on purpose: a self-hosted deployment older than that route omits
   * the field entirely, and this SDK is version-skewed against those. Read it
   * as `newVulnCount ?? newVulns.length` when a number is needed
   * unconditionally.
   */
  newVulnCount?: number;
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
  /** Mirrors core's `FirewallRuleType`. `"secrets"` added 2026-08-05,
   *  `"known-bad"` (EICAR / GTUBE / GTphish canaries) added 2026-08-06 — see
   *  packages/core/src/security/firewall.ts. An unrecognised value is not
   *  ignored: core fails CLOSED on it (blocks) rather than skipping the rule. */
  type: "pii" | "injection" | "toxic" | "topic" | "custom" | "secrets" | "known-bad";
  enabled: boolean;
  config?: Record<string, unknown>;
}

/**
 * Sensitivity dial for {@link EvalGuard.checkFirewall} — a four-level L1–L4
 * scale. Accepts the level name or its ordinal (1–4). When unset, the engine's
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

/** One entry in {@link GuardrailsCheckResult.reasons} — the wire shape of a
 *  core `FirewallReason` (POST /guardrails returns the raw `checkFirewall()`
 *  result). (Live E2E 2026-07-16 #3: the declared `{layer?,detail,score?}` never
 *  matched the wire, which is `{rule,type,detail,severity}`.) */
export interface GuardrailsReason {
  /** The name of the firewall rule that fired. */
  rule: string;
  /** The rule category that matched, or `"invalid-rule"` when the server could
   *  NOT run a configured rule (unknown `type`) and therefore blocked rather
   *  than reporting a pass it could not vouch for. */
  type: "pii" | "injection" | "toxic" | "topic" | "custom" | "secrets" | "invalid-rule" | string;
  /** Human-readable detail of what was detected. */
  detail: string;
  /** Severity of the match. */
  severity: "critical" | "high" | "medium" | "low" | string;
}

/**
 * Every `action` this client knows how to interpret.
 *
 * The wire values are core `FirewallResult["action"]` —
 * `"allow" | "block" | "flag"` (packages/core/src/security/firewall.ts:35).
 * `"redact"` is included because {@link GuardrailsCheckResult} has always
 * declared it publicly. Anything outside this set is INDETERMINATE: a caller
 * writing `if (res.action === "block")` would read an unknown action as
 * permission, which is exactly the fail-open this list exists to prevent.
 */
export const GUARDRAIL_ACTIONS = ["allow", "block", "flag", "redact"] as const;

/** Result of {@link EvalGuard.runGuardrails} (POST /guardrails) — raw checkFirewall() shape. */
export interface GuardrailsCheckResult {
  action: "allow" | "redact" | "block" | string;
  reasons: GuardrailsReason[];
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

/**
 * Every `decision` this client knows how to interpret on a 2xx from
 * POST /mcp/invoke.
 *
 * The gateway only emits a 2xx when the decision pipeline let the call
 * proceed — every deny code is a 403 (`apiError(reason, 403, decision)`,
 * apps/web/src/app/api/v1/mcp/invoke/route.ts), which `request()` already
 * raises as an `EvalGuardError`. So the reachable set is the allowed=true
 * decisions plus the 202 durable-HITL suspend:
 *
 *   allow                   the enforcement cascade permitted the call
 *   honeypot_triggered      a decoy tool: the caller is served a benign 200
 *                           while the trip is alerted out-of-band
 *   pending_human_approval  202 — SUSPENDED pending a human decision; the
 *                           tool was NOT executed
 *   strip_ungrounded /      the two other allowed=true EnforcementDecision
 *   spotlight_untrusted     codes (packages/core/src/mcp-gateway/enforcer.ts);
 *                           the pipeline does not map them today, but they
 *                           mean "the call proceeded with a mutated result",
 *                           so accepting them cannot fail open.
 *
 * Anything outside this set is a decision this client cannot interpret —
 * including ABSENT. A caller writing `if (r.decision !== "allow") refuse()`
 * survives that, but `if (r.decision.startsWith("deny")) refuse()` (and every
 * caller that just consumes `r.response`) reads it as permission for a tool
 * call that no gateway pipeline ever authorised.
 */
export const MCP_INVOKE_DECISIONS = [
  "allow",
  "honeypot_triggered",
  "pending_human_approval",
  "strip_ungrounded",
  "spotlight_untrusted",
] as const;

export interface McpInvokeResult {
  /**
   * One of {@link MCP_INVOKE_DECISIONS} on every response this client accepts.
   * Typed as `| string` (like {@link GuardrailsCheckResult.action}) so the
   * published surface stays back-compatible for consumers that compare it to
   * their own constants.
   */
  decision: "allow" | "honeypot_triggered" | "pending_human_approval" | string;
  reason: string;
  response: unknown;
  latencyMs: number;
  failover?: { fromServerId: string; toServerId: string };
}

// ── Online evaluations (production sampling) ───────────────────────────

/** A production online-eval sampler: scores a sampled % of live traffic. */
export interface OnlineEvalSampler {
  id: string;
  project_id: string;
  name: string;
  enabled: boolean;
  sample_rate: number;
  max_per_hour: number;
  scorer_keys: string[];
  model_filter: string[];
  execution_mode: "sync" | "async";
  last_run_at: string | null;
  last_run_sampled: number | null;
  last_run_scored: number | null;
  last_run_skipped: number | null;
  created_at: string;
  updated_at: string;
}

/** One scored online-eval result row over the query window. */
export interface OnlineEvalResult {
  id: string;
  sampler_id: string;
  scorer_key: string;
  score: number | null;
  passed: boolean | null;
  duration_ms: number | null;
  error: string | null;
  occurred_at: string;
}

/** Per-scorer aggregate over the window returned by listOnlineEvals. */
export interface OnlineEvalAggregate {
  total: number;
  passRate: number;
  errorRate: number;
  p95DurationMs: number | null;
}

export interface OnlineEvalsSummary {
  samplers: OnlineEvalSampler[];
  recentResults: OnlineEvalResult[];
  aggregates: Record<string, OnlineEvalAggregate>;
  windowSince: string;
}

export interface CreateOnlineEvalSamplerInput {
  projectId: string;
  name: string;
  sample_rate?: number;
  max_per_hour?: number;
  scorer_keys?: string[];
  model_filter?: string[];
  execution_mode?: "sync" | "async";
  enabled?: boolean;
}

export interface UpdateOnlineEvalSamplerInput {
  enabled?: boolean;
  sample_rate?: number;
  max_per_hour?: number;
  scorer_keys?: string[];
  model_filter?: string[];
  execution_mode?: "sync" | "async";
}

// ── Prompt optimizer ───────────────────────────────────────────────────

export type PromptOptimizeStrategy =
  | "meta-prompt"
  | "few-shot"
  | "genetic"
  | "bootstrap"
  | string;

export interface OptimizePromptInput {
  projectId: string;
  prompt: string;
  strategy: PromptOptimizeStrategy;
  evalCases: Array<{ input: string; expectedOutput?: string }>;
  scorers: string[];
  targetModel?: string;
  maxIterations?: number;
  targetScore?: number;
  costCeilingUsd?: number;
  /** genetic-strategy knobs */
  populationSize?: number;
  mutationRate?: number;
  crossoverRate?: number;
  eliteCount?: number;
  /** few-shot / bootstrap knob */
  maxExamples?: number;
}

export interface OptimizePromptResult {
  optimizedPrompt: string;
  originalScore: number;
  optimizedScore: number;
  improvementPercent: number;
  strategy: string;
  iterations: number;
  changelog: unknown[];
  durationMs: number;
  targetModel: string;
  costUsd: number;
}

// ── Client ────────────────────────────────────────────────────────────

export class EvalGuard {
  private apiKey: string;
  private baseUrl: string;
  private subject: SubjectContext | null;
  /**
   * Per-instance registry of customer-defined plugins / strategies / scorers.
   * Lets callers extend the 249 built-in attack plugins from their own TS
   * code without forking the monorepo.
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
  /**
   * Default org resolved lazily from GET /project/current and cached for the
   * lifetime of this client, mirroring {@link resolvedProjectId}. Used by
   * org-scoped methods (e.g. {@link createDataSource}) when `orgId` is omitted.
   */
  private resolvedOrgId?: string;

  constructor(config: EvalGuardConfig) {
    this.apiKey = config.apiKey;

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

    // Normalize to the versioned API root so a base copied from the docs / env
    // convention (`https://evalguard.ai/api`, no `/v1`) or given with a trailing
    // slash still resolves — otherwise every call 404s (live E2E 2026-07-16 #5).
    // The hosted default already includes `/api/v1`.
    this.baseUrl = config.baseUrl
      ? normalizeApiBaseUrl(config.baseUrl)
      : "https://evalguard.ai/api/v1";
    this.subject = null;
    // Use static import (was a runtime require under CJS — broken in
    // vitest ESM with "Cannot find module './extensions'"). Cost is the
    // module evaluation, not the registry instantiation, and ESM
    // tree-shaking means consumers that never use() pay nothing in the
    // final bundle anyway.
    this.extensions = new ExtensionRegistry();

    // Sandbox awareness. Inside a NemoClaw/OpenClaw sandbox whose egress
    // allowlist omits our host, every call below fails as an opaque
    // `TypeError: fetch failed` with no cause worth reading, and the fix is one
    // line in a YAML file the operator already owns. Warns at most once per
    // host, only when a policy was successfully read AND excludes the host,
    // and never throws — see packages/sdk/src/sandbox.ts on why this is
    // advisory. Silence with EVALGUARD_SUPPRESS_SANDBOX_WARNING=1.
    warnIfSandboxBlocks(this.baseUrl);
  }

  /**
   * Register a custom plugin, strategy, or scorer — a customer-defined
   * red-team plugin, eval scorer, or attack strategy, usable at runtime
   * without forking the monorepo.
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
   * a READ; it never mutates anything.
   *
   * AUDIT 2026-08-03 (sdk-mcpinvoke-failopen, item 3). This used to return
   * `{ allowed: true }` on EVERY failure shape — connection refused, timeout,
   * 401/404/500, and a 200 carrying a `{success:false,…}` error envelope — on
   * the stated grounds that "the server ALSO sees the version header on every
   * request and can enforce there". It does not: `checkClientVersion` /
   * `gateway_managed_policy.required_min_version` are read by exactly one route,
   * `/api/v1/client/policy` (the advisory endpoint this method calls). There is
   * no other server-side gate, so the client WAS the enforcement point and
   * anyone able to black-hole one GET disabled enterprise version pinning for
   * the whole fleet.
   *
   * Now: a policy that could not be READ is {@link VersionPolicyResult.indeterminate}
   * — `allowed: false` with `indeterminate: true`, never a fabricated "allowed".
   * A genuinely unpinned org still returns `allowed: true`, so nothing changes
   * for a reachable endpoint.
   */
  async checkVersionPolicy(): Promise<VersionPolicyResult> {
    const indeterminate = (why: string): VersionPolicyResult => ({
      allowed: false,
      indeterminate: true,
      requiredMinimumVersion: null,
      requiredMaximumVersion: null,
      reason:
        `EvalGuard could not read this organization's client version policy (${why}), so ` +
        `@evalguard/sdk ${SDK_VERSION} cannot be confirmed to be within the pinned range ` +
        `(INDETERMINATE — treated as a failure, never as "allowed"). This is NOT a pin ` +
        `violation: branch on \`indeterminate\` if your deployment must proceed anyway.`,
    });

    let json: unknown;
    try {
      // A 3s timeout and NO retry — bypassing request()'s 3x exponential
      // backoff, which can take several seconds on a network blip and would
      // hang an SDK init.
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      try {
        const policyUrl = `${this.baseUrl}/client/policy?version=${encodeURIComponent(SDK_VERSION)}`;
        const res = await followSameHostRedirects(
          policyUrl,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${this.apiKey}`,
              "x-evalguard-client-version": SDK_VERSION,
              ...this.subjectHeaders(),
            },
            signal: controller.signal,
          },
          // See request(). This endpoint is the SOLE enforcement point for
          // enterprise version pinning, so a redirect-supplied
          // `versionCheck.allowed:true` from ANOTHER HOST would forge an
          // in-policy verdict. A refusal throws, which lands on the catch below
          // -> indeterminate (deny). Same-host hops (a trailing-slash 308, an
          // http->https 301) are followed so a normalising origin does not turn
          // enterprise version pinning into a hard failure.
          { label: `GET /client/policy` },
        );
        // A non-2xx is not a policy. 401 (revoked key), 403 (plan gate), 404
        // (older server), 5xx — none of them prove this client is in policy.
        if (!res.ok) return indeterminate(`the endpoint answered HTTP ${res.status}`);
        json = (await res.json()) as unknown;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch {
      return indeterminate("the endpoint was unreachable or timed out");
    }

    // API responses are enveloped as { success, data } — unwrap if present.
    // OWN-property membership only: `"data" in json` inherits, which would let
    // `Object.prototype.data` fabricate a version policy for a body that
    // carried none. Same helper as request(). (The bounds below were already
    // read with hasOwnProperty; the unwrap above them was not.)
    const unwrapped = unwrapApiEnvelope(json);
    if (unwrapped === null || typeof unwrapped !== "object" || Array.isArray(unwrapped)) {
      return indeterminate(`the response carried no policy object — shape: ${describeVerdictShape(unwrapped)}`);
    }
    const rec = unwrapped as Record<string, unknown>;
    // Both bounds are ALWAYS present on a real answer: the route builds its
    // body by spreading the `{requiredMinimumVersion, requiredMaximumVersion}`
    // default (apps/web/src/app/api/v1/client/policy/route.ts). A body missing
    // them is a rewritten/error envelope, not "unpinned".
    // OWN-property reads throughout (audit js-requireverdict-own-properties).
    // `OWN` is the module-load-captured test — `Object.prototype.hasOwnProperty`
    // is itself writable, so calling it through the prototype is not a
    // pollution-proof own-property test.
    const rawMin = readOwn(rec, "requiredMinimumVersion");
    const rawMax = readOwn(rec, "requiredMaximumVersion");
    const hasBounds =
      OWN(rec, "requiredMinimumVersion") && OWN(rec, "requiredMaximumVersion");
    const boundOk = (v: unknown) => v === null || typeof v === "string";
    if (!hasBounds || !boundOk(rawMin) || !boundOk(rawMax)) {
      return indeterminate(
        `the response carried no readable version bounds — shape: ${describeVerdictShape(rec)}`,
      );
    }

    const min = (rawMin as string | null) ?? null;
    const max = (rawMax as string | null) ?? null;
    const result: VersionPolicyResult = {
      allowed: true,
      requiredMinimumVersion: min,
      requiredMaximumVersion: max,
    };
    if (!min && !max) return result; // unpinned — the default, unchanged

    // Prefer the SERVER's own verdict when it sent one (it always does when a
    // version is reported, which this method always does). Reusing it keeps the
    // client from re-deriving — and disagreeing with — `checkClientVersion`.
    // Own-only: `Object.prototype.versionCheck = { allowed: true }` would
    // otherwise hand an out-of-range client a server "allowed" verdict the
    // server never sent, defeating the enterprise version pin.
    const vc = readOwn(rec, "versionCheck");
    if (vc && typeof vc === "object" && !Array.isArray(vc)) {
      const allowed = readOwn(vc, "allowed");
      const reason = readOwn(vc, "reason");
      if (typeof allowed === "boolean") {
        result.allowed = allowed;
        if (!allowed) {
          result.reason =
            typeof reason === "string" && reason
              ? reason
              : `@evalguard/sdk ${SDK_VERSION} is outside the version range required by this organization (min=${min ?? "-"}, max=${max ?? "-"}).`;
        }
        return result;
      }
    }

    const ver = parseSemverTuple(SDK_VERSION);
    const minT = parseSemverTuple(min);
    const maxT = parseSemverTuple(max);
    // FAIL CLOSED on an unparseable version while a bound IS set — the same
    // rule the server's `checkClientVersion` applies ("an org that pins a range
    // expects every client to prove its version; a client that can't is treated
    // as out-of-policy"). The old code's `if (ver && minT && …)` guards silently
    // ALLOWED whenever a bound (e.g. "v2", "1.2") or SDK_VERSION failed to parse.
    if (!ver || (min && !minT) || (max && !maxT)) {
      result.allowed = false;
      result.reason =
        `This organization pins the client version range (min=${min ?? "-"}, max=${max ?? "-"}), but ` +
        `the range could not be compared against @evalguard/sdk ${SDK_VERSION} (unparseable semver), ` +
        `so this client cannot prove it is in policy.`;
      return result;
    }
    if (minT && cmpSemver(ver, minT) < 0) {
      result.allowed = false;
      result.reason = `@evalguard/sdk ${SDK_VERSION} is below the minimum version (${min}) required by this organization. Upgrade to continue.`;
    } else if (maxT && cmpSemver(ver, maxT) > 0) {
      result.allowed = false;
      result.reason = `@evalguard/sdk ${SDK_VERSION} is above the maximum version (${max}) allowed by this organization. Downgrade to a supported release.`;
    }
    return result;
  }

  /**
   * Like `checkVersionPolicy()` but THROWS when this SDK version is outside the
   * org's pinned range — call it once at startup to hard-stop an out-of-policy
   * client before it issues any real requests.
   *
   * It also throws when the policy could not be READ
   * ({@link VersionPolicyResult.indeterminate}) — an assertion that passes
   * because the check never ran is not an assertion. The thrown
   * {@link EvalGuardError} carries `code: "VERSION_POLICY_INDETERMINATE"` so a
   * caller that deliberately wants to continue offline can catch exactly that
   * case; nothing inside this SDK calls `assertVersionAllowed()` implicitly.
   */
  async assertVersionAllowed(): Promise<void> {
    const v = await this.checkVersionPolicy();
    if (v.allowed) return;
    if (v.indeterminate) {
      throw new EvalGuardError(
        v.reason ?? "EvalGuard client version policy could not be read",
        { code: VERSION_POLICY_INDETERMINATE_CODE },
      );
    }
    throw new Error(v.reason ?? "EvalGuard client version not allowed by org policy");
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
    // Own-only (audit js-requireverdict-own-properties). This id becomes the
    // SCOPE of every subsequent check — a firewall/guardrail call scoped to the
    // wrong project applies the wrong rules — so it must come from the server's
    // body, not from `Object.prototype.projectId`.
    const projectId = data && typeof data === "object" ? readOwn(data, "projectId") : undefined;
    if (!projectId || typeof projectId !== "string") {
      throw new EvalGuardError(
        "Could not resolve a default project; pass projectId explicitly.",
        { code: "PROJECT_RESOLUTION_FAILED" },
      );
    }
    this.resolvedProjectId = projectId;
    return projectId;
  }

  /**
   * Resolve (and cache) the default org for this API key.
   *
   * GETs /project/current — which returns RAW `{ projectId, orgId }` (not the
   * `{ success, data }` envelope) and auto-creates a default project on a fresh
   * org. The resolved id is cached on the instance so repeated org-scoped calls
   * never re-fetch. Throws a clear, actionable error when no org can be resolved
   * so the caller knows to pass `orgId` explicitly.
   *
   * Public so callers can pre-warm / inspect the resolved id; org-scoped methods
   * (e.g. {@link createDataSource}) use it automatically when `orgId` is omitted.
   */
  async resolveOrgId(): Promise<string> {
    if (this.resolvedOrgId) return this.resolvedOrgId;
    let data: { orgId?: string } | undefined;
    try {
      data = await this.request<{ projectId?: string; orgId?: string }>("/project/current", "GET");
    } catch (err) {
      throw new EvalGuardError(
        "Could not resolve a default org; pass orgId explicitly.",
        { code: "ORG_RESOLUTION_FAILED", cause: err },
      );
    }
    // Own-only — same reasoning as resolveProjectId: this id scopes the checks.
    const orgId = data && typeof data === "object" ? readOwn(data, "orgId") : undefined;
    if (!orgId || typeof orgId !== "string") {
      throw new EvalGuardError(
        "Could not resolve a default org; pass orgId explicitly.",
        { code: "ORG_RESOLUTION_FAILED" },
      );
    }
    this.resolvedOrgId = orgId;
    return orgId;
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
      // Own-only — same reasoning as resolveOrgId.
      const resolved = data && typeof data === "object" ? readOwn(data, "orgId") : undefined;
      orgId = typeof resolved === "string" ? resolved : undefined;
      if (!orgId) {
        throw new EvalGuardError(
          "Could not resolve a default org; pass orgId explicitly.",
          { code: "ORG_RESOLUTION_FAILED" },
        );
      }
    }
    // FAIL CLOSED: this powers "intent-conditioned policy", so `sensitivity`
    // is a clearance verdict — `if (c.sensitivity === "restricted") block()`
    // reads an ABSENT field as "not restricted" and lets the prompt through,
    // and `riskScore` is thresholded the same way. The wire values are core's
    // SENSITIVITY_LEVELS ladder (packages/core/src/intent/index.ts:319); a
    // level outside it is one this client cannot rank.
    return requireVerdict<IntentClassification>(
      await this.request("/governance/intent/classify", "POST", {
        orgId,
        prompt,
        sensitivityFloor: opts?.sensitivityFloor,
      }),
      "POST /governance/intent/classify",
      [
        { path: ["sensitivity"], kind: "enum", values: SENSITIVITY_LEVELS },
        { path: ["riskScore"], kind: "number" },
      ],
    );
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

  /**
   * Start an eval run. POST /evals inserts the run as `running`, fires the
   * model execution in the BACKGROUND, and returns a started-run STUB
   * immediately (NOT a finished result). Poll {@link getEvalRun} for the score.
   */
  async eval(params: EvalParams): Promise<EvalStartedRun> {
    // Resolve a default project only when none was passed — an explicit
    // projectId is sent verbatim (and skips the /project/current fetch).
    const body = params.projectId
      ? params
      : { ...params, projectId: await this.resolveProjectId() };
    return this.request("/evals", "POST", body);
  }

  /**
   * Fetch an eval run's current state. The endpoint returns
   * `{ run, results, summary }` and — since the 2026-07 backend fix — ALSO
   * `status`/`score`/`passRate` FLAT at the top level. This reads the flat
   * fields when present and otherwise derives them from `run`/`summary`, so the
   * returned {@link EvalRunDetail} always exposes populated
   * `status`/`score`/`passRate` regardless of backend version (back-compat).
   */
  async getEvalRun(id: string): Promise<EvalRunDetail> {
    const raw = await this.request<{
      run?: EvalRun | null;
      results?: EvalRunCaseResult[];
      summary?: EvalRunSummary | null;
      status?: EvalRun["status"] | null;
      score?: number | null;
      passRate?: number | null;
    }>(`/evals/${id}`, "GET");

    const run = raw.run ?? null;
    const summary = raw.summary ?? null;
    // Prefer the flat top-level fields (present since the 2026-07 backend fix);
    // fall back to run.*/summary.* so older servers keep working. `??` (not `||`)
    // so a legitimate 0 score / "passed" status isn't discarded.
    const status = raw.status ?? run?.status ?? null;
    const score = raw.score ?? run?.score ?? summary?.avgScore ?? null;
    const passRate = raw.passRate ?? summary?.passRate ?? null;

    return { status, score, passRate, run, results: raw.results ?? [], summary };
  }

  async listEvals(projectId?: string): Promise<EvalRun[]> {
    // Explicit empty string is a caller error; `undefined` means "resolve the
    // default project for this key".
    if (projectId !== undefined && !projectId) throw new Error("projectId is required");
    const resolved = projectId ?? (await this.resolveProjectId());
    // GET /evals returns RAW snake_case rows; normalize each to the declared
    // camelCase EvalRun shape so createdAt/completedAt/projectId/metadata are
    // populated at runtime (live E2E 2026-07-16 #2).
    const rows = await this.request<EvalRunWireRow[]>(
      `/evals?projectId=${encodeURIComponent(resolved)}`,
      "GET",
    );
    return (rows ?? []).map((row) => mapEvalRunRow(row, resolved));
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
   * Start an imperative {@link EvaluationLogger} bound to a new
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

  /**
   * Start a red-team security scan. POST /security runs the attack probes and
   * returns a started-scan STUB ({@link SecurityScanStartedRun}) — the id +
   * summary counts, NOT the per-finding detail. Poll {@link getScan} with the
   * returned `id` for the {@link SecurityFinding} rows.
   *
   *   const scan = await client.securityScan({ model, prompt, attackTypes });
   *   const result = await client.getScan(scan.id); // findings, passRate, …
   */
  async securityScan(params: SecurityScanParams): Promise<SecurityScanStartedRun> {
    // Resolve a default project only when none was passed — an explicit
    // projectId is sent verbatim (and skips the /project/current fetch).
    const body = params.projectId
      ? params
      : { ...params, projectId: await this.resolveProjectId() };
    // FAIL CLOSED on the summary a CI gate reads before it ever polls getScan:
    // `if (scan.severityCounts.critical > 0) fail()` and
    // `if (scan.findingsCount === 0) ship()` both read an unreadable 2xx as a
    // clean red-team result. `totalTests` rides along so a scan that executed
    // nothing cannot report as a scan that found nothing. (Route:
    // `apiSuccess({ id, status, score, totalTests, …, findingsCount }, 201)`.)
    return requireVerdict<SecurityScanStartedRun>(
      await this.request("/security", "POST", body),
      "POST /security",
      [
        { path: ["findingsCount"], kind: "number" },
        { path: ["totalTests"], kind: "number" },
        { path: ["severityCounts", "critical"], kind: "number" },
      ],
    );
  }

  async getScan(id: string): Promise<SecurityScanResult> {
    // FAIL CLOSED — identical reasoning to scanSecrets / scanIac, which were
    // hardened while this one (the red-team scan's OWN result reader) was not.
    // `(scan.findings ?? []).length === 0` is the documented "did the red-team
    // find anything" gate, so an ABSENT findings array is a clean bill of
    // health for a scan whose result never arrived. `totalTests` rides along so
    // "ran nothing" cannot read as "found nothing".
    return requireVerdict<SecurityScanResult>(
      await this.request(`/security/${id}`, "GET"),
      "GET /security/{scanId}",
      [
        { path: ["findings"], kind: "array" },
        { path: ["totalTests"], kind: "number" },
      ],
    );
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
    // FAIL CLOSED: both verdicts are read as booleans by callers comparing the
    // enforcing config against the candidate one. An absent `enforcing.blocked`
    // silently reports "the live config allowed this".
    return requireVerdict<{
      divergence: "agree-block" | "agree-allow" | "shadow-stricter" | "shadow-looser";
      enforcing: { blocked: boolean; category: string | null; latencyMs: number };
      shadow: { blocked: boolean; category: string | null; latencyMs: number };
      latencyOverheadMs: number;
      recorded: boolean;
    }>(
      await this.request("/gateway/guardrails/shadow/evaluate", "POST", params),
      "POST /gateway/guardrails/shadow/evaluate",
      [
        { path: ["enforcing", "blocked"], kind: "boolean" },
        { path: ["shadow", "blocked"], kind: "boolean" },
      ],
    );
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
   * file contents — signature-based, in-product. Pass a single `content` blob
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
    // FAIL CLOSED: for a findings-shaped scanner, an ABSENT `findings` array is
    // indistinguishable from an empty one at the call site
    // (`(res.findings ?? []).length === 0` → "no secrets"), which is a clean
    // bill of health for a scan whose result never arrived. `scannedFiles` is
    // required alongside so "scanned nothing" cannot read as "found nothing".
    return requireVerdict<SecretScanResult>(
      await this.request("/security/secret-scan", "POST", input),
      "POST /security/secret-scan",
      [
        { path: ["findings"], kind: "array" },
        { path: ["scannedFiles"], kind: "number" },
      ],
    );
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

  /**
   * List every scorer the platform exposes (GET /scorers). The route wraps the
   * array in `{ scorers, total }`; this unwraps to the bare `Scorer[]` so
   * callers can `.map`/`for..of` directly — consistent with
   * {@link listWorkflows}. (Live E2E 2026-07-16 #1: `listScorers()` resolved to
   * the wrapper object, so `.map` threw.)
   */
  async listScorers(): Promise<Scorer[]> {
    const res = await this.request<{ scorers: Scorer[] } | Scorer[]>("/scorers", "GET");
    return Array.isArray(res) ? res : res.scorers;
  }

  /**
   * List every red-team attack plugin the platform exposes (GET /plugins).
   * Unwraps the `{ plugins, total }` envelope to the bare `Plugin[]`, matching
   * {@link listScorers}. (Live E2E 2026-07-16 #1.)
   */
  async listPlugins(): Promise<Plugin[]> {
    const res = await this.request<{ plugins: Plugin[] } | Plugin[]>("/plugins", "GET");
    return Array.isArray(res) ? res : res.plugins;
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
    // FAIL CLOSED on an unreadable verdict. `blocked` is unconditionally a
    // boolean on every success path of POST /firewall/check
    // (apps/web/.../firewall/check/route.ts ends in `apiSuccess({ blocked, … })`),
    // so a 2xx without it did not come from the firewall. Returning it would
    // resolve `result.blocked` to `undefined` and every documented caller
    // (`if (result.blocked) refuse()`) reads that as ALLOW.
    return requireVerdict<FirewallResult>(
      await this.request("/firewall/check", "POST", body),
      "POST /firewall/check",
      [{ path: ["blocked"], kind: "boolean" }],
    );
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
    // FAIL CLOSED on an unreadable verdict — the exact defect shipped in
    // `evalguardai` 2.1.5 (`_translate` defaulted an absent `action` to
    // "allow"). POST /guardrails returns core `checkFirewall()`'s
    // `{ action, reasons, latencyMs }` where action is
    // "allow" | "block" | "flag" (packages/core/src/security/firewall.ts:35);
    // "redact" is accepted because this SDK's published `GuardrailsCheckResult`
    // type has always declared it. An action outside that set is one this
    // client cannot interpret, so it is refused rather than read as not-block.
    return requireVerdict<GuardrailsCheckResult>(
      await this.request("/guardrails", "POST", {
        text: params.text,
        ...(params.projectId ? { projectId: params.projectId } : {}),
      }),
      "POST /guardrails",
      [{ path: ["action"], kind: "enum", values: GUARDRAIL_ACTIONS }],
    );
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
    // FAIL CLOSED: `decision` is the ONLY field that says whether the
    // RBAC → CIMD → agent-authz → firewall → rate-limit → quarantine cascade
    // ran and let this tool call through. It was read straight off the body
    // while eleven sibling verdict routes on this client were hardened, so a
    // 2xx that carries no decision (proxy-rewritten 502, `{success:true,
    // data:null}`, a 200 apiError envelope, a differently-versioned server)
    // resolved with `decision: undefined` and handed the caller a `response`
    // no gateway ever authorised.
    return requireVerdict<McpInvokeResult>(
      await this.request("/mcp/invoke", "POST", body, extraHeaders),
      "POST /mcp/invoke",
      [{ path: ["decision"], kind: "enum", values: MCP_INVOKE_DECISIONS }],
    );
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
    // Route reads `assessmentId` (see api/v1/security/report/route.ts GET).
    return this.request(`/security/report?assessmentId=${encodeURIComponent(scanId)}`, "GET");
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

  /**
   * Create a prompt version. Backward-compatible: an opaque `content` string
   * plus optional `model`/`tags` still works exactly as before. To register a
   * fully **typed** prompt artifact, additionally pass:
   *   - `config`: the typed {@link PromptConfig} (model + decoding + tools),
   *   - `template`: a completion string or role-tagged {@link PromptTemplate},
   *   - `templateLanguage`: `"default"` | `"jinja"`.
   *
   * When `config` is supplied it is validated client-side via
   * `validatePromptConfig` before any network call, so a malformed config
   * throws a typed {@link EvalGuardError} (`code: "INVALID_PROMPT_CONFIG"`)
   * instead of a late server 400.
   */
  async createPrompt(params: {
    projectId: string;
    name: string;
    content: string;
    model?: string;
    tags?: string[];
    config?: PromptConfig;
    template?: PromptTemplate;
    templateLanguage?: TemplateLanguage;
  }): Promise<unknown> {
    if (params.config !== undefined) {
      const { valid, errors } = validatePromptConfig(params.config);
      if (!valid) {
        throw new EvalGuardError(`Invalid prompt config: ${errors.join("; ")}`, {
          code: "INVALID_PROMPT_CONFIG",
        });
      }
    }
    return this.request("/prompts", "POST", params);
  }

  async listPrompts(projectId: string): Promise<unknown> {
    return this.request(`/prompts?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  // ── Environments (Phase 2) ────────────────────────────────────────
  //
  // Arbitrary NAMED deployment environments replace the old hardcoded
  // staging/production pair. `staging` + `production` are seeded server-side
  // so existing deploy calls keep working. Each environment carries an
  // { id, name, tag } shape.

  /**
   * List every named environment in the workspace. Each entry carries its
   * `tag` (`default` marks the fallback environment).
   */
  async listEnvironments(projectId: string): Promise<unknown> {
    return this.request(`/environments?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  /**
   * Create a named environment. `tag` defaults to `"other"`; at most one
   * environment may carry `"default"` (the fallback used when a call names no
   * environment).
   */
  async createEnvironment(params: {
    projectId: string;
    name: string;
    tag?: EnvironmentTag;
  }): Promise<unknown> {
    if (!params.name || !params.name.trim()) {
      throw new EvalGuardError("Environment name is required", {
        code: "INVALID_ENVIRONMENT",
      });
    }
    return this.request("/environments", "POST", params);
  }

  /** Remove a named environment. Deployments targeting it should be removed first. */
  async removeEnvironment(projectId: string, name: string): Promise<unknown> {
    // Flat route: DELETE /environments?name= (the org is resolved from auth).
    return this.request(`/environments?name=${encodeURIComponent(name)}`, "DELETE");
  }

  // ── Prompt deployment to named environments (Phase 2) ─────────────
  //
  // Set / remove / list the deployed prompt version per named
  // environment. `environment` is any registered environment name.

  /**
   * Set the deployed prompt version for the specified environment. This is the
   * version used for calls made in that environment. Argument order is
   * (`name`, `environment`, `version`).
   */
  async setPromptDeployment(params: {
    projectId: string;
    name: string;
    environment: string;
    version: number;
  }): Promise<unknown> {
    // Flat route: POST /prompts/deployments — body { name, version, env }.
    return this.request("/prompts/deployments", "POST", {
      name: params.name,
      version: params.version,
      env: params.environment,
    });
  }

  /**
   * @deprecated Unsupported. The prompt deployments API exposes no DELETE
   * route — there is no way to un-deploy a prompt version from an environment.
   * Deploy a different version with {@link setPromptDeployment}, or roll back
   * via the deployments `PUT` action (`action: "rollback"`).
   */
  async removePromptDeployment(_params: {
    projectId: string;
    name: string;
    environment: string;
  }): Promise<unknown> {
    throw new EvalGuardError(
      "removePromptDeployment is not supported: the prompt deployments API has no DELETE route. " +
        "Deploy a different version with setPromptDeployment, or roll back via the deployments PUT action.",
      { code: "UNSUPPORTED_OPERATION" },
    );
  }

  /** List all environments and the prompt version deployed to each. */
  async listPromptEnvironments(projectId: string, name: string): Promise<unknown> {
    // Flat route: GET /prompts/deployments?name= (returns current + history).
    return this.request(`/prompts/deployments?name=${encodeURIComponent(name)}`, "GET");
  }

  // ── Tools (Phase 2) ───────────────────────────────────────────────
  //
  // Managed, versioned Tools deployed to named environments. A Tool
  // version's identity is a `ToolConfig` (function spec REUSED from the
  // prompt config, source code, setup schema). The config is validated
  // client-side via `validateToolConfig` before any network call, exactly
  // as `createPrompt` validates a `PromptConfig`.

  /**
   * Create (or upsert a new version of) a managed Tool. `config` is validated
   * client-side; a malformed config throws a typed {@link EvalGuardError}
   * (`code: "INVALID_TOOL_CONFIG"`) instead of a late server 400.
   */
  async createTool(params: {
    projectId: string;
    name: string;
    config: ToolConfig;
  }): Promise<unknown> {
    const { valid, errors } = validateToolConfig(params.config);
    if (!valid) {
      throw new EvalGuardError(`Invalid tool config: ${errors.join("; ")}`, {
        code: "INVALID_TOOL_CONFIG",
      });
    }
    return this.request("/tools", "POST", params);
  }

  /** Get a Tool (latest version, or a specific `version` when supplied). */
  async getTool(projectId: string, name: string, version?: number): Promise<unknown> {
    // Flat route: GET /tools?name=&version= (a specific version returns one record).
    const q =
      `?name=${encodeURIComponent(name)}` +
      (version !== undefined ? `&version=${version}` : "");
    return this.request(`/tools${q}`, "GET");
  }

  /** List all managed Tools in the workspace. */
  async listTools(projectId: string): Promise<unknown> {
    return this.request(`/tools?projectId=${encodeURIComponent(projectId)}`, "GET");
  }

  /** List every version of a Tool, ascending by version number. */
  async listToolVersions(projectId: string, name: string): Promise<unknown> {
    // Flat route: GET /tools?name= returns all versions of that tool.
    return this.request(`/tools?name=${encodeURIComponent(name)}`, "GET");
  }

  /**
   * Set the deployed Tool version for the specified environment — the version
   * used for calls made in that environment.
   */
  async setToolDeployment(params: {
    projectId: string;
    name: string;
    environment: string;
    version: number;
  }): Promise<unknown> {
    // Flat route: POST /tools/deployments — body { toolName, version, env }.
    return this.request("/tools/deployments", "POST", {
      toolName: params.name,
      version: params.version,
      env: params.environment,
    });
  }

  /**
   * Remove the deployed Tool version from the specified environment. The
   * environment itself remains registered.
   */
  async removeToolDeployment(params: {
    projectId: string;
    name: string;
    environment: string;
  }): Promise<unknown> {
    // Flat route: DELETE /tools/deployments?name=&env=.
    const q =
      `?name=${encodeURIComponent(params.name)}` +
      `&env=${encodeURIComponent(params.environment)}`;
    return this.request(`/tools/deployments${q}`, "DELETE");
  }

  /** List all environments and the Tool version deployed to each. */
  async listToolEnvironments(projectId: string, name: string): Promise<unknown> {
    // Flat route: GET /tools/deployments?name= (returns environments + history).
    return this.request(`/tools/deployments?name=${encodeURIComponent(name)}`, "GET");
  }

  // ── Tool environment variables (Phase 2) ──────────────────────────
  // Get / add / delete a Tool's environment variables.

  /** List a Tool's environment variables. */
  async getToolEnvironmentVariables(projectId: string, name: string): Promise<unknown> {
    // Flat route: GET /tools/env-vars?name=.
    return this.request(`/tools/env-vars?name=${encodeURIComponent(name)}`, "GET");
  }

  /** Add (or overwrite) an environment variable on a Tool. */
  async addToolEnvironmentVariable(params: {
    projectId: string;
    name: string;
    variable: ToolEnvironmentVariable;
  }): Promise<unknown> {
    if (!params.variable.name || !params.variable.name.trim()) {
      throw new EvalGuardError("Environment variable name is required", {
        code: "INVALID_TOOL_ENV_VAR",
      });
    }
    // Flat route: POST /tools/env-vars — body { name, variables: [{ name, value }] }.
    return this.request("/tools/env-vars", "POST", {
      name: params.name,
      variables: [params.variable],
    });
  }

  /** Delete an environment variable from a Tool by name. */
  async deleteToolEnvironmentVariable(
    projectId: string,
    name: string,
    variableName: string,
  ): Promise<unknown> {
    // Flat route: DELETE /tools/env-vars?name=&varName=.
    const q =
      `?name=${encodeURIComponent(name)}` +
      `&varName=${encodeURIComponent(variableName)}`;
    return this.request(`/tools/env-vars${q}`, "DELETE");
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
  // Content-hash registry: one row per (project, name, version), content-hash
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
  // recommends the score threshold that maximizes agreement. Supply `pairs`
  // (human/machine labels) and/or `scored`
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
    // Send an empty JSON object, not a bare no-body POST: request() always sets
    // `Content-Type: application/json`, and the route rejects an empty body with
    // 400 "Invalid JSON body" (audit 2026-07-15 #5). Mirrors snapshotDataset/
    // startDataScan, which already send `{}`.
    return this.request(`/privacy/dsr/${encodeURIComponent(id)}/search`, "POST", {});
  }
  async exportDSR(id: string): Promise<unknown> {
    // Empty JSON body (see searchDSR) — a no-body POST 400s "Invalid JSON body".
    return this.request(`/privacy/dsr/${encodeURIComponent(id)}/export`, "POST", {});
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
    // Empty JSON body (see searchDSR) — a no-body PATCH 400s "Invalid JSON body".
    return this.request(`/privacy/consent?id=${encodeURIComponent(id)}`, "PATCH", {});
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
  async createDataSource(params: { orgId?: string; projectId?: string; name: string; connector_type: "s3" | "snowflake" | "http" | string; config: Record<string, unknown>; classifier_mode?: "dlp_only" | "dlp_plus_llm" | "llm_only"; vault_entry_id?: string; }): Promise<unknown> {
    // The POST route REQUIRES orgId (it runs the admin-role membership gate off
    // body.orgId); omitting it 400s (audit 2026-07-15 #4). Resolve the key's
    // default org when the caller doesn't pass one.
    const orgId = params.orgId ?? (await this.resolveOrgId());
    return this.request("/data-discovery/sources", "POST", { ...params, orgId });
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
    // FAIL CLOSED: `verification.valid` IS the verdict — it is the server's
    // re-check of the Ed25519 signature over a tamper-evident compliance
    // record, and `verdict` is what the record attests. A 2xx that carries
    // neither (proxy-rewritten body, differently-versioned server) would let
    // `bom.verification?.valid` read as `undefined` while an auditor's UI
    // renders the (equally unverified) `bom` payload as a signed decision.
    return requireVerdict<DecisionBOMResponse>(
      await this.request(`/compliance/decision-bom/${encodeURIComponent(id)}`, "GET"),
      "GET /compliance/decision-bom/{id}",
      // Only `verification.valid` is asserted: the row's `verdict` is a
      // free-form string column (route: `verdict: row.verdict`), so an enum
      // over it would refuse legitimate records.
      [{ path: ["verification", "valid"], kind: "boolean" }],
    );
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

  /**
   * Update an agent tool (partial — pass only the fields to change).
   * PATCH /agent-tools/{id}.
   *
   * The PATCH route REPLACES the definition and re-runs `validateToolDefinition`
   * (which requires a full, valid `name` + `parameters` + type-specific config),
   * so sending a bare partial 400s (audit 2026-07-15). To make the "partial"
   * contract actually work, this fetches the current tool, shallow-merges the
   * caller's changes over it, and sends the FULL merged object. The server
   * preserves the stored secret when `rest.auth.value` isn't re-sent, so the
   * fetched tool (secret redacted) round-trips safely. Nested objects
   * (`rest`/`code`/`mcp`/`parameters`) are replaced wholesale when provided.
   */
  async updateAgentTool(
    id: string,
    params: { projectId: string; tool: Partial<AgentTool> },
  ): Promise<AgentTool> {
    if (!id) throw new Error("updateAgentTool: id is required");
    if (!params.projectId) throw new Error("updateAgentTool: projectId is required");
    if (!params.tool || typeof params.tool !== "object") {
      throw new Error("updateAgentTool: tool is required");
    }
    const current = await this.getAgentTool(id, params.projectId);
    const merged: AgentTool = { ...current, ...params.tool };
    return this.request(`/agent-tools/${encodeURIComponent(id)}`, "PATCH", {
      projectId: params.projectId,
      tool: merged,
    });
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
    // FAIL CLOSED — the audio sibling of detectDeepfake (whose `synthetic`
    // boolean IS validated). Here the verdict is the number the caller
    // thresholds: `if (r.probability > 0.8) reject()`. An absent probability
    // makes `undefined > 0.8` false, so an unreadable 2xx admits the voice as
    // genuine. A THRESHOLDED verdict fails open exactly like a boolean one.
    return requireVerdict<{ probability: number; model?: string; scores?: { label: string; score: number }[] }>(
      await this.request("/voice/deepfake-score", "POST", params),
      "POST /voice/deepfake-score",
      [{ path: ["probability"], kind: "number" }],
    );
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
    // FAIL CLOSED. The ROUTE fails closed (flagged) on a backend error, but
    // that guarantee only holds for bodies the route actually produced; a
    // rewritten 200 from a proxy has no `flagged` at all and `if (r.flagged)`
    // reads it as safe.
    return requireVerdict(
      await this.request("/moderation/image", "POST", params),
      "POST /moderation/image",
      [{ path: ["flagged"], kind: "boolean" }],
    );
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
    // FAIL CLOSED — see moderateImage. `framesEvaluated` is required too: a
    // clip verdict computed over zero frames is not a clean clip.
    return requireVerdict(
      await this.request("/moderation/video", "POST", params),
      "POST /moderation/video",
      [
        { path: ["flagged"], kind: "boolean" },
        { path: ["framesEvaluated"], kind: "number" },
      ],
    );
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
    // FAIL CLOSED. The route's documented "fails CLOSED (synthetic) on detector
    // error" contract is a SERVER guarantee; it says nothing about a body the
    // server never wrote. `if (r.synthetic)` on an absent field reads authentic.
    return requireVerdict<{
      kind: "image" | "video";
      synthetic: boolean;
      probability: number;
      label?: string;
      [k: string]: unknown;
    }>(
      await this.request("/moderation/deepfake", "POST", params),
      "POST /moderation/deepfake",
      [{ path: ["synthetic"], kind: "boolean" }],
    );
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
    // FAIL CLOSED: this verdict gates a pre-deploy approval. An absent
    // `verdict` makes `verdict === "block"` false — the server is approved on a
    // body that never carried an approval. `findings` is required too so an
    // empty audit cannot be read as a clean one.
    return requireVerdict<{
      server: { id: string; name?: string; url?: string };
      toolCount: number;
      findings: Array<{ severity: string; category: string; target: string; title: string; detail: string; remediation: string }>;
      summary: { critical: number; high: number; medium: number; low: number; total: number };
      riskScore: number;
      verdict: "block" | "review" | "pass";
      attestation: { signedOff: boolean; signedBy?: string; signedAt?: string; note?: string };
    }>(
      await this.request("/security/mcp-predeployment-audit", "POST", { ...params, tools: params.tools ?? [] }),
      "POST /security/mcp-predeployment-audit",
      [
        { path: ["verdict"], kind: "enum", values: ["block", "review", "pass"] },
        { path: ["findings"], kind: "array" },
      ],
    );
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
    // FAIL CLOSED: `verdict` is what a CI gate branches on. Absent → not
    // "breached" → the pipeline reports the agent safe against attacks that
    // were never run.
    return requireVerdict<{
      totalAttacks: number;
      dangerousAttempts: number;
      breaches: number;
      verdict: "breached" | "attempted" | "safe";
      attacks: Array<{ prompt: string; response: string; attemptedDangerous: boolean; breached: boolean; toolCalls: unknown[] }>;
      tools: string[];
    }>(
      await this.request("/security/agent-exec-redteam", "POST", {
        projectId: params.projectId,
        target_provider: params.targetProvider,
        target_model: params.targetModel,
        system_prompt: params.systemPrompt,
        attack_prompts: params.attackPrompts,
        tools: params.tools,
      }),
      "POST /security/agent-exec-redteam",
      [
        { path: ["verdict"], kind: "enum", values: ["breached", "attempted", "safe"] },
        { path: ["totalAttacks"], kind: "number" },
      ],
    );
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
    // FAIL CLOSED: `decision.allow` is the allow/deny for a boundary crossing.
    // Absent → `decision?.allow` is `undefined` → falsy → the caller lets
    // restricted content cross.
    return requireVerdict<{
      policyId: string;
      policyName: string;
      decision: DataBoundaryEvalDecision;
    }>(
      await this.request("/data-boundary/evaluate", "POST", params),
      "POST /data-boundary/evaluate",
      [{ path: ["decision", "allow"], kind: "boolean" }],
    );
  }

  // ── Agent memory-governance policy (Wave 3) ────────────────────────
  // Admin-managed policy governing durable agent-memory writes for an org (or a
  // project scope): mode off/monitor/enforce + config knobs (poisoning-screen
  // confidence threshold, HITL-on-rewrite, provenance-required). CRUD over
  // /agent-memory/governance. Admin role required (same gate as the route).

  /** Read the org's memory-governance policy (null when none set). Pass
   *  `projectId` to read a project-scoped policy instead of the org-wide one.
   *  GET /agent-memory/governance?orgId=[&projectId=]. */
  async getMemoryGovernancePolicy(params: {
    orgId: string;
    projectId?: string | null;
  }): Promise<{ policy: MemoryGovernancePolicyRecord | null }> {
    if (!params.orgId) throw new Error("getMemoryGovernancePolicy: orgId is required");
    const q = new URLSearchParams({ orgId: params.orgId });
    if (params.projectId) q.set("projectId", params.projectId);
    return this.request(`/agent-memory/governance?${q.toString()}`, "GET");
  }

  /** Create or update the org(+project) memory-governance policy. Admin only.
   *  PUT /agent-memory/governance. */
  async setMemoryGovernancePolicy(params: {
    orgId: string;
    projectId?: string | null;
    enabled?: boolean;
    mode?: MemoryGovernanceMode;
    config?: Partial<MemoryGovernanceConfig>;
  }): Promise<{ policy: MemoryGovernancePolicyRecord }> {
    if (!params.orgId) throw new Error("setMemoryGovernancePolicy: orgId is required");
    return this.request("/agent-memory/governance", "PUT", params);
  }

  /** Delete the org(+project) memory-governance policy (reverts to no
   *  governance). Admin only. DELETE /agent-memory/governance?orgId=[&projectId=]. */
  async deleteMemoryGovernancePolicy(params: {
    orgId: string;
    projectId?: string | null;
  }): Promise<{ deleted: boolean }> {
    if (!params.orgId) throw new Error("deleteMemoryGovernancePolicy: orgId is required");
    const q = new URLSearchParams({ orgId: params.orgId });
    if (params.projectId) q.set("projectId", params.projectId);
    return this.request(`/agent-memory/governance?${q.toString()}`, "DELETE");
  }

  // ── Gateway guardrail config (Wave 2) ──────────────────────────────
  // Per-project, opt-in inline guardrails the gateway proxy wires into the hot
  // path: partner-vendor adapters (aporia / lakera / …, each keyed by a stored
  // provider_keys secretRef) and the dependency-free local presets
  // (local-firewall / moderated-firewall + the Wave-2 agent guardrails
  // data-not-instructions / tool-call-circuit-breaker, which carry NO secretRef).
  // CRUD over /gateway/guardrails. Admin role required (same gate as the route).

  /** List a project's guardrail-config rows (ordered by priority). Returns the
   *  rows normalized to the camelCase {@link GuardrailConfigRecord} shape (the
   *  route projects raw snake_case DB columns). GET
   *  /gateway/guardrails?projectId=…. */
  async listGuardrailConfigs(projectId: string): Promise<GuardrailConfigRecord[]> {
    if (!projectId) throw new Error("listGuardrailConfigs: projectId is required");
    const rows = await this.request<GuardrailConfigWireRow[]>(
      `/gateway/guardrails?projectId=${encodeURIComponent(projectId)}`,
      "GET",
    );
    return (rows ?? []).map(mapGuardrailConfigRow);
  }

  /** Create or update a project's guardrail-config row (idempotent on
   *  (projectId, vendor)). Admin only. POST /gateway/guardrails.
   *
   *  Models the local-vs-vendor secretRef rule client-side so a bad config fails
   *  fast instead of round-tripping to a 400: a {@link LocalGuardrailVendor}
   *  (incl. the Wave-2 `data-not-instructions` / `tool-call-circuit-breaker`)
   *  makes no external call and MUST NOT carry a `secretRef`, while every other
   *  vendor REQUIRES one. */
  async upsertGuardrailConfig(params: UpsertGuardrailConfigParams): Promise<GuardrailConfigRecord> {
    if (!params.orgId) throw new Error("upsertGuardrailConfig: orgId is required");
    if (!params.projectId) throw new Error("upsertGuardrailConfig: projectId is required");
    if (!params.vendor) throw new Error("upsertGuardrailConfig: vendor is required");

    const local = isLocalGuardrailVendor(params.vendor);
    const hasSecretRef = params.secretRef != null;
    if (local && hasSecretRef) {
      throw new Error(
        `upsertGuardrailConfig: local guardrail '${params.vendor}' makes no external call and must not carry a secretRef`,
      );
    }
    if (!local && !hasSecretRef) {
      throw new Error(
        `upsertGuardrailConfig: vendor guardrail '${params.vendor}' requires a secretRef pointing at a stored provider key`,
      );
    }
    if (params.vendorChain && params.vendorChain.length > 0 && params.vendorChain[0] !== params.vendor) {
      throw new Error(
        `upsertGuardrailConfig: vendorChain[0] ('${params.vendorChain[0]}') must equal vendor ('${params.vendor}') — the primary`,
      );
    }

    // Never send a secretRef for a local preset even if the caller passed null —
    // the route rejects the key being present at all for locals.
    const body: Record<string, unknown> = {
      orgId: params.orgId,
      projectId: params.projectId,
      vendor: params.vendor,
    };
    if (params.config !== undefined) body.config = params.config;
    if (params.vendorChain !== undefined) body.vendorChain = params.vendorChain;
    if (params.fallbackOnErrors !== undefined) body.fallbackOnErrors = params.fallbackOnErrors;
    if (!local && hasSecretRef) body.secretRef = params.secretRef;
    if (params.onFlag !== undefined) body.onFlag = params.onFlag;
    if (params.checkRequest !== undefined) body.checkRequest = params.checkRequest;
    if (params.checkResponse !== undefined) body.checkResponse = params.checkResponse;
    if (params.tokenizePii !== undefined) body.tokenizePii = params.tokenizePii;
    if (params.enabled !== undefined) body.enabled = params.enabled;
    if (params.priority !== undefined) body.priority = params.priority;

    const row = await this.request<GuardrailConfigWireRow>("/gateway/guardrails", "POST", body);
    return mapGuardrailConfigRow(row);
  }

  /** Delete a project's guardrail-config row by id. Admin only. DELETE
   *  /gateway/guardrails?projectId=…&id=…. */
  async deleteGuardrailConfig(params: {
    projectId: string;
    id: string;
  }): Promise<{ deleted: string }> {
    if (!params.projectId) throw new Error("deleteGuardrailConfig: projectId is required");
    if (!params.id) throw new Error("deleteGuardrailConfig: id is required");
    const q = new URLSearchParams({ projectId: params.projectId, id: params.id });
    return this.request(`/gateway/guardrails?${q.toString()}`, "DELETE");
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
    // FAIL CLOSED — same reasoning as scanSecrets: an absent `findings` array
    // reads as "no misconfigurations" at every call site.
    return requireVerdict<{
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
    }>(
      await this.request("/security/iac-scan", "POST", { files: params.files }),
      "POST /security/iac-scan",
      [
        { path: ["findings"], kind: "array" },
        { path: ["scannedFiles"], kind: "number" },
      ],
    );
  }

  // ── Online evaluations (production sampling) ───────────────────────

  /**
   * Read the online-eval summary for a project: configured samplers, the most
   * recent scored results over a window, and per-scorer aggregates (pass rate,
   * error rate, p95 duration). GET /online-evals?projectId=
   */
  async listOnlineEvals(
    projectId: string,
    opts?: { since?: string; resultsLimit?: number },
  ): Promise<OnlineEvalsSummary> {
    if (!projectId) throw new Error("projectId is required");
    const q = new URLSearchParams({ projectId });
    if (opts?.since) q.set("since", opts.since);
    if (typeof opts?.resultsLimit === "number") q.set("resultsLimit", String(opts.resultsLimit));
    return this.request(`/online-evals?${q.toString()}`, "GET");
  }

  /**
   * List every online-eval sampler across the projects in an org. Owner/admin.
   * GET /online-eval-samplers?orgId=
   */
  async listOnlineEvalSamplers(
    orgId: string,
  ): Promise<{ samplers: OnlineEvalSampler[]; count: number }> {
    if (!orgId) throw new Error("orgId is required");
    return this.request(`/online-eval-samplers?orgId=${encodeURIComponent(orgId)}`, "GET");
  }

  /**
   * Fetch a single online-eval sampler by id. GET /online-eval-samplers/:id
   */
  async getOnlineEvalSampler(id: string): Promise<{ sampler: OnlineEvalSampler }> {
    if (!id) throw new Error("id is required");
    return this.request(`/online-eval-samplers/${encodeURIComponent(id)}`, "GET");
  }

  /**
   * Create an online-eval sampler that scores a sampled % of live traffic for a
   * project. Owner/admin only. POST /online-eval-samplers
   */
  async createOnlineEvalSampler(
    input: CreateOnlineEvalSamplerInput,
  ): Promise<{ ok: boolean; id: string; name: string }> {
    if (!input?.projectId) throw new Error("projectId is required");
    if (!input?.name) throw new Error("name is required");
    return this.request("/online-eval-samplers", "POST", input);
  }

  /**
   * Update fields of an online-eval sampler (enable/disable, rate, scorers, …).
   * Owner/admin only. PATCH /online-eval-samplers/:id
   */
  async updateOnlineEvalSampler(
    id: string,
    input: UpdateOnlineEvalSamplerInput,
  ): Promise<{ ok: boolean; id: string; fields: string[] }> {
    if (!id) throw new Error("id is required");
    if (!input || Object.keys(input).length === 0) {
      throw new Error("at least one field to update is required");
    }
    return this.request(`/online-eval-samplers/${encodeURIComponent(id)}`, "PATCH", input);
  }

  /**
   * Delete an online-eval sampler. Owner/admin only.
   * DELETE /online-eval-samplers/:id
   */
  async deleteOnlineEvalSampler(id: string): Promise<{ ok: boolean; id: string }> {
    if (!id) throw new Error("id is required");
    return this.request(`/online-eval-samplers/${encodeURIComponent(id)}`, "DELETE");
  }

  // ── Prompt optimizer ───────────────────────────────────────────────

  /**
   * Automatically optimize a prompt against eval cases + scorers using the
   * chosen strategy (meta-prompt, few-shot, genetic, bootstrap). Returns the
   * best prompt found plus before/after scores, changelog, and cost. Editor+.
   * The call is bounded by costCeilingUsd (server rejects with 402 if exceeded).
   * POST /prompts/optimize
   */
  async optimizePrompt(input: OptimizePromptInput): Promise<OptimizePromptResult> {
    if (!input?.projectId) throw new Error("projectId is required");
    if (!input?.prompt || input.prompt.trim().length === 0) throw new Error("prompt is required");
    if (!input?.strategy) throw new Error("strategy is required");
    if (!input?.evalCases || input.evalCases.length === 0) throw new Error("at least one evalCase is required");
    if (!input?.scorers || input.scorers.length === 0) throw new Error("at least one scorer is required");
    return this.request("/prompts/optimize", "POST", input);
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

    // Whether a FAILED attempt may be replayed. See IDEMPOTENT_WRITE_ROUTES:
    // most write routes do not honour the Idempotency-Key we send, so retrying
    // them after a 502/network drop mints duplicate resources.
    const retriable = isRetriableRequest(method, path);

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);
      try {
        const res = await followSameHostRedirects(
          `${this.baseUrl}${path}`,
          {
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
          },
          // A REDIRECT TO ANOTHER HOST IS NOT AN ANSWER (2026-08-10, revised
          // 2026-08-12). WHATWG/undici default to `redirect: "follow"` (20
          // hops), and on 301/302/303 the platform rewrites the request to a GET
          // and DROPS the body — so `checkFirewall(text)` became a bodyless GET
          // at whatever host the response named, and that host's
          // `{"blocked":false}` was returned as a verdict on text it never
          // received.
          //
          // SEC-051 first shipped `redirect: "error"` here. That also refuses
          // the redirects PRODUCTION ITSELF emits on this route — a
          // trailing-slash 308 and an http->https 301 — so a customer whose
          // EVALGUARD_BASE_URL carries either shape got a hard-failing SDK on a
          // patch upgrade. `followSameHostRedirects` follows a hop only while
          // the HOST is unchanged and never downgrades https->http; anything
          // else throws and lands on the catch below, failing CLOSED exactly as
          // `"error"` did.
          //
          // Never bare `"manual"`: an un-followed 3xx is a normal Response whose
          // status a later `res.ok` branch can misread. The hop loop is the
          // whole control.
          { label: `${method} ${path}` },
        );

        if (res.status === 429) {
          // Bounded + jittered: a hostile or mis-set Retry-After can no longer
          // park the caller's request handler for hours. See computeRetryDelayMs.
          const delay = computeRetryDelayMs(res.headers.get('retry-after'), attempt);
          if (attempt < maxRetries) {
            await new Promise(r => setTimeout(r, delay));
            continue;
          }
        }

        // 5xx: replay only when replaying is SAFE. A 502 can mean the write
        // committed and the response was lost, so a non-idempotent POST must
        // surface the error rather than mint a second resource.
        if (res.status >= 500 && retriable && attempt < maxRetries) {
          // Jittered so N clients recovering from the same 5xx do not
          // re-stampede the origin in lockstep.
          await new Promise(r => setTimeout(r, computeRetryDelayMs(null, attempt)));
          continue;
        }

        if (res.status >= 400 && res.status !== 429 && res.status < 500) {
          const errBody = (await res.json().catch(() => null)) as ErrorEnvelope | null;
          const apiErr = errBody?.error;
          throw new EvalGuardError(
            `EvalGuard API error ${res.status}: ${apiErr?.message ?? errBody?.message ?? (errBody === null ? (res.statusText || "Unknown error") : "Unknown error")}`,
            {
              code: apiErr?.code ?? `HTTP_${res.status}`,
              status: res.status,
              // Prefer the envelope's requestId; fall back to the X-Request-Id
              // header so 400/422/500 (whose bodies omit it) still correlate.
              requestId: extractRequestId(res, errBody),
            },
          );
        }

        if (!res.ok) {
          const errBody = (await res.json().catch(() => null)) as ErrorEnvelope | null;
          const apiErr = errBody?.error;
          throw new EvalGuardError(
            `EvalGuard API error ${res.status}: ${apiErr?.message ?? errBody?.message ?? (errBody === null ? (res.statusText || "Unknown error") : "Unknown error")}`,
            {
              code: apiErr?.code ?? `HTTP_${res.status}`,
              status: res.status,
              requestId: extractRequestId(res, errBody),
            },
          );
        }

        // Unwrap the standard { success, data } API envelope so typed methods
        // resolve to T (the payload), not the envelope (audit TS-SDK-ENVELOPE).
        //
        // OWN-property membership (audit js-requireverdict-own-properties): the
        // old `"data" in json` followed the prototype chain, so
        // `Object.prototype.data = { decision: "allow" }` made THIS LINE return
        // a fabricated payload on an empty 200 — and its fields are genuine own
        // properties, so hardening requireVerdict alone would not have caught
        // it. See unwrapApiEnvelope.
        const json = (await res.json()) as unknown;
        return unwrapApiEnvelope(json) as T;
      } catch (err) {
        lastError = err as Error;
        // HTTP errors are already typed + non-retryable; let them through
        // unchanged (the retry decision below is for transient network blips).
        if (err instanceof EvalGuardError) {
          throw err;
        }
        // Same rule as the 5xx branch above: a dropped connection or a
        // client-side timeout does NOT prove the server never applied the
        // write, so only replay requests that are safe to replay.
        if (retriable && attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * Math.pow(2, attempt)));
          continue;
        }
        // Retries exhausted (or the request was not safe to replay) on a
        // network/transport failure (the raw `TypeError: fetch failed` for
        // no-server/DNS/connection-refused, or an AbortError on timeout).
        // Surface it as a typed, catchable error instead of letting the raw
        // TypeError escape (audit: sdk-untyped-network-error).
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
    // Same replay-safety rule as request(). Every current caller is a GET
    // export, so this is a guard against a future non-idempotent caller.
    const retriable = isRetriableRequest(method, path);

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);
      try {
        const res = await followSameHostRedirects(
          `${this.baseUrl}${path}`,
          {
            method,
            headers: {
              Authorization: `Bearer ${this.apiKey}`,
              "x-evalguard-client-version": SDK_VERSION,
              ...this.subjectHeaders(),
            },
            signal: controller.signal,
          },
          // See request(). Same rule on the text/NDJSON/CSV export path: an
          // export substituted wholesale by whoever can answer with a
          // cross-host `Location` is not this org's data, while a same-host
          // normalising hop is the origin doing its job.
          { label: `${method} ${path}` },
        );

        if (res.status === 429) {
          // Bounded + jittered: a hostile or mis-set Retry-After can no longer
          // park the caller's request handler for hours. See computeRetryDelayMs.
          const delay = computeRetryDelayMs(res.headers.get('retry-after'), attempt);
          if (attempt < maxRetries) {
            await new Promise(r => setTimeout(r, delay));
            continue;
          }
        }

        if (res.status >= 500 && retriable && attempt < maxRetries) {
          // Jittered so N clients recovering from the same 5xx do not
          // re-stampede the origin in lockstep.
          await new Promise(r => setTimeout(r, computeRetryDelayMs(null, attempt)));
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
          let parsedBody: ErrorEnvelope | null = null;
          let apiErr: { code?: string; message?: string; requestId?: string } | undefined;
          let envelopeMessage: string | undefined;
          try {
            parsedBody = JSON.parse(rawText) as ErrorEnvelope | null;
            apiErr = parsedBody?.error;
            envelopeMessage = apiErr?.message ?? parsedBody?.message;
          } catch {
            // Non-JSON error body (e.g. a plain-text upstream/proxy error) → keep
            // the raw text in the message and fall back to HTTP_<status>.
          }
          throw new EvalGuardError(
            `EvalGuard API error ${res.status}: ${envelopeMessage ?? rawText}`,
            {
              code: apiErr?.code ?? `HTTP_${res.status}`,
              status: res.status,
              // Envelope requestId first, then the X-Request-Id header — so even
              // a non-JSON error body still yields the correlation id.
              requestId: extractRequestId(res, parsedBody),
            },
          );
        }

        return res.text();
      } catch (err) {
        lastError = err as Error;
        if (err instanceof EvalGuardError) {
          throw err;
        }
        if (retriable && attempt < maxRetries) {
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
