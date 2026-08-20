/**
 * EvalGuard TypeScript SDK -- traceable() wrapper and traced() helper.
 *
 * Zero-config function tracing that automatically captures function name, args,
 * return values, duration, and errors, then sends trace spans to the EvalGuard API.
 *
 * @example
 * ```ts
 * import { traceable, traced } from "@evalguard/sdk";
 *
 * const myLLMCall = traceable(async (prompt: string) => {
 *   return await openai.chat(prompt);
 * }, { name: "my-llm-call" });
 *
 * // Inline tracing
 * const result = await traced("data-load", async (span) => {
 *   const data = await loadData();
 *   span.metadata.rows = data.length;
 *   return data;
 * });
 * ```
 *
 * Environment variables (Node.js) / manual configure():
 *   EVALGUARD_API_KEY        -- API key for authentication
 *   EVALGUARD_BASE_URL       -- API base URL (default: https://evalguard.ai/api)
 *   EVALGUARD_PROJECT_ID     -- Default project ID for traces
 *   EVALGUARD_TRACING_ENABLED -- Set to "false" to disable (default: "true")
 */

import { AsyncLocalStorage } from "node:async_hooks";
// Secret redaction for telemetry egress lives in the published zero-dep leaf
// `@evalguard/wrapper-core` so `@evalguard/otel-sdk` shares the SAME list
// instead of forking a third copy. See ./tracing.ts's "Secret redaction"
// section and packages/wrapper-core/src/secret-redaction.ts.
import {
  REDACTED,
  isSecretKey,
  looksSecretValue,
  redactEmbeddedSecrets,
  followSameHostRedirects,
} from "@evalguard/wrapper-core";
// Generated from package.json#version on `prebuild` (scripts/gen-version.mjs).
// The trace-ingest User-Agent below used to hard-code "evalguard-js/2.0.2",
// eleven releases behind the 3.1.2 this package actually publishes, so
// server-side telemetry could not tell which SDK build sent a span.
import { SDK_VERSION } from "./version";

// ── Types ──────────────────────────────────────────────────────────────

export interface TraceSpan {
  spanId: string;
  traceId: string;
  parentSpanId?: string;
  name: string;
  startTime: number;
  endTime: number;
  durationMs: number;
  status: "ok" | "error";
  inputs?: Record<string, unknown>;
  outputs?: unknown;
  error?: string;
  errorStack?: string;
  metadata: Record<string, unknown>;
}

/**
 * Distributed-tracing identity (observability-tracing-3). Opt-in IDs that are
 * attached to a span and INHERITED by every child span in the same async context,
 * emitted as the `session.id` / `user.id` / `conversation.id` span attributes.
 * Never auto-populated from PII — the caller supplies them explicitly.
 */
export interface TraceIdentity {
  sessionId?: string;
  userId?: string;
  conversationId?: string;
}

export interface TraceableOptions {
  /** Custom span name. Defaults to fn.name or "anonymous". */
  name?: string;
  /** Extra metadata attached to every invocation. */
  metadata?: Record<string, unknown>;
  /** Session id — attached to this span + inherited by child spans. */
  sessionId?: string;
  /** End-user id — attached to this span + inherited by child spans. */
  userId?: string;
  /** Conversation id — attached to this span + inherited by child spans. */
  conversationId?: string;
}

export interface TracingConfig {
  apiKey?: string;
  baseUrl?: string;
  projectId?: string;
  enabled?: boolean;
}

// ── Internal config ────────────────────────────────────────────────────

let _config: TracingConfig = {};

/**
 * Strip trailing slashes WITHOUT a regex. `/\/+$/` is a polynomial-backtracking
 * pattern (O(n²) on a string of many '/'), which CodeQL flags as ReDoS on
 * library-supplied input. This linear char-walk is equivalent and safe.
 */
function _stripTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* "/" */) end--;
  return s.slice(0, end);
}

function _getConfig(): Required<TracingConfig> {
  const env = typeof process !== "undefined" ? process.env : ({} as Record<string, string | undefined>);
  return {
    apiKey: _config.apiKey ?? env.EVALGUARD_API_KEY ?? "",
    // P2-12: align with the rest of the SDK/CLI/Python/Go (host evalguard.ai +
    // /api segment). This base has `/v1/traces/ingest` appended below, so it must
    // NOT include /v1 — yielding the canonical https://evalguard.ai/api/v1/traces/ingest.
    // The prior default (https://api.evalguard.ai) dropped /api and used a (known-dead-host: narrates the default this line replaced)
    // different host, silently dropping spans (the sender swallows all errors).
    baseUrl: _stripTrailingSlashes(_config.baseUrl ?? env.EVALGUARD_BASE_URL ?? "https://evalguard.ai/api"),
    projectId: _config.projectId ?? env.EVALGUARD_PROJECT_ID ?? "",
    enabled: _config.enabled ?? (env.EVALGUARD_TRACING_ENABLED?.toLowerCase() !== "false"),
  };
}

/**
 * Programmatic configuration (alternative to env vars).
 */
export function configureTracing(config: TracingConfig): void {
  _config = { ..._config, ...config };
}

// ── Context propagation via AsyncLocalStorage ──────────────────────────

interface SpanContext {
  span: SpanBuilder;
  traceId: string;
  /** Inherited trace identity (session/user/conversation) — see TraceIdentity. */
  identity?: TraceIdentity;
}

const _storage = new AsyncLocalStorage<SpanContext>();

/**
 * Resolve the effective identity for a new span: each field falls back from the
 * caller's explicit option to the parent context's inherited value. Returns
 * undefined when nothing is set (so we never store empty identity objects).
 */
function _resolveIdentity(
  parent: SpanContext | undefined,
  opts?: TraceIdentity,
): TraceIdentity | undefined {
  const inherited = parent?.identity;
  const sessionId = opts?.sessionId ?? inherited?.sessionId;
  const userId = opts?.userId ?? inherited?.userId;
  const conversationId = opts?.conversationId ?? inherited?.conversationId;
  if (sessionId === undefined && userId === undefined && conversationId === undefined) {
    return undefined;
  }
  return { sessionId, userId, conversationId };
}

/**
 * Emit identity as the canonical dotted span attributes. The dotted form is also
 * deliberately redaction-safe: the secret-key matcher catches `session_id` /
 * `sessionId` but NOT `session.id`.
 */
function _applyIdentityToMeta(meta: Record<string, unknown>, identity?: TraceIdentity): void {
  if (!identity) return;
  if (identity.sessionId !== undefined) meta["session.id"] = identity.sessionId;
  if (identity.userId !== undefined) meta["user.id"] = identity.userId;
  if (identity.conversationId !== undefined) meta["conversation.id"] = identity.conversationId;
}

// ── Span builder ───────────────────────────────────────────────────────

class SpanBuilder {
  readonly spanId: string;
  readonly traceId: string;
  readonly parentSpanId?: string;
  readonly name: string;
  readonly startTime: number;
  inputs: Record<string, unknown> = {};
  outputs: unknown = undefined;
  metadata: Record<string, unknown> = {};
  status: "ok" | "error" = "ok";
  error?: string;
  errorStack?: string;
  endTime: number = 0;
  durationMs: number = 0;

  constructor(name: string, parentSpanId?: string, traceId?: string) {
    this.spanId = _randomHex(16);
    this.traceId = traceId ?? _randomHex(32);
    this.parentSpanId = parentSpanId;
    this.name = name;
    this.startTime = Date.now() / 1000;
  }

  finish(output?: unknown, err?: Error): void {
    this.endTime = Date.now() / 1000;
    this.durationMs = (this.endTime - this.startTime) * 1000;

    if (err) {
      this.status = "error";
      this.error = `${err.name}: ${err.message}`;
      this.errorStack = err.stack;
    } else {
      this.status = "ok";
      if (output !== undefined) {
        this.outputs = output;
      }
    }
  }

  toDict(): TraceSpan {
    const d: TraceSpan = {
      spanId: this.spanId,
      traceId: this.traceId,
      name: this.name,
      startTime: this.startTime,
      endTime: this.endTime,
      durationMs: this.durationMs,
      status: this.status,
      metadata: _safeSerialize(this.metadata) as Record<string, unknown>,
    };
    if (this.parentSpanId) d.parentSpanId = this.parentSpanId;
    if (Object.keys(this.inputs).length > 0) d.inputs = _safeSerialize(this.inputs) as Record<string, unknown>;
    if (this.outputs !== undefined) d.outputs = _safeSerialize(this.outputs);
    // A386: these two used to be assigned RAW while everything beside them went
    // through _safeSerialize. An SDK user's `throw new Error(\`auth failed for
    // ${apiKey}\`)` — or any provider SDK that echoes the Authorization header
    // into its exception message — shipped the credential verbatim to a
    // persisted, dashboard-rendered store, on the DEFAULT traceable() path.
    //
    // _safeSerialize alone would NOT have fixed it: _looksSecretValue is
    // whole-string anchored by design (so ordinary prose is never masked), and
    // an error message is a SENTENCE CONTAINING a token, never the token
    // itself. Free text needs the scanning form.
    if (this.error) d.error = _redactEmbeddedSecrets(this.error);
    if (this.errorStack) d.errorStack = _redactEmbeddedSecrets(this.errorStack);
    return d;
  }
}

// ── Secret redaction ────────────────────────────────────────────────────
//
// The traceable() wrapper captures every function argument verbatim as
// arg0..N (and any metadata the caller attaches). LLM apps routinely pass an
// API key, bearer token, password, or Authorization header as an argument —
// sending those to the ingest endpoint in clear is a credential leak. We
// redact BEFORE the span leaves the process:
//   1. by KEY name — any object key matching a secret pattern → "[REDACTED]"
//   2. by VALUE shape — any string that looks like a known secret token
//      (eg_*, sk-*, Bearer …, OpenAI/Anthropic/AWS-style keys) → "[REDACTED]"
// Redaction is deep (objects + arrays) and runs inside _safeSerialize's
// recursion so it covers nested inputs/outputs/metadata.

// 2026-07-30: the pattern list, the un-anchoring derivation and both scanners
// USED TO LIVE HERE. `@evalguard/otel-sdk` needs exactly the same knowledge for
// its 55 `recordException()` egress points, and a second literal copy of a
// secret list is the failure mode this file's own comments already warn about
// ("a drifted secret list fails silently — you only learn about it from the
// leak"). They now live in `@evalguard/wrapper-core`, the repo's published
// zero-runtime-dependency leaf — see packages/wrapper-core/src/secret-redaction.ts
// for why that package and not a new one.
//
// Re-exported under the historical underscore names because they are part of
// this SDK's surface (`vitest.ts` and the A386 egress tests import them) and a
// rename would be a breaking change for no benefit. `secret-redaction-drift.test.ts`
// asserts FUNCTION IDENTITY against wrapper-core, so re-forking a local copy
// fails a test rather than silently shipping.
export const _redactEmbeddedSecrets = redactEmbeddedSecrets;
export const _isSecretKey = isSecretKey;

const _REDACTED = REDACTED;
const _looksSecretValue = looksSecretValue;

// ── Helpers ─────────────────────────────────────────────────────────────

function _randomHex(length: number): string {
  const bytes = new Uint8Array(length / 2);
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function _safeSerialize(
  obj: unknown,
  depth = 4,
  maxStrLen = 4096,
  keyHint?: string,
): unknown {
  if (depth <= 0) return "<truncated>";
  if (obj === null || obj === undefined) return obj;
  // Redact a whole value when its key name implies it's a secret, regardless
  // of the value's type/shape (e.g. password: 1234, token: { v: "…" }).
  if (keyHint && _isSecretKey(keyHint)) return _REDACTED;
  if (typeof obj === "boolean" || typeof obj === "number") return obj;
  if (typeof obj === "string") {
    if (_looksSecretValue(obj)) return _REDACTED;
    // A386: a whole-string match catches `{ apiKey: "sk-…" }` but not
    // `"retrying with sk-… after 401"`. Scan embedded tokens too — same list,
    // un-anchored — so a credential pasted into a prompt or echoed into an
    // output does not ship in clear either.
    const scanned = _redactEmbeddedSecrets(obj);
    return scanned.length > maxStrLen ? scanned.slice(0, maxStrLen) : scanned;
  }
  if (typeof obj === "bigint") return obj.toString();
  // Errors nested in inputs/outputs carry the same message text as the span's
  // own error field, so they need the same scan.
  if (obj instanceof Error)
    return { name: obj.name, message: _redactEmbeddedSecrets(obj.message) };
  if (Array.isArray(obj)) {
    const items = obj.slice(0, 100).map((v) => _safeSerialize(v, depth - 1, maxStrLen));
    if (obj.length > 100) items.push(`... +${obj.length - 100} more`);
    return items;
  }
  if (typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      // A386 repair: the KEY went onto the wire untested while the identical
      // string in value position was redacted. A record keyed by user data is
      // ordinary — a per-API-key cache, a `{ token: quota }` map, captured
      // `...args` — so the credential left the process in key position with the
      // value beside it masked. `keyHint` keeps the ORIGINAL key: the hint
      // decides whether the VALUE is a secret (`apiKey` → redact), and hinting
      // off a redacted key would break that.
      let safeKey = _looksSecretValue(k) ? _REDACTED : _redactEmbeddedSecrets(k);
      // Two distinct keys can redact to the same string. Suffix rather than
      // overwrite: dropping a value silently is how a redactor turns into data
      // loss nobody notices.
      if (safeKey in result) {
        let suffix = 2;
        while (`${safeKey}_${suffix}` in result) suffix++;
        safeKey = `${safeKey}_${suffix}`;
      }
      result[safeKey] = _safeSerialize(v, depth - 1, maxStrLen, k);
    }
    return result;
  }
  try {
    return String(obj);
  } catch {
    return `<${typeof obj}>`;
  }
}

// ── Background batch sender ────────────────────────────────────────────

class TraceBatcher {
  private queue: TraceSpan[] = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly flushIntervalMs = 2000;
  private readonly maxBatchSize = 50;

  enqueue(span: TraceSpan): void {
    const cfg = _getConfig();
    if (!cfg.enabled || !cfg.apiKey) return;

    this.queue.push(span);
    if (this.queue.length >= this.maxBatchSize) {
      this.flush();
    } else if (this.timer === null) {
      this.timer = setTimeout(() => this.flush(), this.flushIntervalMs);
      // Allow Node.js to exit even if timer is pending
      if (typeof this.timer === "object" && "unref" in this.timer) {
        (this.timer as NodeJS.Timeout).unref();
      }
    }
  }

  flush(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0);
    this._send(batch).catch(() => {
      // Silently drop on failure -- don't affect user code
    });
  }

  private async _send(batch: TraceSpan[]): Promise<void> {
    const cfg = _getConfig();
    const url = `${cfg.baseUrl}/v1/traces/ingest`;
    const body = JSON.stringify({
      projectId: cfg.projectId,
      spans: batch,
    });

    try {
      await followSameHostRedirects(
        url,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${cfg.apiKey}`,
            "Content-Type": "application/json",
            "User-Agent": `evalguard-js/${SDK_VERSION}-tracing`,
          },
          body,
          signal: AbortSignal.timeout(10_000),
        },
        // Telemetry, not a verdict — but the same rule, for one reason: this
        // POST carries the org's API key and the customer's span payloads, and
        // a CROSS-HOST redirect would hand both to whatever host answered with
        // a `Location`. Fire-and-forget already swallows the rejection.
        // (2026-08-10, revised 2026-08-12.)
        //
        // This config path is the one that most needs the same-host follow:
        // `_getConfig` strips trailing slashes but does NOT require https, so
        // `EVALGUARD_BASE_URL=http://evalguard.ai/api` is accepted here and
        // production answers it with a 301 to https on the SAME host. Under the
        // blanket refusal every span from such a deployment was dropped.
        { label: "POST /v1/traces/ingest" },
      );
    } catch {
      // Best-effort -- never throw into user code
    }
  }
}

const _batcher = new TraceBatcher();

// Register a shutdown flush for Node.js.
//
// `beforeExit` ONLY. A library must never install SIGINT/SIGTERM handlers that
// call process.exit(): Node runs signal listeners in registration order, and
// merely importing this module registered ours FIRST, so `process.exit(143)`
// fired before the host's own SIGTERM handler could drain connections — every
// in-flight request was killed on each rolling deploy, and Ctrl-C skipped the
// app's cleanup. `beforeExit` does not alter exit semantics; hosts that want a
// signal-time flush call the exported `flushTraces()` from their OWN handler.
if (typeof process !== "undefined" && typeof process.on === "function") {
  process.on("beforeExit", () => _batcher.flush());
}

// ── traceable() ────────────────────────────────────────────────────────

/**
 * Wraps an async or sync function with automatic tracing.
 *
 * @example
 * ```ts
 * const myCall = traceable(async (prompt: string) => {
 *   return await openai.chat(prompt);
 * });
 *
 * const namedCall = traceable(myFunction, { name: "custom-name" });
 * ```
 */
export function traceable<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options?: TraceableOptions,
): (...args: TArgs) => Promise<TReturn> {
  const spanName = options?.name ?? (fn.name || "anonymous");
  const extraMeta = options?.metadata ?? {};

  const wrapper = async (...args: TArgs): Promise<TReturn> => {
    const parent = _storage.getStore();
    const traceId = parent?.traceId;
    const parentSpanId = parent?.span.spanId;

    const span = new SpanBuilder(spanName, parentSpanId, traceId);
    span.metadata = { ...extraMeta };
    const identity = _resolveIdentity(parent, options);
    _applyIdentityToMeta(span.metadata, identity);

    // Capture inputs as named args if possible
    const inputs: Record<string, unknown> = {};
    args.forEach((arg, i) => inputs[`arg${i}`] = arg);
    span.inputs = inputs;

    return _storage.run({ span, traceId: span.traceId, identity }, async () => {
      try {
        const result = await fn(...args);
        span.finish(result);
        _batcher.enqueue(span.toDict());
        return result;
      } catch (err) {
        span.finish(undefined, err instanceof Error ? err : new Error(String(err)));
        _batcher.enqueue(span.toDict());
        throw err;
      }
    });
  };

  // Preserve function name for debugging
  Object.defineProperty(wrapper, "name", { value: spanName, configurable: true });
  return wrapper;
}

// ── traced() ───────────────────────────────────────────────────────────

/**
 * Inline tracing for a block of code.
 *
 * @example
 * ```ts
 * const data = await traced("load-data", async (span) => {
 *   const rows = await db.query("SELECT * FROM logs");
 *   span.metadata.count = rows.length;
 *   return rows;
 * });
 * ```
 */
export async function traced<T>(
  name: string,
  fn: (span: SpanBuilder) => T | Promise<T>,
  options?: { metadata?: Record<string, unknown> },
): Promise<T> {
  const parent = _storage.getStore();
  const traceId = parent?.traceId;
  const parentSpanId = parent?.span.spanId;

  const span = new SpanBuilder(name, parentSpanId, traceId);
  span.metadata = { ...(options?.metadata ?? {}) };
  // traced() doesn't take its own identity; it inherits the parent's so identity
  // set on an outer traceable() flows down to inline blocks too.
  const identity = _resolveIdentity(parent);
  _applyIdentityToMeta(span.metadata, identity);

  return _storage.run({ span, traceId: span.traceId, identity }, async () => {
    try {
      const result = await fn(span);
      span.finish(result);
      _batcher.enqueue(span.toDict());
      return result;
    } catch (err) {
      span.finish(undefined, err instanceof Error ? err : new Error(String(err)));
      _batcher.enqueue(span.toDict());
      throw err;
    }
  });
}

// ── Utilities ──────────────────────────────────────────────────────────

/**
 * Get the current active span, or undefined if not inside a traced context.
 */
export function getCurrentSpan(): SpanBuilder | undefined {
  return _storage.getStore()?.span;
}

/**
 * Get the current trace ID, or undefined.
 */
export function getCurrentTraceId(): string | undefined {
  return _storage.getStore()?.traceId;
}

/**
 * Get the trace identity (session/user/conversation ids) inherited by the current
 * span context, or undefined when none is set. (observability-tracing-3)
 */
export function getTraceIdentity(): TraceIdentity | undefined {
  return _storage.getStore()?.identity;
}

/**
 * Force-flush all pending spans. Useful in tests or before process exit.
 */
export function flushTraces(): void {
  _batcher.flush();
}
