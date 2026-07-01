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
    // The prior default (https://api.evalguard.ai) dropped /api and used a
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
    if (this.error) d.error = this.error;
    if (this.errorStack) d.errorStack = this.errorStack;
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

const _SECRET_KEY_RE = /(api[_-]?key|secret|token|password|passwd|authorization|auth[_-]?token|access[_-]?key|private[_-]?key|client[_-]?secret|bearer|credential|session[_-]?id|cookie)/i;

// Value-shape patterns for common secret tokens, anchored to avoid masking
// ordinary prose. Each must match the WHOLE string (after trim).
const _SECRET_VALUE_RES: RegExp[] = [
  /^eg_[A-Za-z0-9_-]{8,}$/, // EvalGuard API keys
  /^sk-[A-Za-z0-9_-]{16,}$/, // OpenAI-style secret keys
  /^sk-ant-[A-Za-z0-9_-]{16,}$/, // Anthropic keys
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/, // Slack tokens
  /^gh[posru]_[A-Za-z0-9]{20,}$/, // GitHub tokens
  /^AKIA[0-9A-Z]{16}$/, // AWS access key id
  /^ya29\.[A-Za-z0-9_-]{20,}$/, // Google OAuth tokens
  /^Bearer\s+[A-Za-z0-9._-]{12,}$/i, // Authorization: Bearer …
  /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/, // JWTs
];

const _REDACTED = "[REDACTED]";

function _looksSecretValue(s: string): boolean {
  const t = s.trim();
  if (t.length < 8) return false;
  return _SECRET_VALUE_RES.some((re) => re.test(t));
}

/** True when an object KEY name implies its value is a secret. */
export function _isSecretKey(key: string): boolean {
  return _SECRET_KEY_RE.test(key);
}

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
    return obj.length > maxStrLen ? obj.slice(0, maxStrLen) : obj;
  }
  if (typeof obj === "bigint") return obj.toString();
  if (obj instanceof Error) return { name: obj.name, message: obj.message };
  if (Array.isArray(obj)) {
    const items = obj.slice(0, 100).map((v) => _safeSerialize(v, depth - 1, maxStrLen));
    if (obj.length > 100) items.push(`... +${obj.length - 100} more`);
    return items;
  }
  if (typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = _safeSerialize(v, depth - 1, maxStrLen, k);
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
      await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${cfg.apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "evalguard-js/2.0.2-tracing",
        },
        body,
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      // Best-effort -- never throw into user code
    }
  }
}

const _batcher = new TraceBatcher();

// Register shutdown flush for Node.js
if (typeof process !== "undefined" && typeof process.on === "function") {
  const onExit = () => _batcher.flush();
  process.on("beforeExit", onExit);
  process.on("SIGINT", () => { onExit(); process.exit(130); });
  process.on("SIGTERM", () => { onExit(); process.exit(143); });
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
