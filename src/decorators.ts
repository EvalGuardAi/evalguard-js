/**
 * EvalGuard TypeScript SDK — tracing + security decorators
 * (Phase 3 / Observability & DX).
 *
 * This module is *sugar* over two existing primitives — it does NOT reinvent
 * span/OTel plumbing or the firewall engine:
 *
 *   • Span substrate  → `traceable()` from "./tracing" (AsyncLocalStorage span
 *     tree + background batcher). `flow` / `prompt` / `tool` are thin wrappers
 *     that stamp a standard file `type` onto the span and nest for free
 *     via the existing context propagation.
 *   • Firewall        → `guard` / `guardOutput` from "@evalguard/core"
 *     (on-device pattern engine). The `@guard` decorator runs the firewall on a
 *     call's string inputs (pre) and its string output (post), blocking or
 *     flagging per policy — the one-line way EvalGuard security drops into
 *     agent code.
 *
 * Each wrapper opens an OTel span, writes the file `type`, runs the function,
 * and records the output. Here `type` is emitted as the `eg.file.type` span
 * attribute (same key the core telemetry `traceable` uses) via span metadata.
 *
 * Each capability ships in two forms:
 *   1. A HOF (higher-order function) — `flow(fn, opts?)` — matching the existing
 *      `traceable` HOF. Fully typed, usable anywhere.
 *   2. A TC39 class-method decorator factory — `@withFlow(opts?)` — the
 *      one-line DX for methods (this-preserving).
 *
 * @example
 * ```ts
 * import { flow, tool, guard, withGuard } from "@evalguard/sdk";
 *
 * // HOF: wrap an agent call so the firewall gates input + output.
 * const safeAgent = guard(async (userMessage: string) => llm.chat(userMessage));
 *
 * // Nested spans: `tool` calls inside a `flow` nest under the flow span.
 * const search = tool(async (q: string) => db.search(q), { name: "search" });
 * const answer = flow(async (q: string) => `Found ${(await search(q)).length}`);
 *
 * // Decorator: one line on a class method.
 * class Assistant {
 *   @withGuard({ policy: "block" })
 *   async reply(message: string): Promise<string> { return llm.chat(message); }
 * }
 * ```
 */

import {
  guard as coreGuard,
  guardOutput as coreGuardOutput,
  type OnDeviceConfig,
  type OnDeviceResult,
  type OnDeviceViolation,
} from "@evalguard/core";

import { traceable, type TraceableOptions } from "./tracing";

// ── Span-type sugar (flow / prompt / tool) ──────────────────────────────

/**
 * Standard span file `type` recorded on the span: "prompt" | "flow" | "tool".
 * Emitted as the `eg.file.type` span attribute — the same key the core
 * telemetry `traceable` primitive uses.
 */
export type SpanFileType = "flow" | "prompt" | "tool";

/** Span attribute key for the standard file type. */
export const EG_FILE_TYPE_ATTR = "eg.file.type" as const;

/** Options for the `flow` / `prompt` / `tool` HOFs (superset of tracing opts). */
export type SpanDecoratorOptions = TraceableOptions;

function traceWithType<TArgs extends unknown[], TReturn>(
  type: SpanFileType,
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options?: SpanDecoratorOptions,
): (...args: TArgs) => Promise<TReturn> {
  const name = options?.name ?? `${type}:${fn.name || "anonymous"}`;
  return traceable(fn, {
    ...options,
    name,
    // Stamp the file type onto the span WITHOUT clobbering caller metadata.
    metadata: { [EG_FILE_TYPE_ATTR]: type, ...(options?.metadata ?? {}) },
  });
}

/**
 * Wrap a multi-step orchestration function as a `flow` span. Child
 * `prompt`/`tool`/`traceable` calls nest under it automatically (shared trace id
 * via the tracing substrate's AsyncLocalStorage context).
 */
export function flow<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options?: SpanDecoratorOptions,
): (...args: TArgs) => Promise<TReturn> {
  return traceWithType("flow", fn, options);
}

/** Wrap a model-calling function as a `prompt` span. */
export function prompt<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options?: SpanDecoratorOptions,
): (...args: TArgs) => Promise<TReturn> {
  return traceWithType("prompt", fn, options);
}

/** Wrap a tool/function-call as a `tool` span. */
export function tool<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options?: SpanDecoratorOptions,
): (...args: TArgs) => Promise<TReturn> {
  return traceWithType("tool", fn, options);
}

// ── @guard: firewall over inputs (pre) and outputs (post) ───────────────

/** How `@guard` reacts when the firewall does not allow a scanned value. */
export type GuardPolicy = "block" | "flag";

/** Which side of the call a firewall scan ran on. */
export type GuardPhase = "input" | "output";

/** A single firewall trip observed by a guarded call. */
export interface GuardViolationEvent {
  /** Whether the scan ran on the call input or its output. */
  phase: GuardPhase;
  /** The raw on-device firewall result for the offending value. */
  result: OnDeviceResult;
  /** True when policy caused the call to be blocked (throw). */
  blocked: boolean;
  /** The scanned string value that tripped the firewall (already length-capped). */
  value: string;
}

/** Options for the `guard` HOF / `@withGuard` decorator. */
export interface GuardOptions {
  /** Firewall config forwarded to core `guard` / `guardOutput`. */
  config?: Partial<OnDeviceConfig>;
  /** Scan the call's string inputs before running. Default true. */
  scanInput?: boolean;
  /** Scan the call's string output after running. Default true. */
  scanOutput?: boolean;
  /**
   * "block" (default) → throw {@link GuardBlockedError} when a scan is not
   * allowed. "flag" → run to completion, surface violations via `onViolation`,
   * never throw.
   */
  policy?: GuardPolicy;
  /** Invoked for every firewall trip (block AND flag). Errors are swallowed. */
  onViolation?: (event: GuardViolationEvent) => void;
  /** Also emit a trace span around the guarded call. Default true. */
  trace?: boolean;
  /** Span name when `trace` is on. Defaults to `guard:<fn name>`. */
  name?: string;
  /** Max recursion depth when extracting strings from structured args/output. */
  maxScanDepth?: number;
}

/** Thrown by a `block`-policy guarded call when the firewall trips. */
export class GuardBlockedError extends Error {
  readonly phase: GuardPhase;
  readonly violations: OnDeviceViolation[];
  readonly score: number;
  readonly result: OnDeviceResult;

  constructor(phase: GuardPhase, result: OnDeviceResult) {
    const checks = result.violations.map((v) => `${v.check}:${v.severity}`).join(", ");
    super(`EvalGuard @guard blocked ${phase} (score ${result.score}): ${checks || "policy"}`);
    this.name = "GuardBlockedError";
    this.phase = phase;
    this.violations = result.violations;
    this.score = result.score;
    this.result = result;
    // Restore prototype chain for instanceof across the CJS build target.
    Object.setPrototypeOf(this, GuardBlockedError.prototype);
  }
}

// 2026-07-29 (audit A290). These three constants used to be
//   DEFAULT_MAX_SCAN_DEPTH = 4, MAX_SCAN_STRINGS = 64,
//   MAX_SCAN_STRING_LEN = 20_000
// and every one of them made the guard report CLEAN on text it never looked
// at:
//
//   * depth 4. `guard(fn)` scans the `args` ARRAY, so the array itself burns
//     the first level. A completely ordinary structured payload —
//       fn({ input: { messages: [{ role, content: [{ type: "text", text }] }] } })
//     — puts the attacker's text at depth 6 and collected ZERO strings.
//     Reproduced: the identical injection string passed bare (depth 0) was
//     blocked, and nested was allowed. The guard silently degraded to a no-op
//     for exactly the payload shape LangChain / the OpenAI Responses API /
//     Anthropic tool-use all produce.
//   * count 64. Strings past the 64th were dropped. Put 64 innocuous strings
//     ahead of the payload and the payload is never scanned.
//   * length 20_000. Each string was TRUNCATED before scanning, so anything
//     past 20 KB was reported clean without being examined. Truncating a
//     scanner's input is not a bound, it is a bypass.
//
// New contract: scan EVERYTHING. The only remaining limits are stack-safety
// bounds, and hitting one is a REJECTION, not a pass — see `ScanBudget`.
// Cycles are handled by the `seen` WeakSet, not by the depth counter.
const DEFAULT_MAX_SCAN_DEPTH = 64;
const MAX_SCAN_STRINGS = 10_000;

/** Records whether the collector was cut short. An incomplete scan can never
 *  be reported as "allowed". */
interface ScanBudget {
  exhausted: boolean;
}

/**
 * Collect string leaves from an arbitrary value (args array, output object …)
 * so the firewall can scan structured payloads — e.g. `{ prompt: "…" }` or a
 * chat-message array — not just a bare string.
 *
 * Strings are collected WHOLE and untruncated. If a stack-safety bound is
 * reached, `budget.exhausted` is set and `scanValue` fails closed.
 */
function collectStrings(
  value: unknown,
  depth: number,
  acc: string[],
  seen: WeakSet<object>,
  budget: ScanBudget,
): void {
  if (acc.length >= MAX_SCAN_STRINGS) {
    budget.exhausted = true;
    return;
  }
  if (depth < 0) {
    // Do NOT silently return: unexamined subtrees are why A290 existed.
    budget.exhausted = true;
    return;
  }
  if (typeof value === "string") {
    if (value.length > 0) acc.push(value);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) return;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      collectStrings(item, depth - 1, acc, seen, budget);
      if (budget.exhausted) return;
    }
    return;
  }
  for (const item of Object.values(value)) {
    collectStrings(item, depth - 1, acc, seen, budget);
    if (budget.exhausted) return;
  }
}

function scanValue(
  value: unknown,
  phase: GuardPhase,
  options: GuardOptions | undefined,
): GuardBlockedError | undefined {
  const depth = options?.maxScanDepth ?? DEFAULT_MAX_SCAN_DEPTH;
  const strings: string[] = [];
  const budget: ScanBudget = { exhausted: false };
  collectStrings(value, depth, strings, new WeakSet<object>(), budget);

  const policy = options?.policy ?? "block";
  const scanner = phase === "input" ? coreGuard : coreGuardOutput;

  if (budget.exhausted) {
    // A290: the payload is too deep or too wide for this guard to have read
    // all of it. Reporting "allowed" here is precisely the silent bypass the
    // old caps produced, so reject instead. Callers who genuinely need to
    // pass such a payload can raise `maxScanDepth`.
    const result = incompleteScanResult(
      `@guard could not scan the entire ${phase} payload (depth limit ${depth} or ` +
        `${MAX_SCAN_STRINGS} strings reached). Refusing to report a partial scan as clean. ` +
        `Raise \`maxScanDepth\` or flatten the payload.`,
    );
    if (options?.onViolation) {
      try {
        options.onViolation({ phase, result, blocked: policy === "block", value: "" });
      } catch {
        /* a misbehaving callback must never break the guarded call */
      }
    }
    if (policy === "block") return new GuardBlockedError(phase, result);
  }

  for (const str of strings) {
    const result = scanFullString(str, scanner, options);
    if (result.allowed) continue;
    const blocked = policy === "block";
    if (options?.onViolation) {
      try {
        options.onViolation({ phase, result, blocked, value: str });
      } catch {
        // A misbehaving callback must never break the guarded call.
      }
    }
    if (blocked) return new GuardBlockedError(phase, result);
  }
  return undefined;
}

/**
 * A290, third door: the on-device engine ALSO truncates, at its own
 * `maxInputLength` (default 10_000), and reports it via `result.truncated`.
 * Its own doc comment says: "`allowed: true` on a truncated input means 'no
 * violation in the part we scanned' — NOT 'clean'". `@guard` ignored that
 * flag, so an attacker only had to push the payload past the cutoff.
 *
 * The fix is to actually SCAN the whole string, not to reject it and not to
 * trim it: split into OVERLAPPING windows and scan each. The overlap is what
 * keeps an injection that straddles a window boundary detectable — a naive
 * split would create a brand-new bypass at every multiple of the window size.
 *
 * Only if a window itself still reports `truncated` (i.e. the caller
 * configured a window smaller than our step) do we fall back to the
 * incomplete-scan rejection.
 */
function scanFullString(
  str: string,
  scanner: (s: string, cfg?: GuardOptions["config"]) => OnDeviceResult,
  options: GuardOptions | undefined,
): OnDeviceResult {
  const first = scanner(str, options?.config);
  if (!first.allowed || !first.truncated) return first;

  // The engine truncated but found nothing in the head. Sweep the tail.
  // `maxInputLength` defaults to 10_000 (on-device-runtime.ts:84); honour a
  // caller override when one was supplied.
  const windowSize = Math.max(
    1_000,
    (options?.config as { maxInputLength?: number } | undefined)?.maxInputLength ?? 10_000,
  );
  // 25% overlap: an injection straddling a boundary is still fully inside the
  // next window. A non-overlapping split would create a fresh bypass at every
  // multiple of the window size.
  const step = Math.max(1, Math.floor(windowSize * 0.75));
  for (let start = step; start < str.length; start += step) {
    const chunk = str.slice(start, start + windowSize);
    if (!chunk) break;
    const chunkResult = scanner(chunk, options?.config);
    if (!chunkResult.allowed) return chunkResult;
    if (chunkResult.truncated) {
      return incompleteScanResult(
        "@guard: the on-device scanner truncated even a single scan window, so part of " +
          "this payload was never examined. Refusing to report it clean.",
      );
    }
  }
  return first;
}

/**
 * Build the synthetic result used when @guard provably did not read all of
 * the payload. `content-policy` is used as the check id because it is a
 * member of the `OnDeviceCheck` union; the message carries the real reason.
 */
function incompleteScanResult(message: string): OnDeviceResult {
  return {
    allowed: false,
    score: 0,
    violations: [
      {
        check: "content-policy",
        severity: "high",
        message,
      } as OnDeviceViolation,
    ],
    latencyMs: 0,
    checksRun: 0,
    truncated: true,
  };
}

/**
 * Wrap a function/agent call so the EvalGuard firewall runs on its string
 * inputs (pre) and string output (post). Reuses the core `guard` /
 * `guardOutput` on-device engine — no new scanner.
 *
 * On a firewall trip the `block` policy (default) throws {@link GuardBlockedError}
 * (input trips throw BEFORE the wrapped function runs, so a malicious prompt
 * never reaches the model); the `flag` policy runs to completion and reports via
 * `onViolation`. When `trace` is on (default) the whole guarded call is also
 * emitted as a span (`eg.file.type: "tool"`), so blocks show up in the trace.
 */
export function guard<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options?: GuardOptions,
): (...args: TArgs) => Promise<TReturn> {
  const scanInput = options?.scanInput !== false;
  const scanOutput = options?.scanOutput !== false;

  async function guardedCore(this: unknown, ...args: TArgs): Promise<TReturn> {
    if (scanInput) {
      const blocked = scanValue(args, "input", options);
      if (blocked) throw blocked;
    }
    const result = await fn.apply(this, args);
    if (scanOutput) {
      const blocked = scanValue(result, "output", options);
      if (blocked) throw blocked;
    }
    return result;
  }

  if (options?.trace === false) {
    return guardedCore;
  }
  // Emit a span around the guarded call so blocks/flags surface in the trace.
  const name = options?.name ?? `guard:${fn.name || "anonymous"}`;
  return traceable(guardedCore, {
    name,
    metadata: { [EG_FILE_TYPE_ATTR]: "tool", "eg.guard": true },
  });
}

// ── TC39 method-decorator factories (one-line DX for class methods) ──────
//
// Each returns a standard (TC39) class-method decorator that preserves `this`
// by binding the instance into the HOF at call time. This is the `@flow` /
// `@guard` "one line" ergonomics on top of the HOFs above. Works on any TS 5 /
// standard-decorator build; this repo has `experimentalDecorators` OFF.
//
// The `context` parameter is optional so the factory can also be applied
// functionally (in tests / manual composition) without fabricating a full
// ClassMethodDecoratorContext; TC39 `@`-syntax still passes it at runtime.

/** Bind a method's receiver so a HOF wrapper keeps the instance `this`. */
function bindReceiver<This, TArgs extends unknown[], TReturn>(
  target: (this: This, ...args: TArgs) => TReturn | Promise<TReturn>,
  self: This,
): (...args: TArgs) => TReturn | Promise<TReturn> {
  return (...args: TArgs) => target.apply(self, args);
}

/** `@withFlow(opts?)` — class-method decorator form of {@link flow}. */
export function withFlow(options?: SpanDecoratorOptions) {
  return function decorate<This, TArgs extends unknown[], TReturn>(
    target: (this: This, ...args: TArgs) => TReturn | Promise<TReturn>,
    _context?: ClassMethodDecoratorContext<This, typeof target>,
  ): (this: This, ...args: TArgs) => Promise<TReturn> {
    return function replacement(this: This, ...args: TArgs): Promise<TReturn> {
      return flow(bindReceiver(target, this), options)(...args);
    };
  };
}

/** `@withPrompt(opts?)` — class-method decorator form of {@link prompt}. */
export function withPrompt(options?: SpanDecoratorOptions) {
  return function decorate<This, TArgs extends unknown[], TReturn>(
    target: (this: This, ...args: TArgs) => TReturn | Promise<TReturn>,
    _context?: ClassMethodDecoratorContext<This, typeof target>,
  ): (this: This, ...args: TArgs) => Promise<TReturn> {
    return function replacement(this: This, ...args: TArgs): Promise<TReturn> {
      return prompt(bindReceiver(target, this), options)(...args);
    };
  };
}

/** `@withTool(opts?)` — class-method decorator form of {@link tool}. */
export function withTool(options?: SpanDecoratorOptions) {
  return function decorate<This, TArgs extends unknown[], TReturn>(
    target: (this: This, ...args: TArgs) => TReturn | Promise<TReturn>,
    _context?: ClassMethodDecoratorContext<This, typeof target>,
  ): (this: This, ...args: TArgs) => Promise<TReturn> {
    return function replacement(this: This, ...args: TArgs): Promise<TReturn> {
      return tool(bindReceiver(target, this), options)(...args);
    };
  };
}

/** `@withTrace(opts?)` — class-method decorator form of {@link traceable}. */
export function withTrace(options?: TraceableOptions) {
  return function decorate<This, TArgs extends unknown[], TReturn>(
    target: (this: This, ...args: TArgs) => TReturn | Promise<TReturn>,
    _context?: ClassMethodDecoratorContext<This, typeof target>,
  ): (this: This, ...args: TArgs) => Promise<TReturn> {
    return function replacement(this: This, ...args: TArgs): Promise<TReturn> {
      return traceable(bindReceiver(target, this), options)(...args);
    };
  };
}

/** `@withGuard(opts?)` — class-method decorator form of {@link guard}. */
export function withGuard(options?: GuardOptions) {
  return function decorate<This, TArgs extends unknown[], TReturn>(
    target: (this: This, ...args: TArgs) => TReturn | Promise<TReturn>,
    _context?: ClassMethodDecoratorContext<This, typeof target>,
  ): (this: This, ...args: TArgs) => Promise<TReturn> {
    return function replacement(this: This, ...args: TArgs): Promise<TReturn> {
      return guard(bindReceiver(target, this), options)(...args);
    };
  };
}
