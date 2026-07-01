/**
 * EvalGuard Vitest Plugin -- auto-report test results as eval runs.
 *
 * @example
 * // vitest.config.ts
 * import { defineConfig } from "vitest/config";
 * import { evalguardPlugin } from "@evalguard/sdk/vitest";
 *
 * export default defineConfig({
 *   test: {
 *     reporters: [evalguardPlugin({ projectId: "proj_123" })],
 *   },
 * });
 *
 * @example
 * // In test files
 * import { evalguardTest, expectScore } from "@evalguard/sdk/vitest";
 *
 * evalguardTest("model returns correct answer", async ({ expect }) => {
 *   const output = await callModel("2+2");
 *   expect(output).toBe("4");
 * });
 *
 * test("score threshold", () => {
 *   expectScore(0.95).toBeGreaterThan(0.8);
 * });
 */

import type { EvalGuardConfig } from "./client";
import { EvalGuard } from "./client";

// ── Types ────────────────────────────────────────────────────────────

export interface EvalGuardVitestConfig {
  /** EvalGuard API key (defaults to EVALGUARD_API_KEY env var). */
  apiKey?: string;
  /** EvalGuard API base URL. */
  baseUrl?: string;
  /** Project ID for reporting. */
  projectId?: string;
  /** Only report tests tagged with evalguardTest(). */
  taggedOnly?: boolean;
}

interface TestCaseResult {
  testName: string;
  displayName: string;
  passed: boolean;
  duration: number;
  error?: {
    type: string;
    message: string;
    traceback?: string;
  };
  tags?: string[];
  suite?: string;
}

// ── Internal state for tagged tests ─────────────────────────────────

const _taggedTests = new Set<string>();
const _testMetadata = new Map<string, { tags?: string[] }>();

// ── evalguardTest wrapper ───────────────────────────────────────────

type TestFn = (context: { expect: typeof import("vitest")["expect"] }) => void | Promise<void>;

/**
 * Wrapper around vitest `test()` that tags the test for EvalGuard reporting.
 *
 * @example
 * evalguardTest("model accuracy", async ({ expect }) => {
 *   const result = await callModel("hello");
 *   expect(result).toContain("hello");
 * });
 *
 * evalguardTest("with tags", async ({ expect }) => {
 *   expect(true).toBe(true);
 * }, { tags: ["gpt-4o", "accuracy"] });
 */
export function evalguardTest(
  name: string,
  fn: TestFn,
  options?: { tags?: string[] },
): void {
  _taggedTests.add(name);
  if (options?.tags) {
    _testMetadata.set(name, { tags: options.tags });
  }

  // Delegate to vitest's global `test` (available when globals: true)
  const vitestTest = (globalThis as Record<string, unknown>).test as
    | ((name: string, fn: TestFn) => void)
    | undefined;
  if (typeof vitestTest === "function") {
    vitestTest(name, fn);
  } else {
    // Fallback: re-export so user can import { test } from vitest themselves
    throw new Error(
      "evalguardTest requires vitest globals enabled (globals: true in vitest config) " +
        "or a vitest test context.",
    );
  }
}

// ── expectScore helper ──────────────────────────────────────────────

interface ScoreAssertion {
  toBeGreaterThan(threshold: number): void;
  toBeLessThan(threshold: number): void;
  toBeInRange(min: number, max: number): void;
  toBe(expected: number): void;
}

/**
 * Assertion helper for numeric scores (0-1 range typically).
 *
 * @example
 * expectScore(0.92).toBeGreaterThan(0.8);
 * expectScore(0.15).toBeLessThan(0.3);
 * expectScore(0.85).toBeInRange(0.8, 0.95);
 */
export function expectScore(value: number): ScoreAssertion {
  return {
    toBeGreaterThan(threshold: number): void {
      if (value <= threshold) {
        throw new Error(
          `EvalGuard score assertion failed: expected ${value} to be greater than ${threshold}`,
        );
      }
    },
    toBeLessThan(threshold: number): void {
      if (value >= threshold) {
        throw new Error(
          `EvalGuard score assertion failed: expected ${value} to be less than ${threshold}`,
        );
      }
    },
    toBeInRange(min: number, max: number): void {
      if (value < min || value > max) {
        throw new Error(
          `EvalGuard score assertion failed: expected ${value} to be in range [${min}, ${max}]`,
        );
      }
    },
    toBe(expected: number): void {
      if (value !== expected) {
        throw new Error(
          `EvalGuard score assertion failed: expected ${value} to be ${expected}`,
        );
      }
    },
  };
}

// ── Vitest Reporter ─────────────────────────────────────────────────

/**
 * Vitest Reporter that collects test results and sends them to EvalGuard.
 *
 * Implements the vitest Reporter interface (onInit, onFinished, etc.).
 */
export class EvalGuardReporter {
  private client: EvalGuard | null = null;
  private projectId: string | undefined;
  private taggedOnly: boolean;
  private results: TestCaseResult[] = [];

  constructor(config: EvalGuardVitestConfig = {}) {
    const apiKey = config.apiKey || process.env.EVALGUARD_API_KEY;
    const baseUrl = config.baseUrl || process.env.EVALGUARD_BASE_URL;
    this.projectId = config.projectId || process.env.EVALGUARD_PROJECT_ID;
    this.taggedOnly = config.taggedOnly ?? false;

    if (apiKey) {
      const clientConfig: EvalGuardConfig = { apiKey };
      if (baseUrl) clientConfig.baseUrl = baseUrl;
      this.client = new EvalGuard(clientConfig);
    }
  }

  // ── Reporter lifecycle hooks ──────────────────────────────────────

  onInit(): void {
    this.results = [];
  }

  onFinished(files?: unknown[]): void {
    // Process file results from vitest
    if (Array.isArray(files)) {
      for (const file of files) {
        this._processFile(file as Record<string, unknown>);
      }
    }

    // Send results
    void this._sendResults();
  }

  // Also support the tasks-based API (vitest v1+)
  onTaskUpdate(packs: unknown[]): void {
    // Vitest sends task update packs during execution
    // We collect results in onFinished instead
  }

  // ── Internal helpers ──────────────────────────────────────────────

  private _processFile(file: Record<string, unknown>): void {
    const tasks = file.tasks as Record<string, unknown>[] | undefined;
    if (!Array.isArray(tasks)) return;

    const filepath = (file.filepath || file.name || "") as string;

    for (const task of tasks) {
      this._processTask(task, filepath);
    }
  }

  private _processTask(task: Record<string, unknown>, suite: string): void {
    const name = (task.name || "") as string;
    const type = task.type as string;

    // Handle suite (describe block) -- recurse into children
    if (type === "suite") {
      const children = task.tasks as Record<string, unknown>[] | undefined;
      if (Array.isArray(children)) {
        for (const child of children) {
          this._processTask(child, `${suite} > ${name}`);
        }
      }
      return;
    }

    // Handle individual test
    if (type !== "test") return;

    // Filter to tagged-only if configured
    if (this.taggedOnly && !_taggedTests.has(name)) return;

    const result = task.result as Record<string, unknown> | undefined;
    const state = (result?.state || "skip") as string;
    const duration = (result?.duration || 0) as number;

    const testResult: TestCaseResult = {
      testName: `${suite} > ${name}`,
      displayName: name,
      passed: state === "pass",
      duration: Math.round(duration * 100) / 100,
      suite,
    };

    // Capture error details
    if (state === "fail") {
      const errors = result?.errors as Record<string, unknown>[] | undefined;
      if (Array.isArray(errors) && errors.length > 0) {
        const err = errors[0];
        testResult.error = {
          type: (err.name || "AssertionError") as string,
          message: (err.message || "Test failed") as string,
          traceback: ((err.stack || err.stackStr || "") as string).slice(0, 2000),
        };
      }
    }

    // Attach metadata from evalguardTest()
    const meta = _testMetadata.get(name);
    if (meta?.tags) {
      testResult.tags = meta.tags;
    }

    this.results.push(testResult);
  }

  private async _sendResults(): Promise<void> {
    if (!this.client || this.results.length === 0) return;

    const total = this.results.length;
    const passed = this.results.filter((r) => r.passed).length;
    const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);

    const payload: Record<string, unknown> = {
      source: "vitest",
      summary: {
        total,
        passed,
        failed: total - passed,
        passRate: total > 0 ? Math.round((passed / total) * 10000) / 10000 : 0,
        totalDuration: Math.round(totalDuration * 100) / 100,
      },
      cases: this.results,
    };

    if (this.projectId) {
      payload.projectId = this.projectId;
    }

    try {
      await (this.client as unknown as { request: (path: string, method: string, body: unknown) => Promise<unknown> })
        .request("/evals/ci", "POST", payload);
    } catch {
      // Don't fail tests because of reporting errors -- warn instead
      console.warn("[EvalGuard] Failed to report test results. Check API key and connectivity.");
    }
  }
}

// ── Factory function ────────────────────────────────────────────────

/**
 * Create an EvalGuard vitest reporter instance.
 *
 * @example
 * // vitest.config.ts
 * import { evalguardPlugin } from "@evalguard/sdk/vitest";
 *
 * export default defineConfig({
 *   test: {
 *     reporters: ["default", evalguardPlugin({ projectId: "proj_123" })],
 *   },
 * });
 */
export function evalguardPlugin(config: EvalGuardVitestConfig = {}): EvalGuardReporter {
  return new EvalGuardReporter(config);
}
