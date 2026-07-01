import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";
import { EvaluationLogger } from "../eval-logger";

// ---------------------------------------------------------------------------
// Imperative EvaluationLogger (Weave-style).
//   - startEvalLogger() POSTs /evals with external:true and binds to runId.
//   - logPrediction buffers + auto-assigns test_case_index.
//   - logScore merges a scorer result into the buffered row's scores map.
//   - flush() POSTs the exact ResultRow shape to /evals/[runId]/results.
//   - finish() flushes + PATCHes /evals/[runId] to a terminal status/score.
// fetch is mocked; we assert URLs, methods, and request bodies.
// ---------------------------------------------------------------------------

/** Build a fetch mock whose Nth call resolves the Nth body (last repeats). */
function mockFetchSequence(bodies: unknown[]) {
  let call = 0;
  return vi.fn().mockImplementation(() => {
    const body = bodies[Math.min(call, bodies.length - 1)];
    call += 1;
    return Promise.resolve({
      ok: true,
      status: 200,
      statusText: "OK",
      json: vi.fn().mockResolvedValue(body),
    });
  });
}

/** Parse the JSON body of the f.mock call at `idx`. */
function bodyOf(f: ReturnType<typeof vi.fn>, idx: number): Record<string, unknown> {
  const init = f.mock.calls[idx][1] as RequestInit;
  return JSON.parse(String(init.body)) as Record<string, unknown>;
}

function methodOf(f: ReturnType<typeof vi.fn>, idx: number): string {
  return (f.mock.calls[idx][1] as RequestInit).method as string;
}

function urlOf(f: ReturnType<typeof vi.fn>, idx: number): string {
  return f.mock.calls[idx][0] as string;
}

describe("EvalGuard.startEvalLogger", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("POSTs /evals with external:true, empty cases, and returns a logger bound to the run id", async () => {
    const f = mockFetchSequence([{ success: true, data: { id: "run-123", status: "running" } }]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });

    const logger = await c.startEvalLogger({ projectId: "p1", name: "smoke", model: "gpt-4o" });

    expect(logger).toBeInstanceOf(EvaluationLogger);
    expect(logger.runId).toBe("run-123");
    expect(urlOf(f, 0)).toBe("https://evalguard.ai/api/v1/evals");
    expect(methodOf(f, 0)).toBe("POST");
    const body = bodyOf(f, 0);
    expect(body).toMatchObject({
      projectId: "p1",
      name: "smoke",
      model: "gpt-4o",
      external: true,
      cases: [],
    });
  });

  it("validates required params before any fetch", async () => {
    const f = mockFetchSequence([{ data: { id: "x" } }]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.startEvalLogger({ projectId: "", name: "n", model: "m" })).rejects.toThrow(/projectId/);
    await expect(c.startEvalLogger({ projectId: "p", name: "", model: "m" })).rejects.toThrow(/name/);
    await expect(c.startEvalLogger({ projectId: "p", name: "n", model: "" })).rejects.toThrow(/model/);
    expect(f).not.toHaveBeenCalled();
  });

  it("throws when the server returns no run id", async () => {
    const f = mockFetchSequence([{ success: true, data: { status: "running" } }]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.startEvalLogger({ projectId: "p", name: "n", model: "m" })).rejects.toThrow(/run id/);
  });
});

describe("EvaluationLogger.logPrediction / logScore (buffering)", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  async function newLogger(flushAt?: number): Promise<{ logger: EvaluationLogger; f: ReturnType<typeof vi.fn> }> {
    const f = mockFetchSequence([
      { success: true, data: { id: "run-1", status: "running" } },
      { success: true, data: [{ id: "case" }] }, // results upserts
      { success: true, data: { id: "run-1", status: "passed" } }, // patch
    ]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const logger = await c.startEvalLogger({ projectId: "p", name: "n", model: "m", flushAt });
    return { logger, f };
  }

  it("auto-assigns monotonic test_case_index and buffers without flushing", async () => {
    const { logger, f } = await newLogger(50);
    const a = logger.logPrediction({ input: "q1", output: "a1" });
    const b = logger.logPrediction({ input: "q2", output: "a2" });
    expect(a.index).toBe(0);
    expect(b.index).toBe(1);
    expect(logger.pending).toBe(2);
    // only the create call happened — no flush below threshold.
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("logScore merges into the buffered row's scores map and updates passed/score", async () => {
    const { logger, f } = await newLogger(50);
    const { index } = logger.logPrediction({ input: "q", output: "a", expected: "g" });
    logger.logScore(index, "exact-match", 1, true);
    logger.logScore(index, "relevance", 0.4, false);
    await logger.flush();

    // call 0 = create; call 1 = results POST.
    expect(urlOf(f, 1)).toBe("https://evalguard.ai/api/v1/evals/run-1/results");
    const body = bodyOf(f, 1);
    const rows = body.results as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      test_case_index: 0,
      input: "q",
      output: "a",
      expected: "g",
    });
    expect(rows[0].scores).toMatchObject({
      "exact-match": { score: 1, passed: true },
      relevance: { score: 0.4, passed: false },
    });
    // last scorer set passed=false -> row aggregate reflects it.
    expect(rows[0].passed).toBe(false);
    expect(rows[0].score).toBe(0.4);
  });

  it("logScore on an unknown index throws", async () => {
    const { logger } = await newLogger(50);
    logger.logPrediction({ input: "q", output: "a" });
    expect(() => logger.logScore(99, "s", 1)).toThrow(/unknown prediction index/);
  });

  it("auto-flushes when the buffer reaches flushAt", async () => {
    const { logger, f } = await newLogger(2);
    logger.logPrediction({ input: "q1", output: "a1" });
    logger.logPrediction({ input: "q2", output: "a2" }); // triggers flush
    // allow the fire-and-forget flush microtask to settle.
    await Promise.resolve();
    await Promise.resolve();
    // create + results POST.
    expect(f).toHaveBeenCalledTimes(2);
    expect(urlOf(f, 1)).toContain("/evals/run-1/results");
  });

  it("logScore AFTER a flush re-buffers the FULL merged row (not a blank carrier) so the late score is preserved", async () => {
    // BUG 3: the carrier row used to be blank (input:"", output:"", scores:{}).
    // The results route upserts ON CONFLICT DO UPDATE (full-row replace), so a
    // blank carrier would WIPE the real input/output AND only carry the one late
    // score. The logger must re-send the COMPLETE last-flushed row with the late
    // score merged in.
    const { logger, f } = await newLogger(50);
    const { index } = logger.logPrediction({
      input: "the-question",
      output: "the-answer",
      expected: "gold",
      latencyMs: 42,
      cost: 0.003,
    });
    logger.logScore(index, "exact-match", 1, true);

    // First flush persists the row.
    await logger.flush();
    expect(logger.pending).toBe(0);

    // A late score arrives AFTER the flush (row already evicted from buffer).
    logger.logScore(index, "relevance", 0.4, false);
    // It re-buffers as a single pending row for the same index.
    expect(logger.pending).toBe(1);

    await logger.flush();

    // call 0 = create, call 1 = first flush, call 2 = the late-score re-flush.
    const rows = bodyOf(f, 2).results as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    // FULL row, not a blank carrier — real input/output/expected survive.
    expect(rows[0]).toMatchObject({
      test_case_index: index,
      input: "the-question",
      output: "the-answer",
      expected: "gold",
      latency_ms: 42,
      cost: 0.003,
    });
    // BOTH the original AND the late score are present (merged, not lost).
    expect(rows[0].scores).toMatchObject({
      "exact-match": { score: 1, passed: true },
      relevance: { score: 0.4, passed: false },
    });
    // The late scorer set passed=false → row aggregate reflects it.
    expect(rows[0].passed).toBe(false);
    expect(rows[0].score).toBe(0.4);
  });
});

describe("EvaluationLogger.flush (wire shape)", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("POSTs the exact ResultRow shape and defaults latency_ms=0 + passed=true", async () => {
    const f = mockFetchSequence([
      { success: true, data: { id: "run-9", status: "running" } },
      { success: true, data: [] },
    ]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const logger = await c.startEvalLogger({ projectId: "p", name: "n", model: "m" });

    logger.logPrediction({ input: "in", output: "out", latencyMs: 123, cost: 0.002, metadata: { k: "v" } });
    await logger.flush();

    const rows = (bodyOf(f, 1).results as Array<Record<string, unknown>>);
    expect(rows[0]).toMatchObject({
      test_case_index: 0,
      input: "in",
      output: "out",
      latency_ms: 123,
      cost: 0.002,
      passed: true,
    });
    expect((rows[0].scores as Record<string, unknown>)._metadata).toEqual({ k: "v" });
  });

  it("clears the buffer after a successful flush (idempotent re-flush is a no-op)", async () => {
    const f = mockFetchSequence([
      { success: true, data: { id: "run-2", status: "running" } },
      { success: true, data: [] },
    ]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const logger = await c.startEvalLogger({ projectId: "p", name: "n", model: "m" });
    logger.logPrediction({ input: "q", output: "a" });
    await logger.flush();
    expect(logger.pending).toBe(0);
    await logger.flush(); // no buffered rows -> no extra fetch.
    expect(f).toHaveBeenCalledTimes(2);
  });
});

describe("EvaluationLogger.finish / logSummary (PATCH terminal)", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("finish flushes remaining rows then PATCHes /evals/[runId] to terminal status + score", async () => {
    const f = mockFetchSequence([
      { success: true, data: { id: "run-7", status: "running" } }, // create
      { success: true, data: [] }, // flush
      { success: true, data: { id: "run-7", status: "passed" } }, // patch
    ]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const logger = await c.startEvalLogger({ projectId: "p", name: "n", model: "m" });
    logger.logPrediction({ input: "q", output: "a" });

    await logger.finish({ status: "passed", score: 0.92, passRate: 0.8 });

    // call 1 = results flush, call 2 = PATCH.
    expect(urlOf(f, 2)).toBe("https://evalguard.ai/api/v1/evals/run-7");
    expect(methodOf(f, 2)).toBe("PATCH");
    expect(bodyOf(f, 2)).toEqual({
      status: "passed",
      summary: { score: 0.92, passRate: 0.8 },
    });
  });

  it("finish defaults to status 'passed' when none given", async () => {
    const f = mockFetchSequence([
      { success: true, data: { id: "run-8", status: "running" } },
      { success: true, data: { id: "run-8", status: "passed" } },
    ]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const logger = await c.startEvalLogger({ projectId: "p", name: "n", model: "m" });
    await logger.finish();
    // no rows -> no flush call; create then PATCH.
    expect(methodOf(f, 1)).toBe("PATCH");
    expect(bodyOf(f, 1)).toEqual({ status: "passed" });
  });

  it("logging after finish throws (run is closed)", async () => {
    const f = mockFetchSequence([
      { success: true, data: { id: "run-x", status: "running" } },
      { success: true, data: { id: "run-x", status: "failed" } },
    ]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const logger = await c.startEvalLogger({ projectId: "p", name: "n", model: "m" });
    await logger.finish({ status: "failed" });
    expect(() => logger.logPrediction({ input: "q", output: "a" })).toThrow(/already finished/);
  });
});
