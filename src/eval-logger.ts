// ── Imperative EvaluationLogger (Weave-style) ──────────────────────────
//
// The declarative `client.eval(EvalParams)` API posts a full eval config and
// lets the SERVER run the model. That doesn't fit pipelines that already have
// their own model calls and just want to RECORD predictions + scores against a
// run as they go (the way Weave's `EvaluationLogger` / Braintrust's
// experiment-logging works).
//
// `client.startEvalLogger()` creates an `eval_runs` row in EXTERNAL mode
// (status=running, the server does NOT execute the model) and returns an
// `EvaluationLogger` bound to that run. The logger buffers prediction rows,
// auto-assigns `test_case_index`, merges per-scorer results, and flushes via
// the EXISTING batch-upsert at POST /evals/[runId]/results (idempotent on
// test_case_index). `finish()` flushes the tail and PATCHes the run to a
// terminal status via PATCH /evals/[runId].
//
// No new server endpoint is required for row ingest — the only server change is
// the `external` skip on POST /evals (so the model isn't run) + the (already
// present) PATCH /evals/[runId] used by finish().

/** Transport bound to a single client instance — mirrors `EvalGuard.request()`
 *  (idempotency-key + retry + `{ success, data }` envelope unwrap). Injected by
 *  `EvalGuard.startEvalLogger()` so the logger reuses the client's transport
 *  without `request()` being made public. */
export type BoundRequest = <T = unknown>(
  path: string,
  method: string,
  body?: unknown,
) => Promise<T>;

/** Terminal-or-progress status for an eval run. Mirrors the PATCH
 *  /evals/[runId] status enum exactly. */
export type EvalRunStatus =
  | "pending"
  | "queued"
  | "running"
  | "passed"
  | "failed"
  | "error";

/** Params for {@link EvalGuard.startEvalLogger}. A thin subset of EvalParams —
 *  `cases` are NOT supplied up front (you log them imperatively), and `prompt`
 *  / `scorers` are optional context recorded on the run. */
export interface EvalLoggerParams {
  /** Project the run belongs to (tenant scope). Required. */
  projectId: string;
  /** Human-readable run name. Required. */
  name: string;
  /** Model under evaluation (recorded on the run; not executed server-side). Required. */
  model: string;
  /** Optional templated prompt recorded as run context. */
  prompt?: string;
  /** Optional scorer names recorded as run context. */
  scorers?: string[];
  /**
   * Flush threshold — buffered rows are POSTed once the buffer reaches this
   * many entries. Defaults to 50. Clamped to the server's per-request max of
   * 1000 rows.
   */
  flushAt?: number;
}

/** One imperative prediction to log against the run. */
export interface PredictionRow {
  /** The model input for this case. Required. */
  input: string;
  /** The model output for this case. Required. */
  output: string;
  /** Optional gold/reference output. */
  expected?: string;
  /** Optional measured latency in milliseconds. */
  latencyMs?: number;
  /** Optional measured cost in USD. */
  cost?: number;
  /** Optional structured metadata folded into the row's scores map under `_metadata`. */
  metadata?: Record<string, unknown>;
}

/** Summary passed to {@link EvaluationLogger.logSummary} / {@link EvaluationLogger.finish}. */
export interface EvalLoggerSummary {
  /** Terminal status for the run (default `passed`). */
  status?: EvalRunStatus;
  /** Aggregate score, 0..1 (server clamps). */
  score?: number;
  /** Pass rate, 0..1 — recorded on the run summary for reporting. */
  passRate?: number;
}

// The maximum number of rows POST /evals/[runId]/results accepts in one call.
// Mirrors the `.max(1000)` guard on its zod body so we never build a request
// the server will reject.
const SERVER_MAX_ROWS = 1000;
const DEFAULT_FLUSH_AT = 50;

/**
 * A single buffered row, kept in the EXACT wire shape of the results route's
 * `ResultRow` zod schema (test_case_index, input, expected, output, scores,
 * latency_ms, passed, score, cost) so no server-side change is needed to ingest
 * it. `scores` doubles as the per-scorer results map that `logScore()` merges
 * into — the results route stores it as `scorer_results` verbatim.
 */
interface BufferedRow {
  test_case_index: number;
  input: string;
  expected?: string;
  output: string;
  scores: Record<string, unknown>;
  latency_ms: number;
  passed: boolean;
  score?: number;
  cost?: number;
}

/**
 * Imperative, Weave-style logger bound to one eval run. Construct it via
 * {@link EvalGuard.startEvalLogger}, not directly.
 *
 *   const logger = await client.startEvalLogger({ projectId, name: "smoke", model: "gpt-4o" });
 *   const { index } = logger.logPrediction({ input: q, output: a, expected: gold });
 *   logger.logScore(index, "exact-match", 1, true);
 *   await logger.finish({ status: "passed", score: 0.92, passRate: 0.9 });
 */
export class EvaluationLogger {
  /** The eval_runs id this logger writes to. */
  readonly runId: string;

  private readonly request: BoundRequest;
  private readonly flushAt: number;

  /** Rows not yet flushed, keyed by test_case_index so logScore can find them. */
  private readonly buffer = new Map<number, BufferedRow>();
  /**
   * The last-known full row for each index that has ALREADY been flushed, kept
   * so a late `logScore` (after an auto-flush) can re-buffer the COMPLETE row
   * with merged scores — not a blank carrier. The results route upserts with
   * ON CONFLICT DO UPDATE (full-row replace), so a blank carrier would wipe the
   * real input/output; re-sending the full merged row keeps the merge correct
   * and idempotent.
   */
  private readonly flushed = new Map<number, BufferedRow>();
  /** Monotonic next index — never reused, so flushed + buffered rows never collide. */
  private nextIndex = 0;
  /** True once finish() has run; further logging throws. */
  private finished = false;

  constructor(params: { runId: string; request: BoundRequest; flushAt?: number }) {
    if (!params.runId) throw new Error("EvaluationLogger: runId is required");
    this.runId = params.runId;
    this.request = params.request;
    const at = params.flushAt ?? DEFAULT_FLUSH_AT;
    // Clamp to [1, SERVER_MAX_ROWS]: a flushAt of 0/negative would buffer
    // forever; one above the server cap would build a request the server 400s.
    this.flushAt = Math.max(1, Math.min(SERVER_MAX_ROWS, Math.floor(at)));
  }

  /** Number of rows currently buffered (not yet flushed). For tests/observability. */
  get pending(): number {
    return this.buffer.size;
  }

  /**
   * Buffer a prediction row, auto-assigning the next `test_case_index`. Flushes
   * synchronously-in-the-background when the buffer reaches `flushAt`; the
   * returned `index` is valid immediately so you can `logScore(index, ...)`
   * even after an auto-flush (scores for already-flushed rows re-upsert and
   * MERGE on the same (run, case_index) row). Does NOT await the flush — call
   * `await logger.flush()` or `await logger.finish()` to guarantee durability.
   */
  logPrediction(row: PredictionRow): { index: number } {
    this.assertOpen();
    if (typeof row.input !== "string") throw new Error("logPrediction: input must be a string");
    if (typeof row.output !== "string") throw new Error("logPrediction: output must be a string");

    const index = this.nextIndex++;
    const scores: Record<string, unknown> = {};
    if (row.metadata !== undefined) scores._metadata = row.metadata;

    const buffered: BufferedRow = {
      test_case_index: index,
      input: row.input,
      output: row.output,
      scores,
      // The results route's ResultRow requires latency_ms (number) + passed
      // (boolean). Default latency to 0 and passed to true; a later logScore
      // with passed=false flips it.
      latency_ms: row.latencyMs ?? 0,
      passed: true,
    };
    if (row.expected !== undefined) buffered.expected = row.expected;
    if (row.cost !== undefined) buffered.cost = row.cost;

    this.buffer.set(index, buffered);

    if (this.buffer.size >= this.flushAt) {
      // Fire-and-forget: keep logPrediction synchronous (Weave parity). Errors
      // surface on the next awaited flush()/finish() via re-buffering below.
      void this.flush().catch(() => {
        /* swallowed here; a real failure re-throws on the next awaited flush */
      });
    }

    return { index };
  }

  /**
   * Merge a scorer result into the buffered row for `index`. Stores
   * `{ score, passed }` under `scorerName` in the row's scores map (which the
   * results route persists as `scorer_results`). When `passed` is provided it
   * also updates the row's top-level `passed`/`score` so the run's pass-rate +
   * average reflect the latest scorer outcome.
   *
   * If the row was already flushed (auto-flush after `logPrediction`), the
   * FULL last-flushed row (real input/output + prior scores) is re-buffered for
   * the SAME test_case_index, so the next flush re-upserts it with the merged
   * scores. The results route upserts ON CONFLICT DO UPDATE, so this carries the
   * complete row (not a blank carrier that would wipe input/output) and the late
   * score is durably MERGED rather than dropped.
   */
  logScore(index: number, scorerName: string, value: number, passed?: boolean): void {
    this.assertOpen();
    if (!scorerName) throw new Error("logScore: scorerName is required");
    if (index < 0 || index >= this.nextIndex) {
      throw new Error(`logScore: unknown prediction index ${index} (log the prediction first)`);
    }

    let row = this.buffer.get(index);
    if (!row) {
      // Already flushed — re-buffer a deep copy of the LAST-FLUSHED full row
      // (real input/output + any prior scores), preserving every field so the
      // ON CONFLICT DO UPDATE merges the late score instead of replacing the row
      // with blanks. flushed always has the index here (a flushed row's index is
      // recorded by flush()); fall back to a minimal carrier defensively.
      const prior = this.flushed.get(index);
      row = prior
        ? {
            ...prior,
            scores: { ...prior.scores },
          }
        : {
            test_case_index: index,
            input: "",
            output: "",
            scores: {},
            latency_ms: 0,
            passed: true,
          };
      this.buffer.set(index, row);
    }

    row.scores[scorerName] = passed === undefined ? { score: value } : { score: value, passed };
    // Reflect the scorer outcome on the row aggregate used for pass-rate/avg.
    row.score = value;
    if (passed !== undefined) row.passed = passed;
  }

  /**
   * POST all buffered rows to the existing batch-upsert
   * (POST /evals/[runId]/results). Idempotent on test_case_index, so a retried
   * or duplicate flush never double-counts. A no-op when the buffer is empty.
   */
  async flush(): Promise<void> {
    if (this.buffer.size === 0) return;

    // Snapshot + clear so concurrent logging during the await doesn't lose rows.
    const rows = Array.from(this.buffer.values());
    this.buffer.clear();

    // Respect the server's per-request row cap by chunking. Re-buffer any chunk
    // that fails so the rows aren't silently dropped and a later flush retries.
    for (let i = 0; i < rows.length; i += SERVER_MAX_ROWS) {
      const chunk = rows.slice(i, i + SERVER_MAX_ROWS);
      try {
        await this.request(`/evals/${encodeURIComponent(this.runId)}/results`, "POST", {
          results: chunk,
        });
        // Record each successfully-flushed row's full state so a later
        // logScore() for an already-flushed index re-buffers the COMPLETE row
        // (real input/output) and the late score merges, not a blank carrier.
        for (const r of chunk) {
          this.flushed.set(r.test_case_index, { ...r, scores: { ...r.scores } });
        }
      } catch (err) {
        // Restore the failed chunk (and any not-yet-sent rows) into the buffer
        // so the caller can retry; merge instead of overwrite to preserve any
        // rows logged during the await.
        for (const r of rows.slice(i)) {
          if (!this.buffer.has(r.test_case_index)) this.buffer.set(r.test_case_index, r);
        }
        throw err;
      }
    }
  }

  /**
   * Flush remaining rows, then PATCH the run to a terminal status with the
   * given summary (score / pass-rate). Separated from finish() so callers can
   * record a non-terminal summary mid-run if they want; finish() simply calls
   * this with a terminal default.
   */
  async logSummary(summary: EvalLoggerSummary = {}): Promise<void> {
    this.assertOpen();
    await this.flush();

    const status: EvalRunStatus = summary.status ?? "passed";
    // PATCH /evals/[runId] reads score from summary.score (clamped 0..1) and
    // passRate is recorded in the summary blob for reporting.
    const summaryBlob: Record<string, unknown> = {};
    if (summary.score !== undefined) summaryBlob.score = summary.score;
    if (summary.passRate !== undefined) summaryBlob.passRate = summary.passRate;

    const body: { status: EvalRunStatus; summary?: Record<string, unknown> } = { status };
    if (Object.keys(summaryBlob).length > 0) body.summary = summaryBlob;

    await this.request(`/evals/${encodeURIComponent(this.runId)}`, "PATCH", body);

    // A terminal status closes the run (the route's immutability gate then
    // rejects further PATCHes); lock the logger to match.
    if (status === "passed" || status === "failed" || status === "error") {
      this.finished = true;
    }
  }

  /**
   * Flush the tail and close the run. Equivalent to `logSummary()` with a
   * terminal status (defaults to `passed`). After finish() the logger is locked
   * and further logging throws.
   */
  async finish(summary: EvalLoggerSummary = {}): Promise<void> {
    const status: EvalRunStatus = summary.status ?? "passed";
    await this.logSummary({ ...summary, status });
    this.finished = true;
  }

  private assertOpen(): void {
    if (this.finished) {
      throw new Error("EvaluationLogger: run already finished — create a new logger to log more");
    }
  }
}
