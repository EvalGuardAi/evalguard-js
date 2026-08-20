import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, normalizeApiBaseUrl } from "../client";

// Regression tests for the live-E2E SDK fixes (2026-07-16):
//   #1 listScorers()/listPlugins() unwrap the { scorers|plugins, total } envelope
//      to a bare array so `.map`/`for..of` work.
//   #2 listEvals() maps raw snake_case rows to the camelCase EvalRun shape.
//   #4 securityScan() returns the started-scan STUB (id + counts), not findings.
//   #5 normalizeApiBaseUrl() maps a `.../api` (or bare-origin) base to `.../api/v1`.
// (baseUrl constructor normalization + requestId header threading are covered in
//  sdk.test.ts.)

function mockFetch(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    headers: { get: () => null },
    json: vi.fn().mockResolvedValue(body),
  });
}

/** Wrap a payload in the standard { success, data } API envelope the client unwraps. */
function enveloped(data: unknown) {
  return { success: true, data };
}

describe("SDK E2E fix #1 — listScorers()/listPlugins() return a bare array", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listScorers unwraps { scorers, total } → Scorer[]", async () => {
    const f = mockFetch(
      enveloped({
        scorers: [
          { id: "exact-match", name: "Exact Match", description: "…", type: "string" },
          { id: "contains", name: "Contains", description: "…", type: "string" },
        ],
        total: 2,
      }),
    );
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const scorers = await c.listScorers();
    expect(Array.isArray(scorers)).toBe(true);
    expect(scorers.map((s) => s.id)).toEqual(["exact-match", "contains"]);
  });

  it("listPlugins unwraps { plugins, total } → Plugin[]", async () => {
    const f = mockFetch(
      enveloped({
        plugins: [{ id: "prompt-injection", name: "PI", description: "…", type: "injection" }],
        total: 1,
      }),
    );
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const plugins = await c.listPlugins();
    expect(Array.isArray(plugins)).toBe(true);
    expect(plugins[0].id).toBe("prompt-injection");
  });

  it("tolerates a bare-array response (defensive) too", async () => {
    const f = mockFetch(enveloped([{ id: "a", name: "A", description: "…", type: "string" }]));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const scorers = await c.listScorers();
    expect(scorers.map((s) => s.id)).toEqual(["a"]);
  });
});

describe("SDK E2E fix #2 — listEvals() maps raw rows to the camelCase EvalRun shape", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("normalizes created_at/completed_at/config and scopes projectId", async () => {
    const wireRow = {
      id: "run-1",
      name: "smoke",
      model: "gpt-4o",
      status: "passed",
      score: 0.92,
      config: { prompt: "…", scorers: ["exact-match"] },
      created_at: "2026-07-16T10:00:00.000Z",
      completed_at: "2026-07-16T10:00:05.000Z",
      created_by: "user-1",
      duration: 5000,
    };
    const f = mockFetch(enveloped([wireRow]));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });

    const runs = await c.listEvals("proj-xyz");
    expect(runs).toHaveLength(1);
    const run = runs[0];
    expect(run.id).toBe("run-1");
    expect(run.projectId).toBe("proj-xyz"); // filled from the query scope
    expect(run.status).toBe("passed");
    expect(run.score).toBe(0.92);
    expect(run.createdAt).toBe("2026-07-16T10:00:00.000Z");
    expect(run.completedAt).toBe("2026-07-16T10:00:05.000Z");
    expect(run.duration).toBe(5000);
    expect(run.metadata).toEqual({ prompt: "…", scorers: ["exact-match"] });
    // The snake_case keys must NOT leak through.
    expect((run as unknown as Record<string, unknown>).created_at).toBeUndefined();
    expect((run as unknown as Record<string, unknown>).completed_at).toBeUndefined();
  });

  it("handles a still-running row (null score, no completed_at)", async () => {
    const f = mockFetch(
      enveloped([
        {
          id: "run-2",
          name: "live",
          status: "running",
          score: null,
          config: {},
          created_at: "2026-07-16T11:00:00.000Z",
          completed_at: null,
          duration: null,
        },
      ]),
    );
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const [run] = await c.listEvals("proj-1");
    expect(run.status).toBe("running");
    expect(run.score).toBeNull();
    expect(run.completedAt).toBeUndefined();
    expect(run.duration).toBeNull();
  });

  it("maps max_score when a response happens to include it", async () => {
    const f = mockFetch(
      enveloped([
        {
          id: "run-3",
          name: "m",
          status: "passed",
          score: 88,
          max_score: 100,
          config: {},
          created_at: "2026-07-16T12:00:00.000Z",
        },
      ]),
    );
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const [run] = await c.listEvals("proj-1");
    expect(run.maxScore).toBe(100);
  });
});

describe("SDK E2E fix #4 — securityScan() returns the started-scan stub", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("resolves to { id, status, score, totalTests, duration, severityCounts, findingsCount }", async () => {
    const stub = {
      id: "scan-1",
      status: "failed",
      score: 40,
      totalTests: 12,
      duration: 3200,
      severityCounts: { critical: 1, high: 2, medium: 0, low: 3 },
      findingsCount: 6,
    };
    const f = mockFetch(enveloped(stub));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const scan = await c.securityScan({
      projectId: "proj-1",
      model: "gpt-4o",
      prompt: "You are helpful.",
      attackTypes: ["prompt-injection"],
    });
    // The typed stub fields exist at runtime; results are fetched via getScan(id).
    expect(scan.id).toBe("scan-1");
    expect(scan.status).toBe("failed");
    expect(scan.totalTests).toBe(12);
    expect(scan.severityCounts.critical).toBe(1);
    expect(scan.findingsCount).toBe(6);
  });
});

describe("SDK E2E fix #5 — normalizeApiBaseUrl", () => {
  it("leaves an already-versioned root untouched (and trims trailing slashes)", () => {
    expect(normalizeApiBaseUrl("https://evalguard.ai/api/v1")).toBe("https://evalguard.ai/api/v1");
    expect(normalizeApiBaseUrl("https://evalguard.ai/api/v1/")).toBe("https://evalguard.ai/api/v1");
  });

  it("appends /v1 to a `.../api` base (the docs/env/tracing convention)", () => {
    expect(normalizeApiBaseUrl("https://evalguard.ai/api")).toBe("https://evalguard.ai/api/v1");
    expect(normalizeApiBaseUrl("https://evalguard.ai/api/")).toBe("https://evalguard.ai/api/v1");
    expect(normalizeApiBaseUrl("http://localhost:3000/api")).toBe("http://localhost:3000/api/v1");
  });

  it("appends /api/v1 to a bare origin", () => {
    expect(normalizeApiBaseUrl("https://self-hosted.example.com")).toBe(
      "https://self-hosted.example.com/api/v1",
    );
  });
});
