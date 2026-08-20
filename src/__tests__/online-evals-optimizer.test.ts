import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

function mockFetch(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: vi.fn().mockResolvedValue(body),
  });
}

describe("EvalGuard SDK — online evals", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listOnlineEvals GETs /online-evals with projectId + window params (envelope unwrap)", async () => {
    const f = mockFetch({
      success: true,
      data: {
        samplers: [],
        recentResults: [{ id: "r1", sampler_id: "s1", scorer_key: "faithfulness", score: 0.9, passed: true, duration_ms: 12, error: null, occurred_at: "2026-07-01T00:00:00Z" }],
        aggregates: { faithfulness: { total: 1, passRate: 1, errorRate: 0, p95DurationMs: 12 } },
        windowSince: "2026-06-24T00:00:00Z",
      },
    });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.listOnlineEvals("proj-1", { resultsLimit: 100 });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/online-evals?");
    expect(url).toContain("projectId=proj-1");
    expect(url).toContain("resultsLimit=100");
    expect(init.method).toBe("GET");
    expect(out.aggregates.faithfulness.passRate).toBe(1);
    expect(out.recentResults[0].scorer_key).toBe("faithfulness");
  });

  it("listOnlineEvals throws before fetch when projectId is empty", async () => {
    const f = mockFetch({ success: true, data: {} });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.listOnlineEvals("")).rejects.toThrow(/projectId/i);
    expect(f).not.toHaveBeenCalled();
  });

  it("listOnlineEvalSamplers GETs /online-eval-samplers by orgId (bare response, no envelope)", async () => {
    const f = mockFetch({
      samplers: [
        { id: "s1", project_id: "p1", name: "prod-faith", enabled: true, sample_rate: 0.05, max_per_hour: 100, scorer_keys: ["faithfulness"], model_filter: [], execution_mode: "sync", last_run_at: null, last_run_sampled: null, last_run_scored: null, last_run_skipped: null, created_at: "x", updated_at: "y" },
      ],
      count: 1,
    });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.listOnlineEvalSamplers("org-1");

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/online-eval-samplers?orgId=org-1");
    expect(init.method).toBe("GET");
    expect(out.count).toBe(1);
    expect(out.samplers[0].name).toBe("prod-faith");
  });

  it("createOnlineEvalSampler POSTs the body to /online-eval-samplers", async () => {
    const f = mockFetch({ ok: true, id: "s-new", name: "prod-faith" });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.createOnlineEvalSampler({
      projectId: "p1",
      name: "prod-faith",
      sample_rate: 0.1,
      scorer_keys: ["faithfulness"],
    });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/online-eval-samplers");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.name).toBe("prod-faith");
    expect(sent.sample_rate).toBe(0.1);
    expect(out.id).toBe("s-new");
  });

  it("createOnlineEvalSampler throws before fetch without projectId/name", async () => {
    const f = mockFetch({ ok: true });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    // @ts-expect-error — exercising runtime guard
    await expect(c.createOnlineEvalSampler({ name: "x" })).rejects.toThrow(/projectId/i);
    // @ts-expect-error — exercising runtime guard
    await expect(c.createOnlineEvalSampler({ projectId: "p1" })).rejects.toThrow(/name/i);
    expect(f).not.toHaveBeenCalled();
  });

  it("updateOnlineEvalSampler PATCHes /online-eval-samplers/:id and rejects an empty patch", async () => {
    const f = mockFetch({ ok: true, id: "s1", fields: ["enabled"] });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.updateOnlineEvalSampler("s1", { enabled: false });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/online-eval-samplers/s1");
    expect(init.method).toBe("PATCH");
    expect(out.fields).toContain("enabled");
    await expect(c.updateOnlineEvalSampler("s1", {})).rejects.toThrow(/at least one field/i);
  });

  it("deleteOnlineEvalSampler DELETEs /online-eval-samplers/:id", async () => {
    const f = mockFetch({ ok: true, id: "s1" });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.deleteOnlineEvalSampler("s1");

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/online-eval-samplers/s1");
    expect(init.method).toBe("DELETE");
    expect(out.ok).toBe(true);
  });
});

describe("EvalGuard SDK — prompt optimizer", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("optimizePrompt POSTs /prompts/optimize and unwraps the result envelope", async () => {
    const f = mockFetch({
      success: true,
      data: {
        optimizedPrompt: "Answer concisely: {{input}}",
        originalScore: 0.6,
        optimizedScore: 0.9,
        improvementPercent: 50,
        strategy: "meta-prompt",
        iterations: 3,
        changelog: [{ step: 1 }],
        durationMs: 4200,
        targetModel: "gpt-4o-mini",
        costUsd: 0.012,
      },
    });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.optimizePrompt({
      projectId: "p1",
      prompt: "Answer: {{input}}",
      strategy: "meta-prompt",
      evalCases: [{ input: "2+2?", expectedOutput: "4" }],
      scorers: ["exact-match"],
      targetModel: "gpt-4o-mini",
    });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/prompts/optimize");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.strategy).toBe("meta-prompt");
    expect(sent.evalCases[0].input).toBe("2+2?");
    expect(out.optimizedScore).toBe(0.9);
    expect(out.improvementPercent).toBe(50);
  });

  it("optimizePrompt validates required inputs before any fetch", async () => {
    const f = mockFetch({ success: true, data: {} });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      // @ts-expect-error — exercising runtime guard
      c.optimizePrompt({ prompt: "x", strategy: "meta-prompt", evalCases: [{ input: "a" }], scorers: ["exact-match"] }),
    ).rejects.toThrow(/projectId/i);
    await expect(
      c.optimizePrompt({ projectId: "p1", prompt: "   ", strategy: "meta-prompt", evalCases: [{ input: "a" }], scorers: ["exact-match"] }),
    ).rejects.toThrow(/prompt/i);
    await expect(
      c.optimizePrompt({ projectId: "p1", prompt: "x", strategy: "meta-prompt", evalCases: [], scorers: ["exact-match"] }),
    ).rejects.toThrow(/evalCase/i);
    expect(f).not.toHaveBeenCalled();
  });
});
