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

describe("EvalGuard SDK — Evaluator Hub + CLHF", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listEvaluators: GET /evaluators with projectId (+ optional name)", async () => {
    const f = mockFetch([{ name: "faithfulness", version: 2 }]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.listEvaluators("proj-1", "faithfulness");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/evaluators?");
    expect(url).toContain("projectId=proj-1");
    expect(url).toContain("name=faithfulness");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("GET");
  });

  it("listEvaluators: throws on empty projectId before any fetch", async () => {
    const f = mockFetch([]);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.listEvaluators("")).rejects.toThrow(/projectId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("createEvaluator: POST /evaluators with the definition body", async () => {
    const f = mockFetch({ id: "v1", version: 1 });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.createEvaluator({
      projectId: "p",
      name: "faithfulness",
      definition: { kind: "llm-judge", threshold: 0.7 },
    });
    expect(f.mock.calls[0][0]).toContain("/evaluators");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({
      projectId: "p",
      name: "faithfulness",
      definition: { kind: "llm-judge" },
    });
  });

  it("diffEvaluatorVersions: POST /evaluators/diff with the version pair", async () => {
    const f = mockFetch({ diff: { changed: true } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.diffEvaluatorVersions({ projectId: "p", name: "faithfulness", fromVersion: 1, toVersion: 2 });
    expect(f.mock.calls[0][0]).toContain("/evaluators/diff");
    expect(JSON.parse(String((f.mock.calls[0][1] as RequestInit).body))).toMatchObject({
      fromVersion: 1,
      toVersion: 2,
    });
  });

  it("calibrateScorer: POST /scorers/calibrate, and rejects when no data supplied", async () => {
    const f = mockFetch({ scorerId: null, agreement: { kappa: 0.8, accuracy: 0.9, confusion: {} } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.calibrateScorer({ pairs: [{ human: true, machine: true }] });
    expect(f.mock.calls[0][0]).toContain("/scorers/calibrate");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("POST");
    await expect(c.calibrateScorer({})).rejects.toThrow(/pairs|scored/);
  });
});
