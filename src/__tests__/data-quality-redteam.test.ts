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

describe("EvalGuard SDK — datasetHealth + planRedTeam", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("datasetHealth: POSTs to /datasets/health and unwraps the data envelope", async () => {
    const f = mockFetch({ success: true, data: { health: { rowCount: 4, nonIid: { score: 0.2, nonIid: true } } } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.datasetHealth({ labels: [0, 0, 0, 1], embeddings: [[1, 0], [0.99, 0.01], [0.98, 0], [0, 1]] });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/datasets/health");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(init.body as string);
    expect(sent.labels).toEqual([0, 0, 0, 1]);
    expect(out.health.rowCount).toBe(4);
    expect(out.health.nonIid?.nonIid).toBe(true);
  });

  it("datasetHealth: throws before any fetch when no labels/embeddings/features", async () => {
    const f = mockFetch({ success: true, data: {} });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.datasetHealth({})).rejects.toThrow(/at least one of/);
    expect(f).not.toHaveBeenCalled();
  });

  it("planRedTeam: POSTs capabilities to /security/red-team-plan and unwraps the plan", async () => {
    const f = mockFetch({
      success: true,
      data: { plan: { categories: [{ id: "mcp-attack", name: "MCP", pluginCount: 3 }], plugins: [], totalPlugins: 3 } },
    });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.planRedTeam({ usesMcp: true });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/security/red-team-plan");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string).usesMcp).toBe(true);
    expect(out.plan.totalPlugins).toBe(3);
  });

  it("planRedTeam: defaults to an empty-capabilities body", async () => {
    const f = mockFetch({ success: true, data: { plan: { categories: [], plugins: [], totalPlugins: 0 } } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.planRedTeam();
    expect(JSON.parse((f.mock.calls[0][1] as RequestInit).body as string)).toEqual({});
  });
});
