import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

function mockFetch(body: unknown) {
  return vi.fn().mockResolvedValue({ ok: true, status: 200, statusText: "OK", json: vi.fn().mockResolvedValue(body) });
}
const enveloped = (data: unknown) => ({ success: true, data });

describe("EvalGuard SDK — agent communication graph", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("getAgentGraph: GET /traces/graph with window", async () => {
    const f = mockFetch(enveloped({ services: ["a", "b"], edges: [{ from: "a", to: "b", callCount: 3, errorCount: 0, avgLatencyMs: 12 }], totalCalls: 3, totalErrors: 0, windowHours: 168, spanCount: 9 }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.getAgentGraph({ projectId: "p", windowHours: 168 });
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/traces/graph?");
    expect(url).toContain("windowHours=168");
    expect(out.edges[0].from).toBe("a");
    expect(out.totalCalls).toBe(3);
  });

  it("getAgentGraph: throws on missing projectId before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.getAgentGraph({ projectId: "" })).rejects.toThrow(/projectId/);
    expect(f).not.toHaveBeenCalled();
  });
});
