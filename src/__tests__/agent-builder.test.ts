import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";
import type { AgentTool } from "../client";

function mockFetch(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: vi.fn().mockResolvedValue(body),
  });
}

/** Wrap a payload in the standard { success, data } API envelope the client unwraps. */
function enveloped(data: unknown) {
  return { success: true, data };
}

const SAMPLE_TOOL: AgentTool = {
  name: "lookup_order",
  description: "Look up an order by id",
  type: "rest",
  parameters: { type: "object", properties: { orderId: { type: "string" } }, required: ["orderId"] },
  rest: { method: "GET", url: "https://api.example.com/orders/{orderId}", timeoutMs: 5000 },
};

describe("EvalGuard SDK — agent-tools CRUD + test", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listAgentTools: GET /agent-tools?projectId and unwraps { tools }", async () => {
    const f = mockFetch(enveloped({ tools: [{ ...SAMPLE_TOOL, id: "t1" }] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.listAgentTools("proj-1");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/agent-tools?");
    expect(url).toContain("projectId=proj-1");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("GET");
    expect(out.tools[0].id).toBe("t1");
  });

  it("listAgentTools: throws on empty projectId before any fetch", async () => {
    const f = mockFetch(enveloped({ tools: [] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.listAgentTools("")).rejects.toThrow(/projectId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("createAgentTool: POST /agent-tools with { projectId, tool }", async () => {
    const f = mockFetch(enveloped({ ...SAMPLE_TOOL, id: "t1", hasSecret: false }), 201);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const created = await c.createAgentTool({ projectId: "p", tool: SAMPLE_TOOL });
    expect(f.mock.calls[0][0]).toContain("/agent-tools");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({
      projectId: "p",
      tool: { name: "lookup_order", type: "rest" },
    });
    expect(created.id).toBe("t1");
  });

  it("createAgentTool: throws when tool missing before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    // @ts-expect-error intentionally omit required tool to assert the guard
    await expect(c.createAgentTool({ projectId: "p" })).rejects.toThrow(/tool/);
    expect(f).not.toHaveBeenCalled();
  });

  it("getAgentTool: GET /agent-tools/{id}?projectId", async () => {
    const f = mockFetch(enveloped({ ...SAMPLE_TOOL, id: "t1" }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.getAgentTool("t1", "proj-1");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/agent-tools/t1?");
    expect(url).toContain("projectId=proj-1");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("GET");
  });

  it("updateAgentTool: PATCH /agent-tools/{id} with the partial body", async () => {
    const f = mockFetch(enveloped({ ...SAMPLE_TOOL, id: "t1", description: "updated" }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.updateAgentTool("t1", { projectId: "p", tool: { description: "updated" } });
    expect(f.mock.calls[0][0]).toContain("/agent-tools/t1");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(String(init.body))).toMatchObject({
      projectId: "p",
      tool: { description: "updated" },
    });
  });

  it("deleteAgentTool: DELETE /agent-tools/{id}?projectId", async () => {
    const f = mockFetch(enveloped({ id: "t1", deleted: true }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.deleteAgentTool("t1", "proj-1");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/agent-tools/t1?");
    expect(url).toContain("projectId=proj-1");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("DELETE");
    expect(out).toEqual({ id: "t1", deleted: true });
  });

  it("testAgentTool: POST /agent-tools/{id}/test with { projectId, args }", async () => {
    const f = mockFetch(enveloped({ ok: true, stage: "request", status: 200, body: { order: "ok" } }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const res = await c.testAgentTool("t1", { projectId: "p", args: { orderId: "o-9" } });
    expect(f.mock.calls[0][0]).toContain("/agent-tools/t1/test");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: "p", args: { orderId: "o-9" } });
    expect(res.ok).toBe(true);
    expect(res.stage).toBe("request");
  });
});

describe("EvalGuard SDK — abuse-reports", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listAbuseReports: GET /abuse-reports?projectId (+ optional status)", async () => {
    const f = mockFetch(enveloped({ reports: [] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.listAbuseReports("proj-1", "open");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/abuse-reports?");
    expect(url).toContain("projectId=proj-1");
    expect(url).toContain("status=open");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("GET");
  });

  it("listAbuseReports: omits status from the query when not supplied", async () => {
    const f = mockFetch(enveloped({ reports: [] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.listAbuseReports("proj-1");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("projectId=proj-1");
    expect(url).not.toContain("status=");
  });

  it("listAbuseReports: throws on empty projectId before any fetch", async () => {
    const f = mockFetch(enveloped({ reports: [] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.listAbuseReports("")).rejects.toThrow(/projectId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("reportAbuse: POST /abuse-reports with the body, returns { report, triage }", async () => {
    const f = mockFetch(
      enveloped({
        report: { id: "r1", projectId: "p", category: "hate", status: "open" },
        triage: {
          severity: "high",
          category: "hate",
          dedupKey: "p:hate:subj",
          autoEscalate: true,
          feedToDetector: true,
          reasons: ["category=hate"],
        },
      }),
      201,
    );
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const res = await c.reportAbuse({ projectId: "p", category: "hate", description: "slur" });
    expect(f.mock.calls[0][0]).toContain("/abuse-reports");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: "p", category: "hate" });
    expect(res.triage.autoEscalate).toBe(true);
    expect(res.report.id).toBe("r1");
  });

  it("reportAbuse: throws when category missing before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    // @ts-expect-error intentionally omit required category to assert the guard
    await expect(c.reportAbuse({ projectId: "p" })).rejects.toThrow(/category/);
    expect(f).not.toHaveBeenCalled();
  });
});

describe("EvalGuard SDK — agent deployments", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listAgentDeployments: GET /workflows/{id}/deploy?projectId", async () => {
    const f = mockFetch(enveloped({ deployments: [] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.listAgentDeployments("wf-1", "proj-1");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/workflows/wf-1/deploy?");
    expect(url).toContain("projectId=proj-1");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("GET");
  });

  it("deployAgent: POST /workflows/{id}/deploy with the channel body", async () => {
    const f = mockFetch(
      enveloped({
        id: "d1",
        workflow_id: "wf-1",
        project_id: "p",
        public_id: "pub_abc",
        channel: "web",
        status: "active",
        allowed_origins: ["https://example.com"],
        greeting: "Hi!",
        created_at: "2026-06-12T00:00:00Z",
        updated_at: null,
      }),
      201,
    );
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const dep = await c.deployAgent("wf-1", {
      projectId: "p",
      channel: "web",
      allowedOrigins: ["https://example.com"],
      greeting: "Hi!",
    });
    expect(f.mock.calls[0][0]).toContain("/workflows/wf-1/deploy");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: "p", channel: "web" });
    expect(dep.public_id).toBe("pub_abc");
  });

  it("deployAgent: throws when channel missing before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    // @ts-expect-error intentionally omit required channel to assert the guard
    await expect(c.deployAgent("wf-1", { projectId: "p" })).rejects.toThrow(/channel/);
    expect(f).not.toHaveBeenCalled();
  });

  it("updateAgentDeployment: PATCH /deployments/{id} with the status body", async () => {
    const f = mockFetch(enveloped({ id: "d1", status: "paused" }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.updateAgentDeployment("d1", { projectId: "p", status: "paused" });
    expect(f.mock.calls[0][0]).toContain("/deployments/d1");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: "p", status: "paused" });
  });

  it("deleteAgentDeployment: DELETE /deployments/{id}?projectId", async () => {
    const f = mockFetch(enveloped({ id: "d1", deleted: true }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.deleteAgentDeployment("d1", "proj-1");
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/deployments/d1?");
    expect(url).toContain("projectId=proj-1");
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("DELETE");
    expect(out).toEqual({ id: "d1", deleted: true });
  });
});
