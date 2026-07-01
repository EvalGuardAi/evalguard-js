import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

function mockFetch(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({ ok, status, statusText: ok ? "OK" : "Error", json: vi.fn().mockResolvedValue(body) });
}
const enveloped = (data: unknown) => ({ success: true, data });

describe("EvalGuard SDK — MCP pre-deploy audit", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("auditMcpServer: POST /security/mcp-predeployment-audit with server + tools", async () => {
    const f = mockFetch(enveloped({ verdict: "block", riskScore: 60, toolCount: 1, findings: [], summary: { critical: 1, high: 0, medium: 0, low: 0, total: 1 }, attestation: { signedOff: false } }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.auditMcpServer({ projectId: "p", server: { id: "s", authSchemes: [] }, tools: [{ name: "x" }] });
    expect(f.mock.calls[0][0]).toContain("/security/mcp-predeployment-audit");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: "p", server: { id: "s" }, tools: [{ name: "x" }] });
    expect(out.verdict).toBe("block");
  });

  it("auditMcpServer: throws on missing server before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.auditMcpServer({ projectId: "p", server: undefined as unknown as Record<string, unknown> })).rejects.toThrow(/server/);
    expect(f).not.toHaveBeenCalled();
  });

  it("runAgentExecRedTeam: POST /security/agent-exec-redteam with snake_case params", async () => {
    const f = mockFetch(enveloped({ totalAttacks: 5, dangerousAttempts: 2, breaches: 1, verdict: "breached", attacks: [], tools: ["delete_account"] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.runAgentExecRedTeam({ projectId: "p", targetProvider: "openai", targetModel: "gpt-4o-mini" });
    expect(f.mock.calls[0][0]).toContain("/security/agent-exec-redteam");
    expect(JSON.parse(String((f.mock.calls[0][1] as RequestInit).body))).toMatchObject({ projectId: "p", target_provider: "openai", target_model: "gpt-4o-mini" });
    expect(out.verdict).toBe("breached");
    expect(out.breaches).toBe(1);
  });

  it("runAgentExecRedTeam: throws on missing target before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.runAgentExecRedTeam({ projectId: "p", targetProvider: "", targetModel: "" })).rejects.toThrow(/target/);
    expect(f).not.toHaveBeenCalled();
  });
});
