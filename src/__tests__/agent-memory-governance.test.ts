import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

/**
 * Coverage for the agent memory-governance policy client methods
 * (getMemoryGovernancePolicy / setMemoryGovernancePolicy /
 * deleteMemoryGovernancePolicy). Each test mocks global fetch and asserts the
 * SDK hits /agent-memory/governance with the right verb + query/body and unwraps
 * the standard { success, data } envelope the route returns. The live route
 * requires the migration to be applied + admin auth; these are mocked-HTTP
 * contract tests (no server), which is the expected SDK verification.
 */

function mockFetch(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    headers: { get: () => null },
    json: vi.fn().mockResolvedValue(body),
    text: vi.fn().mockResolvedValue(typeof body === "string" ? body : JSON.stringify(body)),
  });
}
function enveloped(data: unknown) {
  return { success: true, data };
}
function lastCall(f: ReturnType<typeof vi.fn>): [string, RequestInit] {
  return f.mock.calls[f.mock.calls.length - 1] as [string, RequestInit];
}

const ORG = "11111111-1111-1111-1111-111111111111";
const PROJ = "22222222-2222-2222-2222-222222222222";

const policy = {
  id: "p-1",
  orgId: ORG,
  projectId: null,
  enabled: true,
  mode: "monitor",
  config: { thresholds: { poisonMinConfidence: 0.3 }, requireApprovalOnRewrite: true, requireProvenance: false },
  createdBy: "u-1",
  createdAt: "2026-07-17T00:00:00.000Z",
  updatedAt: "2026-07-17T00:00:00.000Z",
};

describe("EvalGuard SDK — agent memory governance", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("getMemoryGovernancePolicy: GET /agent-memory/governance with orgId, unwraps { policy }", async () => {
    const f = mockFetch(enveloped({ policy }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.getMemoryGovernancePolicy({ orgId: ORG });
    const [url, init] = lastCall(f);
    expect(url).toContain("/agent-memory/governance?");
    expect(url).toContain(`orgId=${ORG}`);
    expect(url).not.toContain("projectId=");
    expect(init.method).toBe("GET");
    expect(out.policy?.mode).toBe("monitor");
    expect(out.policy?.config.thresholds?.poisonMinConfidence).toBe(0.3);
  });

  it("getMemoryGovernancePolicy: adds projectId to the query when scoped", async () => {
    const f = mockFetch(enveloped({ policy: { ...policy, projectId: PROJ } }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.getMemoryGovernancePolicy({ orgId: ORG, projectId: PROJ });
    const [url] = lastCall(f);
    expect(url).toContain(`orgId=${ORG}`);
    expect(url).toContain(`projectId=${PROJ}`);
    expect(out.policy?.projectId).toBe(PROJ);
  });

  it("getMemoryGovernancePolicy: returns { policy: null } when none set", async () => {
    const f = mockFetch(enveloped({ policy: null }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.getMemoryGovernancePolicy({ orgId: ORG });
    expect(out.policy).toBeNull();
  });

  it("getMemoryGovernancePolicy: throws before any fetch when orgId is missing", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.getMemoryGovernancePolicy({ orgId: "" })).rejects.toThrow(/orgId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("setMemoryGovernancePolicy: PUT /agent-memory/governance with the policy body", async () => {
    const f = mockFetch(enveloped({ policy: { ...policy, mode: "enforce" } }), 200);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.setMemoryGovernancePolicy({
      orgId: ORG,
      enabled: true,
      mode: "enforce",
      config: { requireProvenance: true },
    });
    const [url, init] = lastCall(f);
    expect(url).toContain("/agent-memory/governance");
    expect(url).not.toContain("?");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(String(init.body))).toMatchObject({
      orgId: ORG,
      enabled: true,
      mode: "enforce",
      config: { requireProvenance: true },
    });
    expect(out.policy.mode).toBe("enforce");
  });

  it("setMemoryGovernancePolicy: throws before any fetch when orgId is missing", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.setMemoryGovernancePolicy({ orgId: "", mode: "monitor" })).rejects.toThrow(/orgId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("deleteMemoryGovernancePolicy: DELETE /agent-memory/governance and unwraps { deleted }", async () => {
    const f = mockFetch(enveloped({ deleted: true }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.deleteMemoryGovernancePolicy({ orgId: ORG, projectId: PROJ });
    const [url, init] = lastCall(f);
    expect(url).toContain("/agent-memory/governance?");
    expect(url).toContain(`orgId=${ORG}`);
    expect(url).toContain(`projectId=${PROJ}`);
    expect(init.method).toBe("DELETE");
    expect(out.deleted).toBe(true);
  });

  it("deleteMemoryGovernancePolicy: throws before any fetch when orgId is missing", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.deleteMemoryGovernancePolicy({ orgId: "" })).rejects.toThrow(/orgId/);
    expect(f).not.toHaveBeenCalled();
  });
});
