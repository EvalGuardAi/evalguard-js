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
function enveloped(data: unknown) {
  return { success: true, data };
}

describe("EvalGuard SDK — AI-SBOM supply-chain scan", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("generateAISBOM: POST /ai-sbom/generate with projectName (the required field)", async () => {
    const f = mockFetch(enveloped({ format: "EvalGuard-AIBOM", bom: {} }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.generateAISBOM("my-app");
    expect(f.mock.calls[0][0]).toContain("/ai-sbom/generate");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectName: "my-app" });
  });

  it("generateAISBOM: forwards manifests, lockfiles and liveCveScan", async () => {
    const f = mockFetch(enveloped({ format: "EvalGuard-AIBOM", bom: {}, supplyChain: { typosquats: [] } }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.generateAISBOM("my-app", {
      projectVersion: "2.0.0",
      format: "cyclonedx",
      packageJson: { dependencies: { openai: "^4.0.0" } },
      packageLockJson: { lockfileVersion: 3, packages: {} },
      pythonRequirements: "torch==2.0.0",
      poetryLock: '[[package]]\nname = "requests"\nversion = "2.31.0"',
      liveCveScan: false,
    });
    const body = JSON.parse(String((f.mock.calls[0][1] as RequestInit).body));
    expect(body).toMatchObject({
      projectName: "my-app",
      projectVersion: "2.0.0",
      format: "cyclonedx",
      liveCveScan: false,
    });
    expect(body.packageLockJson).toEqual({ lockfileVersion: 3, packages: {} });
    expect(body.pythonRequirements).toBe("torch==2.0.0");
    expect(body.poetryLock).toContain("requests");
  });
});
