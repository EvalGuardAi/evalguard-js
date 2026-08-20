import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

// Regression tests for the live-E2E SDK fixes (2026-07-15):
//   #1 no-body writes must send `{}` (not a bare no-body POST/PATCH) so the
//      server doesn't 400 "Invalid JSON body" — searchDSR / exportDSR / revokeConsent.
//   #3 createDataSource must include the required `orgId`.
// (Bug #2 — getSecurityReport uses `assessmentId` not `scanId` — is asserted in
//  parity-runtime-methods.test.ts; bugs #4/#5 in sdk.test.ts / agent-builder.test.ts.)

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

describe("SDK E2E fix #1 — no-body writes send an empty JSON object", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("searchDSR: POST /privacy/dsr/{id}/search with body '{}' (not undefined)", async () => {
    const f = mockFetch(enveloped({ found: 0, summary: {}, next: "" }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.searchDSR("dsr-1");
    const url = f.mock.calls[0][0] as string;
    const init = f.mock.calls[0][1] as RequestInit;
    expect(url).toContain("/privacy/dsr/dsr-1/search");
    expect(init.method).toBe("POST");
    // The load-bearing assertion: an empty JSON body, NOT undefined.
    expect(init.body).toBe("{}");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("exportDSR: POST /privacy/dsr/{id}/export with body '{}'", async () => {
    const f = mockFetch(enveloped({ ok: true }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.exportDSR("dsr-2");
    const url = f.mock.calls[0][0] as string;
    const init = f.mock.calls[0][1] as RequestInit;
    expect(url).toContain("/privacy/dsr/dsr-2/export");
    expect(init.method).toBe("POST");
    expect(init.body).toBe("{}");
  });

  it("revokeConsent: PATCH /privacy/consent?id={id} with body '{}'", async () => {
    const f = mockFetch(enveloped({ ok: true }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.revokeConsent("consent-9");
    const url = f.mock.calls[0][0] as string;
    const init = f.mock.calls[0][1] as RequestInit;
    expect(url).toContain("/privacy/consent?id=consent-9");
    expect(init.method).toBe("PATCH");
    expect(init.body).toBe("{}");
  });
});

describe("SDK E2E fix #3 — createDataSource includes the required orgId", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("sends the explicit orgId in the POST body (no /project/current lookup)", async () => {
    const f = mockFetch(enveloped({ id: "src-1" }), 201);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.createDataSource({
      orgId: "org-explicit",
      name: "prod-s3",
      connector_type: "s3",
      config: { bucket: "b" },
    });
    // Only ONE call — the explicit orgId skips the resolve fetch.
    expect(f).toHaveBeenCalledTimes(1);
    const url = f.mock.calls[0][0] as string;
    const init = f.mock.calls[0][1] as RequestInit;
    expect(url).toContain("/data-discovery/sources");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(String(init.body));
    expect(sent.orgId).toBe("org-explicit");
    expect(sent.name).toBe("prod-s3");
    expect(sent.connector_type).toBe("s3");
  });

  it("resolves orgId from /project/current when omitted, then POSTs with it", async () => {
    const f = vi
      .fn()
      // 1) resolveOrgId → GET /project/current returns RAW { projectId, orgId }
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: "OK",
        json: vi.fn().mockResolvedValue({ projectId: "proj-1", orgId: "org-resolved" }),
      })
      // 2) POST /data-discovery/sources (enveloped)
      .mockResolvedValueOnce({
        ok: true,
        status: 201,
        statusText: "OK",
        json: vi.fn().mockResolvedValue(enveloped({ id: "src-2" })),
      });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.createDataSource({
      name: "snow",
      connector_type: "snowflake",
      config: {},
    });

    expect(f).toHaveBeenCalledTimes(2);
    expect(f.mock.calls[0][0]).toContain("/project/current");
    const postUrl = f.mock.calls[1][0] as string;
    const postInit = f.mock.calls[1][1] as RequestInit;
    expect(postUrl).toContain("/data-discovery/sources");
    expect(postInit.method).toBe("POST");
    expect(JSON.parse(String(postInit.body)).orgId).toBe("org-resolved");
  });
});
