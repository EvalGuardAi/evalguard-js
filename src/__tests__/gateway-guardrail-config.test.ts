import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, LOCAL_GUARDRAIL_VENDORS, isLocalGuardrailVendor } from "../client";

/**
 * Coverage for the gateway guardrail-config client methods
 * (listGuardrailConfigs / upsertGuardrailConfig / deleteGuardrailConfig). Each
 * test mocks global fetch and asserts the SDK hits /gateway/guardrails with the
 * right verb + query/body, normalizes the raw snake_case rows the route returns
 * into the camelCase GuardrailConfigRecord shape, and models the local-vs-vendor
 * secretRef rule client-side. The live route requires the migration applied +
 * admin auth; these are mocked-HTTP contract tests (no server), the expected SDK
 * verification.
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
const SECRET = "33333333-3333-3333-3333-333333333333";
const ROW_ID = "44444444-4444-4444-4444-444444444444";

// Raw snake_case row exactly as the route projects the DB columns.
function wireRow(overrides: Record<string, unknown> = {}) {
  return {
    id: ROW_ID,
    org_id: ORG,
    project_id: PROJ,
    vendor: "data-not-instructions",
    vendor_chain: ["data-not-instructions"],
    fallback_on_errors: null,
    config: { profile: "strict" },
    secret_ref: null,
    on_flag: "block",
    check_request: true,
    check_response: false,
    tokenize_pii: false,
    enabled: true,
    priority: 100,
    created_at: "2026-07-17T00:00:00.000Z",
    updated_at: "2026-07-17T00:00:00.000Z",
    ...overrides,
  };
}

describe("EvalGuard SDK — gateway guardrail config", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("exposes the four canonical local vendors incl. the two Wave-2 agent guardrails", () => {
    expect([...LOCAL_GUARDRAIL_VENDORS]).toEqual([
      "local-firewall",
      "moderated-firewall",
      "data-not-instructions",
      "tool-call-circuit-breaker",
    ]);
    expect(isLocalGuardrailVendor("data-not-instructions")).toBe(true);
    expect(isLocalGuardrailVendor("tool-call-circuit-breaker")).toBe(true);
    expect(isLocalGuardrailVendor("aporia")).toBe(false);
  });

  it("listGuardrailConfigs: GET /gateway/guardrails?projectId and normalizes snake_case rows to camelCase", async () => {
    const f = mockFetch(enveloped([wireRow(), wireRow({ id: "row-2", vendor: "aporia", secret_ref: SECRET, priority: 200 })]));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.listGuardrailConfigs(PROJ);
    const [url, init] = lastCall(f);
    expect(url).toContain("/gateway/guardrails?projectId=");
    expect(url).toContain(PROJ);
    expect(init.method).toBe("GET");
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({
      id: ROW_ID,
      orgId: ORG,
      projectId: PROJ,
      vendor: "data-not-instructions",
      secretRef: null,
      onFlag: "block",
      checkRequest: true,
      checkResponse: false,
      tokenizePii: false,
      enabled: true,
      priority: 100,
      createdAt: "2026-07-17T00:00:00.000Z",
      updatedAt: "2026-07-17T00:00:00.000Z",
    });
    // No raw snake_case keys leak through the normalizer.
    expect((out[0] as unknown as Record<string, unknown>).org_id).toBeUndefined();
    expect(out[1].vendor).toBe("aporia");
    expect(out[1].secretRef).toBe(SECRET);
  });

  it("listGuardrailConfigs: returns [] when the project has no rows", async () => {
    const f = mockFetch(enveloped([]));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    expect(await c.listGuardrailConfigs(PROJ)).toEqual([]);
  });

  it("listGuardrailConfigs: throws before any fetch when projectId is missing", async () => {
    const f = mockFetch(enveloped([]));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.listGuardrailConfigs("")).rejects.toThrow(/projectId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("upsertGuardrailConfig: POST /gateway/guardrails for a local vendor WITHOUT a secretRef", async () => {
    const f = mockFetch(enveloped(wireRow()), 201);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.upsertGuardrailConfig({
      orgId: ORG,
      projectId: PROJ,
      vendor: "tool-call-circuit-breaker",
      onFlag: "block",
      checkRequest: true,
    });
    const [url, init] = lastCall(f);
    expect(url).toContain("/gateway/guardrails");
    expect(url).not.toContain("?");
    expect(init.method).toBe("POST");
    const sent = JSON.parse(String(init.body));
    expect(sent).toMatchObject({
      orgId: ORG,
      projectId: PROJ,
      vendor: "tool-call-circuit-breaker",
      onFlag: "block",
      checkRequest: true,
    });
    // A local vendor must never carry a secretRef on the wire.
    expect("secretRef" in sent).toBe(false);
    expect(out.orgId).toBe(ORG);
    expect(out.secretRef).toBeNull();
  });

  it("upsertGuardrailConfig: sends the secretRef for a vendor adapter", async () => {
    const f = mockFetch(enveloped(wireRow({ vendor: "aporia", secret_ref: SECRET })), 201);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.upsertGuardrailConfig({
      orgId: ORG,
      projectId: PROJ,
      vendor: "aporia",
      secretRef: SECRET,
    });
    const [, init] = lastCall(f);
    expect(JSON.parse(String(init.body))).toMatchObject({ vendor: "aporia", secretRef: SECRET });
    expect(out.secretRef).toBe(SECRET);
  });

  it("upsertGuardrailConfig: throws before any fetch when a local vendor is given a secretRef", async () => {
    const f = mockFetch(enveloped(wireRow()));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      c.upsertGuardrailConfig({ orgId: ORG, projectId: PROJ, vendor: "data-not-instructions", secretRef: SECRET }),
    ).rejects.toThrow(/must not carry a secretRef/);
    expect(f).not.toHaveBeenCalled();
  });

  it("upsertGuardrailConfig: throws before any fetch when a vendor adapter lacks a secretRef", async () => {
    const f = mockFetch(enveloped(wireRow()));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      c.upsertGuardrailConfig({ orgId: ORG, projectId: PROJ, vendor: "lakera" }),
    ).rejects.toThrow(/requires a secretRef/);
    expect(f).not.toHaveBeenCalled();
  });

  it("upsertGuardrailConfig: throws when vendorChain[0] does not equal the primary vendor", async () => {
    const f = mockFetch(enveloped(wireRow()));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      c.upsertGuardrailConfig({
        orgId: ORG,
        projectId: PROJ,
        vendor: "aporia",
        secretRef: SECRET,
        vendorChain: ["lakera", "aporia"],
      }),
    ).rejects.toThrow(/must equal vendor/);
    expect(f).not.toHaveBeenCalled();
  });

  it("upsertGuardrailConfig: throws before any fetch when orgId is missing", async () => {
    const f = mockFetch(enveloped(wireRow()));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      c.upsertGuardrailConfig({ orgId: "", projectId: PROJ, vendor: "local-firewall" }),
    ).rejects.toThrow(/orgId/);
    expect(f).not.toHaveBeenCalled();
  });

  it("deleteGuardrailConfig: DELETE /gateway/guardrails?projectId&id and unwraps { deleted }", async () => {
    const f = mockFetch(enveloped({ deleted: ROW_ID }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.deleteGuardrailConfig({ projectId: PROJ, id: ROW_ID });
    const [url, init] = lastCall(f);
    expect(url).toContain("/gateway/guardrails?");
    expect(url).toContain(`projectId=${PROJ}`);
    expect(url).toContain(`id=${ROW_ID}`);
    expect(init.method).toBe("DELETE");
    expect(out.deleted).toBe(ROW_ID);
  });

  it("deleteGuardrailConfig: throws before any fetch when id is missing", async () => {
    const f = mockFetch(enveloped({ deleted: ROW_ID }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.deleteGuardrailConfig({ projectId: PROJ, id: "" })).rejects.toThrow(/id/);
    expect(f).not.toHaveBeenCalled();
  });
});
