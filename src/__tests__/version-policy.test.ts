import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, EvalGuardError, SDK_VERSION, VERSION_POLICY_INDETERMINATE_CODE } from "../client";

// Enterprise-managed client version pinning. The SDK consults
// /client/policy?version=<SDK_VERSION> and refuses to run when this SDK version
// is outside the org's pinned range. Unpinned = allowed.
//
// 2026-08-03 (sdk-mcpinvoke-failopen, item 3): a policy that could not be READ
// is no longer reported as `allowed: true`. It used to be — for EVERY failure
// shape: connection refused, timeout, 401/404/500, and a 200 carrying a
// `{success:false,…}` error envelope. The justification in the docstring
// ("the server ALSO sees the version header on every request and can enforce
// there") is false: `checkClientVersion` /
// `gateway_managed_policy.required_min_version` are consulted by exactly one
// route — /api/v1/client/policy, the advisory endpoint this method calls — so
// the client WAS the enforcement point and one black-holed GET disabled
// enterprise version pinning fleet-wide.

function mockFetchOnce(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    headers: { get: () => null },
    json: vi.fn().mockResolvedValue({ success: true, data: body }),
  });
}

/** A raw (un-enveloped) 200 body, for the "the body is not a policy" cases. */
function mockRawOnce(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    headers: { get: () => null },
    json: vi.fn().mockResolvedValue(body),
  });
}

describe("EvalGuard.checkVersionPolicy / assertVersionAllowed", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("sends x-evalguard-client-version on the policy request", async () => {
    const mockFn = mockFetchOnce({ requiredMinimumVersion: null, requiredMaximumVersion: null });
    globalThis.fetch = mockFn;
    await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(mockFn).toHaveBeenCalledWith(
      expect.stringContaining(`/client/policy?version=${encodeURIComponent(SDK_VERSION)}`),
      expect.objectContaining({
        headers: expect.objectContaining({ "x-evalguard-client-version": SDK_VERSION }),
      }),
    );
  });

  it("allows when the org is unpinned (both bounds null) — default behavior", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: null, requiredMaximumVersion: null });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(true);
  });

  it("REFUSES when this SDK version is below the org's required minimum", async () => {
    // SDK_VERSION is 2.1.0; pin a minimum strictly above it.
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: "99.0.0", requiredMaximumVersion: null });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(false);
    expect(r.requiredMinimumVersion).toBe("99.0.0");
    expect(r.reason).toContain("99.0.0");
  });

  it("REFUSES when this SDK version is above the org's required maximum", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: null, requiredMaximumVersion: "0.0.1" });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(false);
    expect(r.requiredMaximumVersion).toBe("0.0.1");
  });

  it("allows when this SDK version is inside the pinned range", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: "0.0.1", requiredMaximumVersion: "99.0.0" });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(true);
  });

  it("assertVersionAllowed throws when out of range", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: "99.0.0", requiredMaximumVersion: null });
    await expect(new EvalGuard({ apiKey: "k" }).assertVersionAllowed()).rejects.toThrow(/below the minimum/);
  });

  it("assertVersionAllowed resolves silently when allowed", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: null, requiredMaximumVersion: null });
    await expect(new EvalGuard({ apiKey: "k" }).assertVersionAllowed()).resolves.toBeUndefined();
  });

  it("prefers the server's own versionCheck verdict when it sends one", async () => {
    globalThis.fetch = mockFetchOnce({
      requiredMinimumVersion: "99.0.0",
      requiredMaximumVersion: null,
      versionCheck: { allowed: false, status: "below_minimum", reason: "server says no" },
    });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe("server says no");
  });
});

// ── The read failed: never a fabricated "allowed" ────────────────────────
describe("checkVersionPolicy — an unreadable policy is INDETERMINATE, not allowed", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  const CASES: Array<[string, () => void]> = [
    ["connection refused / DNS", () => { globalThis.fetch = vi.fn().mockRejectedValue(new Error("fetch failed")); }],
    ["abort / timeout", () => { globalThis.fetch = vi.fn().mockRejectedValue(Object.assign(new Error("aborted"), { name: "AbortError" })); }],
    ["401 revoked key", () => { globalThis.fetch = mockFetchOnce({}, 401, false); }],
    ["404 older server without the route", () => { globalThis.fetch = mockFetchOnce({}, 404, false); }],
    ["500", () => { globalThis.fetch = mockFetchOnce({}, 500, false); }],
    ["200 apiError envelope", () => { globalThis.fetch = mockRawOnce({ success: false, error: { code: "X", message: "upstream timeout" } }); }],
    ["200 { success:true, data:null }", () => { globalThis.fetch = mockRawOnce({ success: true, data: null }); }],
    ["200 empty object", () => { globalThis.fetch = mockRawOnce({}); }],
    ["200 bare string (captive proxy / HTML)", () => { globalThis.fetch = mockRawOnce("<html>gateway timeout</html>"); }],
    ["200 bare array", () => { globalThis.fetch = mockRawOnce([]); }],
    ["200 bounds of the wrong type", () => { globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: 2, requiredMaximumVersion: null }); }],
  ];

  for (const [label, arrange] of CASES) {
    it(`does not claim allowed: ${label}`, async () => {
      arrange();
      const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
      expect(r.allowed).toBe(false);
      expect(r.indeterminate).toBe(true);
      expect(r.reason).toMatch(/INDETERMINATE/);
    });

    it(`assertVersionAllowed hard-stops with a distinguishable code: ${label}`, async () => {
      arrange();
      const err = await new EvalGuard({ apiKey: "k" })
        .assertVersionAllowed()
        .then(() => null, (e: unknown) => e);
      expect(err).toBeInstanceOf(EvalGuardError);
      expect((err as EvalGuardError).code).toBe(VERSION_POLICY_INDETERMINATE_CODE);
    });
  }

  it("a PINNED range the client cannot compare fails closed (unparseable bound)", async () => {
    // `if (ver && minT && …)` silently ALLOWED whenever a bound failed to
    // parse — the server's own checkClientVersion refuses in that case.
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: "v2", requiredMaximumVersion: null });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(false);
    expect(r.indeterminate).toBeUndefined(); // a real policy, just uncomparable
    expect(r.reason).toMatch(/unparseable semver/);
  });

  // OVER-BLOCK CONTROL: the guard must not deny the ordinary cases.
  it("an unpinned org over a reachable endpoint is still ALLOWED", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: null, requiredMaximumVersion: null });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r).toMatchObject({ allowed: true });
    expect(r.indeterminate).toBeUndefined();
  });

  it("an in-range pinned org is still ALLOWED", async () => {
    globalThis.fetch = mockFetchOnce({ requiredMinimumVersion: "0.0.1", requiredMaximumVersion: "99.0.0" });
    const r = await new EvalGuard({ apiKey: "k" }).checkVersionPolicy();
    expect(r.allowed).toBe(true);
  });
});
