import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, SDK_VERSION } from "../client";

// Enterprise-managed client version pinning. The SDK consults
// /client/policy?version=<SDK_VERSION> and refuses to run when this SDK version
// is outside the org's pinned range. Unpinned / unreachable = allowed.

function mockFetchOnce(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    headers: { get: () => null },
    json: vi.fn().mockResolvedValue({ success: true, data: body }),
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

  it("fail-open: a network error on the policy read does not brick the client", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network down"));
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
});
