// Regression — deep audit 2026-07-25 MEDIUM (availability).
//
// The 429 branch of the SDK transport honoured `Retry-After` VERBATIM:
//
//   const delay = retryAfter > 0 ? retryAfter * 1000
//                                : Math.min(1000 * 2 ** attempt, 60000);
//
// The 60s ceiling guarded only the exponential fallback. A server (or an
// intermediary CDN/WAF under load shedding) answering `Retry-After: 3600` put
// the calling goroutine/handler to sleep for an hour, up to maxRetries times —
// the 30s AbortController bounds the fetch, never the sleep. A customer calling
// `await client.checkFirewall(...)` on their request path lost the handler for
// hours with no error and no cancellation.
//
// There was also no jitter on either branch, so a fleet that rate-limits
// together retries in lockstep and re-stampedes the recovering origin.
//
// These tests pin: (1) a hard ceiling, (2) the HTTP-date form of Retry-After is
// understood rather than silently discarded, (3) jitter is present and bounded.

import { describe, expect, it, vi, afterEach } from "vitest";
import { computeRetryDelayMs, MAX_RETRY_DELAY_MS } from "../client";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Pin Math.random so the jitter factor is deterministic per-case. */
function withRandom<T>(value: number, fn: () => T): T {
  const spy = vi.spyOn(Math, "random").mockReturnValue(value);
  try {
    return fn();
  } finally {
    spy.mockRestore();
  }
}

describe("computeRetryDelayMs", () => {
  it("CLAMPS a hostile Retry-After to the ceiling instead of sleeping for an hour", () => {
    // random() = 1 → jitter factor 1.0, i.e. the maximum this can ever return.
    const delay = withRandom(0.999999, () => computeRetryDelayMs("3600", 0));
    expect(delay).toBeLessThanOrEqual(MAX_RETRY_DELAY_MS);
    // The pre-fix code returned 3_600_000 here.
    expect(delay).toBeLessThan(3_600_000);
  });

  it("never exceeds the ceiling for any attempt or header value", () => {
    for (const header of [null, "0", "1", "120", "86400", "not-a-number"]) {
      for (let attempt = 0; attempt < 8; attempt++) {
        const delay = withRandom(0.999999, () => computeRetryDelayMs(header, attempt));
        expect(delay).toBeLessThanOrEqual(MAX_RETRY_DELAY_MS);
        expect(delay).toBeGreaterThanOrEqual(0);
      }
    }
  });

  it("honours a short Retry-After (the hint can shorten, just not extend)", () => {
    // 2s, jitter factor 1.0 → 2000ms.
    const delay = withRandom(0.999999, () => computeRetryDelayMs("2", 0));
    expect(delay).toBeGreaterThan(1_000);
    expect(delay).toBeLessThanOrEqual(2_000);
  });

  it("understands the HTTP-date form of Retry-After (parseInt yielded NaN before)", () => {
    const now = Date.parse("2026-07-25T00:00:00Z");
    const at = new Date(now + 10_000).toUTCString();
    const delay = withRandom(0.999999, () => computeRetryDelayMs(at, 0, now));
    // ~10s, clamped under the ceiling — not silently dropped to the
    // exponential fallback.
    expect(delay).toBeGreaterThan(5_000);
    expect(delay).toBeLessThanOrEqual(10_000);
  });

  it("applies jitter so clients do not retry in lockstep", () => {
    const low = withRandom(0, () => computeRetryDelayMs("30", 0));
    const high = withRandom(0.999999, () => computeRetryDelayMs("30", 0));
    expect(low).toBeLessThan(high);
    // Bounded at ±50% of the base, never zero.
    expect(low).toBeGreaterThanOrEqual(30_000 * 0.5 - 1);
    expect(high).toBeLessThanOrEqual(30_000);
  });

  it("falls back to bounded exponential backoff when the header is absent", () => {
    const a0 = withRandom(0.999999, () => computeRetryDelayMs(null, 0));
    const a1 = withRandom(0.999999, () => computeRetryDelayMs(null, 1));
    expect(a0).toBeLessThanOrEqual(1_000);
    expect(a1).toBeLessThanOrEqual(2_000);
    expect(a1).toBeGreaterThan(a0);
  });
});
