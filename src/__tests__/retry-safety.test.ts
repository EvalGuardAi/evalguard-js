import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, EvalGuardError, isRetriableRequest } from "../client";

/**
 * The SDK stamps an `Idempotency-Key` on every write, but the SERVER only
 * honours it on routes that opt into `idempotent: true`
 * (apps/web/src/lib/api-handler.ts) — a handful of them, not the ~340 write
 * routes. Retrying a 5xx or a dropped connection on the rest re-executes the
 * write: `createApiKey` mints a SECOND credential, and the caller only ever
 * sees the second response. nginx returning 502 with the response in flight is
 * routine during a deploy, so this is not a rare path (audit 2026-07-25).
 */

function fetchAlways(status: number, body: unknown = { success: true, data: {} }) {
  return vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    statusText: status < 400 ? "OK" : "Error",
    headers: { get: () => null },
    json: vi.fn().mockResolvedValue(body),
  });
}

describe("SDK retry safety — non-idempotent writes are not replayed", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("does NOT retry POST /api-keys on 502 — one attempt, one credential", async () => {
    const fetchMock = fetchAlways(502, { success: false, error: { message: "Bad Gateway" } });
    globalThis.fetch = fetchMock;

    const client = new EvalGuard({ apiKey: "key" });
    const err = await client
      .createApiKey({ orgId: "org-1", name: "ci" })
      .catch((e) => e as EvalGuardError);

    expect(err).toBeInstanceOf(EvalGuardError);
    expect((err as EvalGuardError).status).toBe(502);
    // THE assertion: exactly one POST reached the server. Blind retry made this
    // 4, i.e. up to 4 API keys for one createApiKey() call.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry POST /api-keys on a dropped connection", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("fetch failed"));
    globalThis.fetch = fetchMock;

    const client = new EvalGuard({ apiKey: "key" });
    const err = await client
      .createApiKey({ orgId: "org-1", name: "ci" })
      .catch((e) => e as EvalGuardError);

    expect(err).toBeInstanceOf(EvalGuardError);
    expect((err as EvalGuardError).code).toBe("NETWORK_ERROR");
    // A dropped connection does not prove the row wasn't written.
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("STILL retries 5xx on routes the server dedups via Idempotency-Key", async () => {
    // POST /security opts into `idempotent: true`, so the retry replays the
    // original response instead of running a second scan.
    const fetchMock = fetchAlways(503, { success: false, error: { message: "transient" } });
    globalThis.fetch = fetchMock;

    const client = new EvalGuard({ apiKey: "key" });
    await client
      .securityScan({ projectId: "p", model: "gpt-4o", prompt: "hi", attackTypes: ["prompt-injection"] })
      .catch(() => undefined);

    expect(fetchMock).toHaveBeenCalledTimes(4); // 1 + 3 retries
  }, 35_000);

  it("STILL retries 5xx on GET and DELETE (idempotent by HTTP semantics)", async () => {
    const getMock = fetchAlways(500, { success: false, error: { message: "boom" } });
    globalThis.fetch = getMock;
    const client = new EvalGuard({ apiKey: "key" });
    await client.getEvalRun("run-1").catch(() => undefined);
    expect(getMock).toHaveBeenCalledTimes(4);

    const delMock = fetchAlways(500, { success: false, error: { message: "boom" } });
    globalThis.fetch = delMock;
    await client.deleteOnlineEvalSampler("s-1").catch(() => undefined);
    expect(delMock).toHaveBeenCalledTimes(4);
  }, 70_000);

  it("STILL retries 429 on a non-idempotent POST (rate-limited = never executed)", async () => {
    const fetchMock = fetchAlways(429, { success: false, error: { message: "slow down" } });
    globalThis.fetch = fetchMock;

    const client = new EvalGuard({ apiKey: "key" });
    await client.createApiKey({ orgId: "org-1", name: "ci" }).catch(() => undefined);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  }, 70_000);
});

describe("isRetriableRequest", () => {
  it("treats GET/HEAD/OPTIONS/DELETE/PUT as replay-safe", () => {
    for (const m of ["GET", "head", "OPTIONS", "DELETE", "put"]) {
      expect(isRetriableRequest(m, "/anything/at/all")).toBe(true);
    }
  });

  it("allows POST only on the routes that honour Idempotency-Key server-side", () => {
    expect(isRetriableRequest("POST", "/evals")).toBe(true);
    expect(isRetriableRequest("POST", "/security")).toBe(true);
    expect(isRetriableRequest("POST", "/batches")).toBe(true);
    expect(isRetriableRequest("POST", "/billing/activate")).toBe(true);
    expect(isRetriableRequest("POST", "/verticals/fin-123/scan")).toBe(true);
    // …and nothing else.
    expect(isRetriableRequest("POST", "/api-keys")).toBe(false);
    expect(isRetriableRequest("POST", "/team/invite")).toBe(false);
    expect(isRetriableRequest("PATCH", "/online-eval-samplers/s-1")).toBe(false);
    expect(isRetriableRequest("POST", "/webhooks")).toBe(false);
  });

  it("is not fooled by query strings, trailing slashes, or prefix lookalikes", () => {
    expect(isRetriableRequest("POST", "/evals?dryRun=1")).toBe(true);
    expect(isRetriableRequest("POST", "/evals/")).toBe(true);
    expect(isRetriableRequest("POST", "/evals/eval-1/rerun")).toBe(false);
    expect(isRetriableRequest("POST", "/security-incidents")).toBe(false);
  });
});
