import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EvalGuard, EvalGuardError } from "../client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockFetchResponse(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: vi.fn().mockResolvedValue(body),
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("EvalGuard SDK", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── Initialization ──────────────────────────────────────────────────────

  describe("constructor", () => {
    it("stores the API key", () => {
      const client = new EvalGuard({ apiKey: "eg_test_key_123" });
      // Verify by making a request and inspecting the Authorization header
      const mockFn = mockFetchResponse({ id: "1" });
      globalThis.fetch = mockFn;
      client.eval({
        name: "test",
        projectId: "proj-1",
        model: "gpt-4o",
        prompt: "hello",
        cases: [],
        scorers: [],
      });
      expect(mockFn).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer eg_test_key_123",
          }),
        })
      );
    });

    it("uses default base URL when none provided", () => {
      const mockFn = mockFetchResponse({ id: "1" });
      globalThis.fetch = mockFn;
      const client = new EvalGuard({ apiKey: "key" });
      client.getEvalRun("run-1");
      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/evals/run-1",
        expect.any(Object)
      );
    });

    it("uses custom base URL when provided", () => {
      const mockFn = mockFetchResponse({ id: "1" });
      globalThis.fetch = mockFn;
      const client = new EvalGuard({
        apiKey: "key",
        baseUrl: "http://localhost:3000/api",
      });
      client.getEvalRun("run-1");
      expect(mockFn).toHaveBeenCalledWith(
        "http://localhost:3000/api/evals/run-1",
        expect.any(Object)
      );
    });
  });

  // ── eval() ──────────────────────────────────────────────────────────────

  describe("eval()", () => {
    it("sends POST to /evals with correct payload", async () => {
      const responseBody = { id: "eval-1", status: "pending" };
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const params = {
        name: "accuracy-test",
        projectId: "proj-abc",
        model: "gpt-4o",
        prompt: "Answer: {{input}}",
        cases: [{ input: "2+2", expectedOutput: "4" }],
        scorers: ["exact-match"],
      };

      const result = await client.eval(params);

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/evals",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            Authorization: "Bearer key",
          }),
          body: JSON.stringify(params),
        })
      );
      expect(result).toEqual(responseBody);
    });

    it("includes cases without expectedOutput", async () => {
      const mockFn = mockFetchResponse({ id: "eval-2" });
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      await client.eval({
        name: "open-ended",
        projectId: "proj-1",
        model: "gpt-4o",
        prompt: "{{input}}",
        cases: [{ input: "Tell me a joke" }],
        scorers: ["contains"],
      });

      const sentBody = JSON.parse(mockFn.mock.calls[0][1].body);
      expect(sentBody.cases[0]).toEqual({ input: "Tell me a joke" });
      expect(sentBody.cases[0].expectedOutput).toBeUndefined();
    });
  });

  // ── getEvalRun() ────────────────────────────────────────────────────────

  describe("getEvalRun()", () => {
    it("sends GET to /evals/:id", async () => {
      const responseBody = { id: "eval-1", status: "passed", score: 0.95 };
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const result = await client.getEvalRun("eval-1");

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/evals/eval-1",
        expect.objectContaining({
          method: "GET",
          body: undefined,
        })
      );
      expect(result).toEqual(responseBody);
    });
  });

  // ── securityScan() ─────────────────────────────────────────────────────

  describe("securityScan()", () => {
    it("sends POST to /security with correct payload", async () => {
      const responseBody = { id: "scan-1", status: "pending" };
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const params = {
        projectId: "proj-abc",
        model: "gpt-4o",
        prompt: "You are a helpful assistant.",
        attackTypes: ["prompt-injection", "jailbreak"],
      };

      const result = await client.securityScan(params);

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/security",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(params),
        })
      );
      expect(result).toEqual(responseBody);
    });
  });

  // ── Idempotency-Key on POST retries (audit P2-16) ───────────────────────

  describe("idempotency key", () => {
    it("sends an Idempotency-Key header on POST writes", async () => {
      const mockFn = mockFetchResponse({ id: "scan-1" });
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      await client.securityScan({
        projectId: "proj-abc",
        model: "gpt-4o",
        prompt: "hi",
        attackTypes: ["prompt-injection"],
      });

      const headers = (mockFn.mock.calls[0][1] as { headers: Record<string, string> }).headers;
      expect(typeof headers["Idempotency-Key"]).toBe("string");
      expect(headers["Idempotency-Key"].length).toBeGreaterThan(0);
    });

    it("does NOT send an Idempotency-Key on GET reads", async () => {
      const mockFn = mockFetchResponse({ id: "run-1" });
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      await client.getEvalRun("run-1");

      const headers = (mockFn.mock.calls[0][1] as { headers: Record<string, string> }).headers;
      expect(headers["Idempotency-Key"]).toBeUndefined();
    });

    it("reuses ONE Idempotency-Key across a 5xx retry (no duplicate scans)", async () => {
      // First attempt 503 (retried), second attempt 200.
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 503,
          statusText: "Service Unavailable",
          json: vi.fn().mockResolvedValue({ message: "transient" }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          statusText: "OK",
          json: vi.fn().mockResolvedValue({ id: "scan-1" }),
        });
      globalThis.fetch = fetchMock;

      const client = new EvalGuard({ apiKey: "key" });
      await client.securityScan({
        projectId: "proj-abc",
        model: "gpt-4o",
        prompt: "hi",
        attackTypes: ["prompt-injection"],
      });

      expect(fetchMock).toHaveBeenCalledTimes(2);
      const keyA = (fetchMock.mock.calls[0][1] as { headers: Record<string, string> }).headers["Idempotency-Key"];
      const keyB = (fetchMock.mock.calls[1][1] as { headers: Record<string, string> }).headers["Idempotency-Key"];
      expect(keyA).toBeTruthy();
      expect(keyA).toBe(keyB);
    });

    it("uses a DIFFERENT Idempotency-Key for separate calls", async () => {
      const mockFn = mockFetchResponse({ id: "scan-1" });
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const params = {
        projectId: "proj-abc",
        model: "gpt-4o",
        prompt: "hi",
        attackTypes: ["prompt-injection"],
      };
      await client.securityScan(params);
      await client.securityScan(params);

      const keyA = (mockFn.mock.calls[0][1] as { headers: Record<string, string> }).headers["Idempotency-Key"];
      const keyB = (mockFn.mock.calls[1][1] as { headers: Record<string, string> }).headers["Idempotency-Key"];
      expect(keyA).not.toBe(keyB);
    });
  });

  // ── getScan() ───────────────────────────────────────────────────────────

  describe("getScan()", () => {
    it("sends GET to /security/:id", async () => {
      const responseBody = { findings: [], passRate: 1, totalTests: 0 };
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const result = await client.getScan("scan-1");

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/security/scan-1",
        expect.objectContaining({ method: "GET", body: undefined })
      );
      expect(result).toEqual(responseBody);
    });
  });

  // ── listScans() ─────────────────────────────────────────────────────────

  describe("listScans()", () => {
    it("sends GET to /security?projectId=", async () => {
      const responseBody = [{ id: "scan-1", model: "gpt-4o", status: "completed" }];
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const result = await client.listScans("proj-abc");

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/security?projectId=proj-abc",
        expect.objectContaining({ method: "GET", body: undefined })
      );
      expect(result).toEqual(responseBody);
    });

    it("throws when projectId is missing", async () => {
      const client = new EvalGuard({ apiKey: "key" });
      await expect(client.listScans("")).rejects.toThrow("projectId is required");
    });
  });

  // ── compareEvals() ──────────────────────────────────────────────────────

  describe("compareEvals()", () => {
    it("sends GET to /evals/compare with runA, runB, projectId", async () => {
      const responseBody = {
        run_a: {}, run_b: {}, score_diff: 0,
        regressions: 0, improvements: 0, unchanged: 0, cases: [],
      };
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const result = await client.compareEvals({ runA: "run-1", runB: "run-2", projectId: "proj-abc" });

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/evals/compare?runA=run-1&runB=run-2&projectId=proj-abc",
        expect.objectContaining({ method: "GET", body: undefined })
      );
      expect(result).toEqual(responseBody);
    });

    it("throws when a run id is missing", async () => {
      const client = new EvalGuard({ apiKey: "key" });
      await expect(
        client.compareEvals({ runA: "", runB: "run-2", projectId: "p" })
      ).rejects.toThrow("runA and runB are required");
    });
  });

  // ── trace() ─────────────────────────────────────────────────────────────

  describe("trace()", () => {
    it("sends POST to /traces with correct payload", async () => {
      const responseBody = { id: "trace-1" };
      const mockFn = mockFetchResponse(responseBody);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      const params = {
        projectId: "proj-1",
        sessionId: "sess-abc",
        steps: [{ type: "llm-call", input: "hi", output: "hello" }],
      };

      const result = await client.trace(params);

      expect(mockFn).toHaveBeenCalledWith(
        "https://evalguard.ai/api/v1/traces",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(params),
        })
      );
      expect(result).toEqual(responseBody);
    });
  });

  // ── Error handling ──────────────────────────────────────────────────────

  describe("error handling", () => {
    it("throws on non-ok response with API error message", async () => {
      const mockFn = mockFetchResponse(
        { message: "Invalid API key" },
        401,
        false
      );
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "bad-key" });
      await expect(client.getEvalRun("eval-1")).rejects.toThrow(
        "EvalGuard API error 401: Invalid API key"
      );
    });

    it("throws with status text when response body has no message", { timeout: 35_000 }, async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
        json: vi.fn().mockRejectedValue(new Error("not json")),
      });

      const client = new EvalGuard({ apiKey: "key" });
      await expect(client.eval({
        name: "t",
        projectId: "p",
        model: "m",
        prompt: "p",
        cases: [],
        scorers: [],
      })).rejects.toThrow("EvalGuard API error 500: Internal Server Error");
    });

    it("throws with 'Unknown error' when body has no message field", async () => {
      const mockFn = mockFetchResponse({}, 403, false);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "key" });
      await expect(client.getEvalRun("x")).rejects.toThrow(
        "EvalGuard API error 403: Unknown error"
      );
    });

    it("throws on network error (fetch rejects)", { timeout: 35_000 }, async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new TypeError("fetch failed"));

      const client = new EvalGuard({ apiKey: "key" });
      // The original message is preserved inside the wrapped, typed error.
      await expect(client.getEvalRun("eval-1")).rejects.toThrow("fetch failed");
    });
  });

  // ── Typed errors (EvalGuardError) ────────────────────────────────────────
  //
  // Every error thrown from the transport (`request` / `requestText`) must be an
  // `EvalGuardError` so a consumer can distinguish a NETWORK failure (no server /
  // DNS / connection refused — the raw `TypeError: fetch failed` that used to
  // escape) from an HTTP API error, without string-matching the message.

  describe("EvalGuardError", () => {
    it("is exported and extends Error with a stable name", () => {
      const e = new EvalGuardError("boom", { code: "NETWORK_ERROR" });
      expect(e).toBeInstanceOf(Error);
      expect(e).toBeInstanceOf(EvalGuardError);
      expect(e.name).toBe("EvalGuardError");
      expect(e.code).toBe("NETWORK_ERROR");
      expect(e.message).toBe("boom");
    });

    it("wraps a network failure (fetch rejects) as EvalGuardError code NETWORK_ERROR", { timeout: 35_000 }, async () => {
      const raw = new TypeError("fetch failed");
      globalThis.fetch = vi.fn().mockRejectedValue(raw);

      const client = new EvalGuard({ apiKey: "key" });
      let caught: unknown;
      try {
        await client.getEvalRun("eval-1"); // GET → network method
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(EvalGuardError);
      // It must NOT be the raw TypeError that used to escape.
      expect(caught).not.toBeInstanceOf(TypeError);
      const e = caught as EvalGuardError;
      expect(e.code).toBe("NETWORK_ERROR");
      expect(e.status).toBeUndefined();
      // Original error preserved for diagnostics.
      expect(e.cause).toBe(raw);
      // Message names the path + carries the underlying message.
      expect(e.message).toContain("/evals/eval-1");
      expect(e.message).toContain("fetch failed");
    });

    it("retries a network failure 3 times before throwing NETWORK_ERROR", { timeout: 35_000 }, async () => {
      const fetchMock = vi.fn().mockRejectedValue(new TypeError("fetch failed"));
      globalThis.fetch = fetchMock;

      const client = new EvalGuard({ apiKey: "key" });
      await expect(client.getEvalRun("eval-1")).rejects.toBeInstanceOf(EvalGuardError);
      // maxRetries=3 → 4 total attempts; the backoff/retry loop is preserved.
      expect(fetchMock).toHaveBeenCalledTimes(4);
    });

    it("throws an HTTP error as EvalGuardError with status + HTTP_<status> code", async () => {
      const mockFn = mockFetchResponse({ message: "Invalid API key" }, 401, false);
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "bad-key" });
      let caught: unknown;
      try {
        await client.getEvalRun("eval-1");
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(EvalGuardError);
      const e = caught as EvalGuardError;
      expect(e.status).toBe(401);
      expect(e.code).toBe("HTTP_401");
      // Human-readable message (incl. the envelope's error message) is preserved.
      expect(e.message).toBe("EvalGuard API error 401: Invalid API key");
    });

    it("does NOT retry a 4xx HTTP error (typed + non-retryable)", async () => {
      const fetchMock = mockFetchResponse({ message: "nope" }, 403, false);
      globalThis.fetch = fetchMock;

      const client = new EvalGuard({ apiKey: "key" });
      await expect(client.getEvalRun("x")).rejects.toBeInstanceOf(EvalGuardError);
      // A 4xx is a definitive answer — exactly one fetch, no backoff retries.
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    // requestText()-backed methods (exportDpo / exportBurp) return non-JSON
    // bodies on success, but their ERROR responses still use the standard
    // { error:{ code, message, requestId } } envelope. The error path must parse
    // it (like request()) so the server's stable code + requestId surface,
    // instead of always falling back to HTTP_<status> (audit TS-SDK-ENVELOPE).
    it("requestText: parses the standard error envelope (code + message + requestId)", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        text: vi.fn().mockResolvedValue(
          JSON.stringify({
            success: false,
            error: { code: "INVALID_FORMAT", message: "Unsupported export format", requestId: "req_123" },
          }),
        ),
      });

      const client = new EvalGuard({ apiKey: "key" });
      let caught: unknown;
      try {
        await client.exportDpo("eval-1", "proj-1"); // → requestText()
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(EvalGuardError);
      const e = caught as EvalGuardError;
      expect(e.status).toBe(400);
      // The server's stable code wins over the HTTP_<status> fallback.
      expect(e.code).toBe("INVALID_FORMAT");
      expect(e.requestId).toBe("req_123");
      expect(e.message).toBe("EvalGuard API error 400: Unsupported export format");
    });

    it("requestText: falls back to HTTP_<status> for a non-JSON error body", async () => {
      // Use a 4xx so the (definitive, non-retryable) error path runs once with
      // no backoff delays — a 5xx would retry 3× before throwing.
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
        text: vi.fn().mockResolvedValue("plain text not-found page"),
      });
      globalThis.fetch = fetchMock;

      const client = new EvalGuard({ apiKey: "key" });
      let caught: unknown;
      try {
        await client.exportBurp("scan-1", "proj-1"); // → requestText()
      } catch (err) {
        caught = err;
      }

      expect(caught).toBeInstanceOf(EvalGuardError);
      const e = caught as EvalGuardError;
      expect(e.status).toBe(404);
      // No JSON envelope → keep the raw text + HTTP_<status> code.
      expect(e.code).toBe("HTTP_404");
      expect(e.requestId).toBeUndefined();
      expect(e.message).toBe("EvalGuard API error 404: plain text not-found page");
      // 4xx is definitive — exactly one fetch, no retries.
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  // ── Headers ─────────────────────────────────────────────────────────────

  describe("request headers", () => {
    it("always sends Content-Type and Authorization headers", async () => {
      const mockFn = mockFetchResponse({});
      globalThis.fetch = mockFn;

      const client = new EvalGuard({ apiKey: "sk-test-abc123" });
      await client.getEvalRun("run-1");

      const headers = mockFn.mock.calls[0][1].headers;
      expect(headers["Content-Type"]).toBe("application/json");
      expect(headers.Authorization).toBe("Bearer sk-test-abc123");
    });
  });
});
