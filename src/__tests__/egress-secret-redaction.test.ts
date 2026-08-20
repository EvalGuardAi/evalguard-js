import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EvalGuardReporter } from "../vitest";
import { _redactEmbeddedSecrets, configureTracing, flushTraces, traceable } from "../tracing";

/**
 * Audit A386 repair — "payloads leaving the process past their own redaction".
 *
 * The first fix closed the pydantic plugin's `error` field. The adversarial
 * re-audit found the identical shape one call site over: the CI reporter POSTs
 * a raw `message` + `stack` to /evals/ci, the span's own `error`/`errorStack`
 * were assigned raw, `_safeSerialize` stringified object KEYS without ever
 * testing them, and no pattern in the secret list matched a connection string
 * even though the finding names connection strings.
 *
 * GROUND TRUTH for every assertion below: a credential the test itself minted
 * must not appear in the bytes the SDK hands to `fetch` / to its HTTP client.
 * Nothing here asserts on whatever the implementation happens to return.
 */

const ANTHROPIC_KEY = "sk-ant-A1B2C3D4E5F6G7H8I9J0K1L2";
const DSN = "postgres://admin:hunter2@db.internal:5432/prod";

let fetchSpy: ReturnType<typeof vi.fn>;

/** Every byte the tracer actually put on the wire. */
function outboundBodies(): string {
  return fetchSpy.mock.calls.map((c) => String((c[1] as RequestInit)?.body ?? "")).join("\n");
}

beforeEach(() => {
  fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
  globalThis.fetch = fetchSpy as unknown as typeof fetch;
  configureTracing({
    apiKey: "eg_test_key",
    baseUrl: "https://api.evalguard.test",
    projectId: "proj-1",
    enabled: true,
  });
  process.env.EVALGUARD_API_KEY = "eg_test_key_for_redaction";
});

afterEach(() => {
  configureTracing({ apiKey: undefined, enabled: undefined });
  delete process.env.EVALGUARD_API_KEY;
  vi.restoreAllMocks();
});

describe("A386 — the @traceable span must not ship a credential", () => {
  it("**redacts a secret embedded in the thrown error's message**", async () => {
    const fn = traceable(async () => {
      throw new Error(`auth failed using ${ANTHROPIC_KEY}`);
    });
    await expect(fn()).rejects.toThrow();
    flushTraces();
    await Promise.resolve();

    const body = outboundBodies();
    expect(body.length, "no span reached the wire — the test proves nothing").toBeGreaterThan(0);
    expect(body, "the tracer shipped a live API key in span.error").not.toContain(ANTHROPIC_KEY);
    expect(body).toContain("auth failed using");
  });

  it("**redacts a secret embedded in the thrown error's stack**", async () => {
    const fn = traceable(async () => {
      const err = new Error("boom");
      err.stack = `Error: boom\n    at auth (/repo/src/a.ts:1:1) { key: '${ANTHROPIC_KEY}' }`;
      throw err;
    });
    await expect(fn()).rejects.toThrow();
    flushTraces();
    await Promise.resolve();

    const body = outboundBodies();
    expect(body.length).toBeGreaterThan(0);
    expect(body, "the tracer shipped a live API key in span.errorStack").not.toContain(
      ANTHROPIC_KEY,
    );
    expect(body).toContain("/repo/src/a.ts");
  });

  it("**redacts a credential that appears in KEY position**", async () => {
    const fn = traceable(async (_cache: Record<string, string>) => "ok");
    await fn({ [ANTHROPIC_KEY]: "hit" });
    flushTraces();
    await Promise.resolve();

    const body = outboundBodies();
    expect(body.length).toBeGreaterThan(0);
    expect(body, "an object keyed by a credential shipped the key verbatim").not.toContain(
      ANTHROPIC_KEY,
    );
  });

  it("keeps distinct keys distinct when both redact to the same string", async () => {
    const other = "sk-ant-Z9Y8X7W6V5U4T3S2R1Q0P9O8";
    const fn = traceable(async (_cache: Record<string, string>) => "ok");
    await fn({ [ANTHROPIC_KEY]: "a", [other]: "b" });
    flushTraces();
    await Promise.resolve();

    const spans = JSON.parse(String((fetchSpy.mock.calls[0][1] as RequestInit).body)) as {
      spans: Array<{ inputs?: Record<string, Record<string, unknown>> }>;
    };
    const cache = spans.spans[0].inputs?.arg0 as Record<string, unknown>;
    // Ground truth: two entries went in, two values must come out. Collapsing
    // them would be silent data loss.
    expect(Object.keys(cache)).toHaveLength(2);
    expect(Object.values(cache).sort()).toEqual(["a", "b"]);
  });
});

describe("A386 — the vitest CI reporter must not ship a credential", () => {
  /** Capture the exact body the reporter hands to the HTTP client. */
  function captureReporter(reporter: EvalGuardReporter) {
    const request = vi.fn(async () => ({}));
    (reporter as unknown as { client: unknown }).client = { request };
    return request;
  }

  function failingFile(message: string, stack: string): Record<string, unknown> {
    return {
      filepath: "/repo/src/auth.test.ts",
      tasks: [
        {
          type: "test",
          name: "authenticates",
          result: {
            state: "fail",
            duration: 4,
            errors: [{ name: "Error", message, stack }],
          },
        },
      ],
    };
  }

  it("**redacts a secret embedded in the failure message**", async () => {
    const reporter = new EvalGuardReporter({ projectId: "proj_1" });
    const request = captureReporter(reporter);

    reporter.onInit();
    await reporter.onFinished([
      failingFile(`401 from provider using ${ANTHROPIC_KEY}`, "Error: boom\n    at f (a.ts:1:1)"),
    ]);

    expect(request).toHaveBeenCalledTimes(1);
    const body = JSON.stringify((request.mock.calls[0] as unknown[])[2]);
    expect(body, "the reporter shipped a live API key to /evals/ci").not.toContain(ANTHROPIC_KEY);
    // Not a blanket blank-out: the surrounding text must survive so the failure
    // is still diagnosable.
    expect(body).toContain("401 from provider using");
  });

  it("**redacts a secret embedded in the stack trace**", async () => {
    const reporter = new EvalGuardReporter({ projectId: "proj_1" });
    const request = captureReporter(reporter);

    reporter.onInit();
    await reporter.onFinished([
      failingFile(
        "assertion failed",
        [
          "Error: assertion failed",
          `    at Object.<anonymous> (/repo/src/auth.test.ts:9:11) { token: '${ANTHROPIC_KEY}' }`,
          "    at run (/repo/node_modules/vitest/dist/runner.js:1:1)",
        ].join("\n"),
      ),
    ]);

    const body = JSON.stringify((request.mock.calls[0] as unknown[])[2]);
    expect(body, "the reporter shipped a live API key inside err.stack").not.toContain(
      ANTHROPIC_KEY,
    );
    expect(body).toContain("auth.test.ts");
  });

  it("**redacts BEFORE the 2000-char cut — truncation is not what stops the leak**", async () => {
    const reporter = new EvalGuardReporter({ projectId: "proj_1" });
    const request = captureReporter(reporter);

    // Land the credential so it STRADDLES the cut. Truncate-then-redact leaves
    // the first 15 characters of a live key on the wire and calls it safe;
    // redact-then-truncate leaves nothing. This is the ordering assertion —
    // truncation is a size policy, never a redaction control.
    const CUT = 2000;
    const straddleAt = CUT - 15;
    const pad = "    at frame (/repo/src/x.ts:1:1)\n";
    let stack = "Error: assertion failed\n";
    while (stack.length + pad.length <= straddleAt) stack += pad;
    stack += "x".repeat(straddleAt - stack.length);
    stack += `${ANTHROPIC_KEY} trailing`;
    expect(stack.indexOf(ANTHROPIC_KEY)).toBe(straddleAt);

    reporter.onInit();
    await reporter.onFinished([failingFile("assertion failed", stack)]);

    const body = JSON.stringify((request.mock.calls[0] as unknown[])[2]);
    expect(body).not.toContain(ANTHROPIC_KEY);
    // The surviving fragment of a truncated key is still an unredacted
    // credential fragment. It must not be there either.
    expect(body, "a 15-char fragment of a live key survived the cut").not.toContain(
      ANTHROPIC_KEY.slice(0, 15),
    );
  });
});

describe("A386 — the secret list must cover a connection string", () => {
  it("**redacts a credentialed URI embedded in free text**", () => {
    const out = _redactEmbeddedSecrets(`ECONNREFUSED ${DSN} after 3 retries`);
    expect(out, "a DB password survived every redactor").not.toContain("hunter2");
    expect(out).toContain("ECONNREFUSED");
    expect(out).toContain("after 3 retries");
  });

  it("does NOT mask an ordinary URL that carries no credential", () => {
    const plain = "GET https://evalguard.ai/api/v1/traces returned 502";
    expect(_redactEmbeddedSecrets(plain)).toBe(plain);
  });

  it("leaves ordinary prose untouched", () => {
    const prose = "the model refused the request because the prompt was unsafe";
    expect(_redactEmbeddedSecrets(prose)).toBe(prose);
  });

  it("every derived un-anchored pattern is a compilable regex", () => {
    // Guards the derivation itself: it runs at module load, so a bad strip is
    // an import-time crash for every consumer of the SDK.
    expect(() => _redactEmbeddedSecrets("warm the module")).not.toThrow();
  });
});
