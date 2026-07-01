import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  traceable, traced, configureTracing, getCurrentSpan, getCurrentTraceId, getTraceIdentity, flushTraces,
} from "../tracing";

// SDK tracing wrapper. Bugs class:
//   - Span error → user code aborted (telemetry must NEVER throw)
//   - traceId not propagated through async parent → child spans
//     orphaned in dashboard
//   - Inputs serialized too deep → 10MB span body sent to backend
//   - Sensitive arg captured verbatim → API key leaks via input field
//   - flush throws → process exit hook hangs

let fetchSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchSpy = vi.fn().mockResolvedValue({ ok: true, status: 200 } as Response);
  globalThis.fetch = fetchSpy as unknown as typeof fetch;
  configureTracing({
    apiKey: "eg_test_key",
    baseUrl: "https://api.evalguard.test",
    projectId: "proj-1",
    enabled: true,
  });
});

afterEach(() => {
  configureTracing({ apiKey: undefined, enabled: undefined });
  vi.restoreAllMocks();
});

describe("traceable — wraps + propagates", () => {
  it("invokes the wrapped function and returns its result", async () => {
    const fn = traceable(async (a: number, b: number) => a + b);
    expect(await fn(1, 2)).toBe(3);
  });

  it("propagates synchronous return values via Promise wrap", async () => {
    const fn = traceable((x: number) => x * 2);
    expect(await fn(5)).toBe(10);
  });

  it("rethrows errors from the wrapped function", async () => {
    const fn = traceable(async () => { throw new Error("inner"); });
    await expect(fn()).rejects.toThrow("inner");
  });

  it("preserves the function name as wrapper.name", () => {
    function namedFn() { return 1; }
    const wrapper = traceable(namedFn);
    expect(wrapper.name).toBe("namedFn");
  });

  it("uses options.name when provided", () => {
    const wrapper = traceable(() => 1, { name: "custom-span-name" });
    expect(wrapper.name).toBe("custom-span-name");
  });
});

describe("traced — inline tracing block", () => {
  it("invokes the inner function with a span object and returns its result", async () => {
    const result = await traced("my-block", async (span) => {
      span.metadata.foo = "bar";
      return 42;
    });
    expect(result).toBe(42);
  });

  it("rethrows errors", async () => {
    await expect(
      traced("erroring-block", async () => { throw new Error("boom"); }),
    ).rejects.toThrow("boom");
  });
});

describe("getCurrentSpan / getCurrentTraceId — context propagation", () => {
  it("returns the active span when called inside a traced block", async () => {
    let captured: ReturnType<typeof getCurrentSpan>;
    await traced("outer", async () => {
      captured = getCurrentSpan();
    });
    expect(captured).toBeDefined();
    expect(captured!.name).toBe("outer");
  });

  it("nested traces share the same traceId (parent-child relationship)", async () => {
    let outerTraceId: string | undefined;
    let innerTraceId: string | undefined;
    await traced("outer", async () => {
      outerTraceId = getCurrentTraceId();
      await traced("inner", async () => {
        innerTraceId = getCurrentTraceId();
      });
    });
    expect(outerTraceId).toBeDefined();
    expect(innerTraceId).toBe(outerTraceId);
  });

  it("returns undefined outside any traced block", () => {
    expect(getCurrentSpan()).toBeUndefined();
    expect(getCurrentTraceId()).toBeUndefined();
  });
});

describe("traceable + batcher — fail-soft", () => {
  it("does NOT throw when fetch rejects (telemetry must never break user code)", async () => {
    fetchSpy.mockRejectedValue(new Error("network"));
    const fn = traceable(async () => 1);
    // Wait for batch send to be attempted
    expect(await fn()).toBe(1);
    flushTraces();
    // No throw despite fetch reject
    await new Promise((r) => setTimeout(r, 50));
  });

  it("does NOT enqueue spans when tracing disabled", async () => {
    configureTracing({ enabled: false });
    const fn = traceable(async () => 1);
    await fn();
    flushTraces();
    await new Promise((r) => setTimeout(r, 100));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does NOT enqueue when API key missing", async () => {
    configureTracing({ apiKey: "" });
    const fn = traceable(async () => 1);
    await fn();
    flushTraces();
    await new Promise((r) => setTimeout(r, 100));
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("flushTraces", () => {
  it("does not throw when called outside a traced block", () => {
    expect(() => flushTraces()).not.toThrow();
  });

  it("can be called multiple times", () => {
    flushTraces();
    flushTraces();
    flushTraces();
  });
});

describe("configureTracing — runtime updates", () => {
  it("disabled flag flips behavior immediately on next traceable call", async () => {
    configureTracing({ enabled: false });
    const fn = traceable(async () => "off");
    const r = await fn();
    expect(r).toBe("off"); // Function still runs, just not traced
  });

  it("baseUrl trailing slashes stripped", async () => {
    configureTracing({ baseUrl: "https://api.evalguard.test/" });
    const fn = traceable(async () => 1);
    await fn();
    flushTraces();
    // Wait briefly for batcher to send
    await new Promise((r) => setTimeout(r, 50));
    if (fetchSpy.mock.calls.length > 0) {
      const url = fetchSpy.mock.calls[0][0];
      expect(url).toBe("https://api.evalguard.test/v1/traces/ingest");
    }
  });
});

// ── Secret redaction ──────────────────────────────────────────────────
// The traceable() wrapper captures args verbatim as arg0..N. A secret passed
// as an arg (token-shaped string) or nested under a secret-named key must be
// masked BEFORE the span body leaves the process. Verified by inspecting the
// serialized span payload sent to fetch.
describe("traceable — secret redaction", () => {
  async function captureSentSpan(fn: () => Promise<unknown>): Promise<Record<string, unknown> | null> {
    await fn();
    flushTraces();
    await new Promise((r) => setTimeout(r, 50));
    if (fetchSpy.mock.calls.length === 0) return null;
    const body = JSON.parse(fetchSpy.mock.calls[0][1].body as string) as {
      spans: Array<Record<string, unknown>>;
    };
    return body.spans[0] ?? null;
  }

  it("masks token-shaped string args (eg_*, sk-*, Bearer, JWT)", async () => {
    const fn = traceable(async (_a: string) => "ok", { name: "auth-call" });
    const span = await captureSentSpan(() => fn("eg_live_abcdefgh12345678"));
    expect(span).not.toBeNull();
    const inputs = span!.inputs as Record<string, unknown>;
    expect(inputs.arg0).toBe("[REDACTED]");
  });

  it("masks values under secret-named keys (apiKey / password / authorization)", async () => {
    const fn = traceable(async (_cfg: Record<string, unknown>) => "ok", { name: "config-call" });
    const span = await captureSentSpan(() =>
      fn({ apiKey: "plain-but-secret-by-key", password: "hunter2", username: "alice" }),
    );
    const inputs = span!.inputs as Record<string, unknown>;
    const arg0 = inputs.arg0 as Record<string, unknown>;
    expect(arg0.apiKey).toBe("[REDACTED]");
    expect(arg0.password).toBe("[REDACTED]");
    // Non-secret keys pass through untouched.
    expect(arg0.username).toBe("alice");
  });

  it("redacts secrets nested in metadata", async () => {
    const fn = traceable(async () => "ok", {
      name: "meta-call",
      metadata: { token: "sk-abcdefghijklmnop1234", region: "us-east-1" },
    });
    const span = await captureSentSpan(() => fn());
    const meta = span!.metadata as Record<string, unknown>;
    expect(meta.token).toBe("[REDACTED]");
    expect(meta.region).toBe("us-east-1");
  });

  it("leaves ordinary (non-secret) values intact", async () => {
    const fn = traceable(async (_a: string, _b: number) => "ok", { name: "plain-call" });
    const span = await captureSentSpan(() => fn("hello world", 42));
    const inputs = span!.inputs as Record<string, unknown>;
    expect(inputs.arg0).toBe("hello world");
    expect(inputs.arg1).toBe(42);
  });
});

describe("traceable — trace identity (observability-tracing-3)", () => {
  it("attaches session/user/conversation ids as dotted span attributes", async () => {
    let meta: Record<string, unknown> | undefined;
    const fn = traceable(async () => { meta = getCurrentSpan()?.metadata; }, {
      sessionId: "s1", userId: "u1", conversationId: "c1",
    });
    await fn();
    expect(meta?.["session.id"]).toBe("s1");
    expect(meta?.["user.id"]).toBe("u1");
    expect(meta?.["conversation.id"]).toBe("c1");
  });

  it("child spans inherit the parent identity", async () => {
    let inner: Record<string, unknown> | undefined;
    const innerFn = traceable(async () => { inner = getCurrentSpan()?.metadata; });
    const outer = traceable(async () => { await innerFn(); }, { sessionId: "S", userId: "U" });
    await outer();
    expect(inner?.["session.id"]).toBe("S");
    expect(inner?.["user.id"]).toBe("U");
  });

  it("a child can override one identity field and inherit the rest", async () => {
    let inner: Record<string, unknown> | undefined;
    const innerFn = traceable(async () => { inner = getCurrentSpan()?.metadata; }, { userId: "U2" });
    const outer = traceable(async () => { await innerFn(); }, { sessionId: "S", userId: "U1" });
    await outer();
    expect(inner?.["session.id"]).toBe("S");  // inherited
    expect(inner?.["user.id"]).toBe("U2");    // overridden
  });

  it("getTraceIdentity exposes the inherited identity inside a span", async () => {
    let id: ReturnType<typeof getTraceIdentity>;
    const fn = traceable(async () => { id = getTraceIdentity(); }, { sessionId: "s", conversationId: "c" });
    await fn();
    expect(id).toEqual({ sessionId: "s", userId: undefined, conversationId: "c" });
    expect(getTraceIdentity()).toBeUndefined(); // outside any span
  });

  it("traced() inline blocks inherit the parent traceable identity", async () => {
    let tracedMeta: Record<string, unknown> | undefined;
    const outer = traceable(async () => {
      await traced("inner", async (span) => { tracedMeta = span.metadata; });
    }, { sessionId: "S" });
    await outer();
    expect(tracedMeta?.["session.id"]).toBe("S");
  });

  it("adds no identity keys when none is set (backward compatible)", async () => {
    let meta: Record<string, unknown> | undefined;
    const fn = traceable(async () => { meta = getCurrentSpan()?.metadata; });
    await fn();
    expect(meta && "session.id" in meta).toBe(false);
    expect(meta && "user.id" in meta).toBe(false);
  });

  it("the dotted session.id key is NOT caught by secret redaction", async () => {
    let dict: ReturnType<NonNullable<ReturnType<typeof getCurrentSpan>>["toDict"]> | undefined;
    const fn = traceable(async () => { dict = getCurrentSpan()?.toDict(); }, { sessionId: "sess-123" });
    await fn();
    // If "session.id" matched the secret-key regex, this would be "[REDACTED]".
    expect((dict?.metadata as Record<string, unknown>)?.["session.id"]).toBe("sess-123");
  });
});
