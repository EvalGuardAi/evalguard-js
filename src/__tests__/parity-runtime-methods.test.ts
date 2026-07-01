import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

/**
 * Coverage for the 2026-06-29 SDK/CLI-parity runtime methods. Each test mocks
 * global fetch and asserts the SDK hits the correct route + verb, sends the
 * right body/headers, and unwraps the response the way the route returns it.
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

function lastCall(f: ReturnType<typeof vi.fn>): [string, RequestInit] {
  return f.mock.calls[f.mock.calls.length - 1] as [string, RequestInit];
}

describe("SDK parity runtime methods", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("listWorkflows GETs /workflows and unwraps the {workflows} payload", async () => {
    const f = mockFetch({ success: true, data: { workflows: [{ id: "w1", name: "n", description: null, tags: [], created_by: null, created_at: "t", updated_at: null }] } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.listWorkflows("11111111-1111-1111-1111-111111111111");
    const [url, init] = lastCall(f);
    expect(url).toContain("/workflows?projectId=11111111-1111-1111-1111-111111111111");
    expect(init.method).toBe("GET");
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("w1");
  });

  it("createWorkflow POSTs name+projectId and unwraps the record", async () => {
    const f = mockFetch({ success: true, data: { id: "w2", name: "My WF", description: null, tags: [], created_at: "t", updated_at: null } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.createWorkflow({ projectId: "p", name: "My WF" });
    const [url, init] = lastCall(f);
    expect(url).toContain("/workflows");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toMatchObject({ projectId: "p", name: "My WF" });
    expect(out.id).toBe("w2");
  });

  it("runWorkflow POSTs to /workflows/:id/run with inputs", async () => {
    const f = mockFetch({ success: true, data: { id: "r1", status: "pending", created_at: "t" } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.runWorkflow("wf-1", { projectId: "p", inputs: { a: 1 } });
    const [url, init] = lastCall(f);
    expect(url).toContain("/workflows/wf-1/run");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ projectId: "p", inputs: { a: 1 } });
    expect(out.status).toBe("pending");
  });

  it("listAgents GETs /agents with agentName filter", async () => {
    const f = mockFetch({ success: true, data: { agents: [], total: 0 } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.listAgents("p1", { agentName: "bot", limit: 10 });
    const [url, init] = lastCall(f);
    expect(url).toContain("/agents?projectId=p1");
    expect(url).toContain("agentName=bot");
    expect(url).toContain("limit=10");
    expect(init.method).toBe("GET");
    expect(out.total).toBe(0);
  });

  it("createAgent POSTs steps to /agents", async () => {
    const f = mockFetch({ success: true, data: { traceId: "t1", sessionId: "s1", agentName: "bot", stepsReceived: 2 } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.createAgent({ agentName: "bot", projectId: "p", steps: [{ name: "a" }, { name: "b" }] });
    const [url, init] = lastCall(f);
    expect(url).toContain("/agents");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toMatchObject({ agentName: "bot", projectId: "p" });
    expect(out.stepsReceived).toBe(2);
  });

  it("runGuardrails POSTs text to /guardrails and returns raw action shape", async () => {
    const f = mockFetch({ action: "block", reasons: [{ detail: "pii" }], latencyMs: 3 });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.runGuardrails({ text: "hello", projectId: "p" });
    const [url, init] = lastCall(f);
    expect(url).toContain("/guardrails");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ text: "hello", projectId: "p" });
    expect(out.action).toBe("block");
  });

  it("checkFirewall normalizes FirewallRule[] to category strings + forwards sensitivity/subject", async () => {
    const f = mockFetch({ success: true, data: { blocked: false, score: 0.1, category: null, subcategory: null, sensitivity: "strict", latencyMs: 2, hits: [] } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.checkFirewall({
      input: "x",
      rules: [{ id: "prompt-injection", name: "PI", type: "injection", enabled: true }],
      sensitivity: "strict",
      projectId: "p",
      subjectEmail: "u@e.com",
    });
    const [url, init] = lastCall(f);
    expect(url).toContain("/firewall/check");
    const sent = JSON.parse(init.body as string);
    expect(sent.rules).toEqual(["prompt-injection"]);
    expect(sent.sensitivity).toBe("strict");
    expect(sent.projectId).toBe("p");
    expect(sent.subjectEmail).toBe("u@e.com");
    expect(out.sensitivity).toBe("strict");
  });

  it("chatCompletions POSTs to /chat/completions and returns the raw OpenAI body", async () => {
    const f = mockFetch({ id: "chatcmpl-1", object: "chat.completion", created: 1, model: "gpt-4o", choices: [{ index: 0, message: { role: "assistant", content: "hi" }, finish_reason: "stop" }] });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.chatCompletions({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] });
    const [url, init] = lastCall(f);
    expect(url).toContain("/chat/completions");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string).stream).toBe(false);
    expect(out.choices[0].message.content).toBe("hi");
  });

  it("chatCompletions throws (no fetch) when stream is requested", async () => {
    const f = mockFetch({});
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      c.chatCompletions({ model: "gpt-4o", messages: [{ role: "user", content: "x" }], stream: true }),
    ).rejects.toThrow(/streaming/i);
    expect(f).not.toHaveBeenCalled();
  });

  it("storeEmbedding POSTs action=store", async () => {
    const f = mockFetch({ success: true, data: { id: "e1", project_id: "p", content: "lbl", metadata: {} } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.storeEmbedding({ projectId: "p", id: "e1", vector: [0.1, 0.2], label: "lbl" });
    const [url, init] = lastCall(f);
    expect(url).toContain("/embeddings");
    const sent = JSON.parse(init.body as string);
    expect(sent.action).toBe("store");
    expect(sent.vector).toEqual([0.1, 0.2]);
    expect(out.id).toBe("e1");
  });

  it("findSimilarEmbeddings POSTs action=similar with a queryVector", async () => {
    const f = mockFetch({ success: true, data: [{ id: "e1", label: "l", score: 0.9 }] });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.findSimilarEmbeddings({ projectId: "p", queryVector: [1, 0], topK: 5 });
    const [, init] = lastCall(f);
    const sent = JSON.parse(init.body as string);
    expect(sent.action).toBe("similar");
    expect(sent.topK).toBe(5);
    expect(out[0].score).toBe(0.9);
  });

  it("findSimilarEmbeddings throws (no fetch) when neither queryVector nor queryId is given", async () => {
    const f = mockFetch({ success: true, data: [] });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.findSimilarEmbeddings({ projectId: "p" })).rejects.toThrow(/queryVector or queryId/i);
    expect(f).not.toHaveBeenCalled();
  });

  it("rerank sends the x-provider-api-key header and returns the raw provider result", async () => {
    const f = mockFetch({ provider: "cohere", results: [{ index: 0, score: 0.8 }] });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.rerank(
      { orgId: "00000000-0000-0000-0000-000000000000", query: "q", documents: ["a", "b"], model: "rerank-english-v3.0" },
      "vendor-key-123",
    );
    const [url, init] = lastCall(f);
    expect(url).toContain("/retrieval/rerank");
    const headers = init.headers as Record<string, string>;
    expect(headers["x-provider-api-key"]).toBe("vendor-key-123");
    expect(out.provider).toBe("cohere");
  });

  it("rerank throws (no fetch) when the vendor key is missing", async () => {
    const f = mockFetch({});
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(
      c.rerank({ orgId: "o", query: "q", documents: ["a"], model: "m" }, ""),
    ).rejects.toThrow(/vendor API key/i);
    expect(f).not.toHaveBeenCalled();
  });

  it("hybridRetrieval POSTs the method+documents", async () => {
    const f = mockFetch({ success: true, data: { method: "bm25", results: [{ id: "d1" }] } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.hybridRetrieval({ method: "bm25", query: "q", documents: [{ id: "d1", text: "t" }] });
    const [url, init] = lastCall(f);
    expect(url).toContain("/retrieval/hybrid");
    expect(JSON.parse(init.body as string).method).toBe("bm25");
    expect(out.method).toBe("bm25");
  });

  it("corpusIntegrity POSTs documents", async () => {
    const f = mockFetch({ success: true, data: { duplicates: [], conflicts: [] } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.corpusIntegrity({ documents: [{ text: "doc" }], nearDuplicateThreshold: 0.9 });
    const [url, init] = lastCall(f);
    expect(url).toContain("/retrieval/corpus-integrity");
    const sent = JSON.parse(init.body as string);
    expect(sent.documents[0].text).toBe("doc");
    expect(sent.nearDuplicateThreshold).toBe(0.9);
  });

  it("analyzeTraceSpans POSTs spans to /traces/analyze", async () => {
    const f = mockFetch({ success: true, data: { issues: [] } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await c.analyzeTraceSpans({ spans: [{ spanId: "s" }], callLLM: false });
    const [url, init] = lastCall(f);
    expect(url).toContain("/traces/analyze");
    const sent = JSON.parse(init.body as string);
    expect(sent.callLLM).toBe(false);
    expect(sent.spans).toHaveLength(1);
  });

  it("analyzeTraceSpans throws (no fetch) when neither traceId nor spans given", async () => {
    const f = mockFetch({ success: true, data: {} });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.analyzeTraceSpans({})).rejects.toThrow(/traceId or spans/i);
    expect(f).not.toHaveBeenCalled();
  });

  it("traceToDataset POSTs a single traceId", async () => {
    const f = mockFetch({ success: true, data: { created: 1, duplicatesSkipped: 0, skipped: 0, deduplicated: 0, qualityDistribution: {}, examples: [] } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.traceToDataset({ traceId: "tr1", datasetId: "d1", projectId: "p1" });
    const [url, init] = lastCall(f);
    expect(url).toContain("/traces/to-dataset");
    expect(JSON.parse(init.body as string)).toMatchObject({ traceId: "tr1", datasetId: "d1", projectId: "p1" });
    expect(out.created).toBe(1);
  });

  it("exportTraces GETs /traces/export and returns the raw OTLP body", async () => {
    const f = mockFetch({ resourceSpans: [] });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = (await c.exportTraces("p1", { traceId: "tr1", limit: 100 })) as { resourceSpans: unknown[] };
    const [url, init] = lastCall(f);
    expect(url).toContain("/traces/export?projectId=p1");
    expect(url).toContain("traceId=tr1");
    expect(init.method).toBe("GET");
    expect(out.resourceSpans).toEqual([]);
  });

  it("importTraces POSTs platform+payload", async () => {
    const f = mockFetch({ success: true, data: { platform: "helicone", inserted: 3, failed: 0, errors: [], skippedDuplicates: 0 } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.importTraces({ platform: "helicone", projectId: "p1", payload: { data: [] } });
    const [url, init] = lastCall(f);
    expect(url).toContain("/traces/import");
    expect(JSON.parse(init.body as string).platform).toBe("helicone");
    expect(out.inserted).toBe(3);
  });

  it("aggregateTraces GETs /traces/aggregate with orgId+projectId", async () => {
    const f = mockFetch({ success: true, data: { buckets: [], bucketCount: 0, source: "postgres", fellBack: false } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.aggregateTraces({ orgId: "o1", projectId: "p1", model: "gpt-4o" });
    const [url, init] = lastCall(f);
    expect(url).toContain("/traces/aggregate?orgId=o1");
    expect(url).toContain("projectId=p1");
    expect(url).toContain("model=gpt-4o");
    expect(init.method).toBe("GET");
    expect(out.source).toBe("postgres");
  });

  it("evalCode POSTs code and unwraps the results envelope", async () => {
    const f = mockFetch({ success: true, data: { results: [{ scorer: "code-security", score: 1, passed: true }], summary: { total: 1, passed: 1, failed: 0, avg_score: 1 }, latency_ms: 5 } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.evalCode({ code: "print(1)", scorers: ["code-security"] });
    const [url, init] = lastCall(f);
    expect(url).toContain("/eval/code");
    expect(JSON.parse(init.body as string).code).toBe("print(1)");
    expect(out.summary.passed).toBe(1);
  });

  it("mcpInvoke POSTs serverId+toolName and forwards runId as a header", async () => {
    const f = mockFetch({ success: true, data: { decision: "allow", reason: "ok", response: { result: 42 }, latencyMs: 7 } });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.mcpInvoke({ serverId: "srv", toolName: "lookup", arguments: { q: "x" }, runId: "run-9" });
    const [url, init] = lastCall(f);
    expect(url).toContain("/mcp/invoke");
    const sent = JSON.parse(init.body as string);
    expect(sent).toMatchObject({ serverId: "srv", toolName: "lookup", arguments: { q: "x" } });
    expect((init.headers as Record<string, string>)["x-evalguard-mcp-run-id"]).toBe("run-9");
    expect(out.decision).toBe("allow");
  });
});
