import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard } from "../client";

function mockFetch(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: vi.fn().mockResolvedValue(body),
  });
}
function enveloped(data: unknown) {
  return { success: true, data };
}

describe("EvalGuard SDK — agent memory", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("rememberMemory: POST /agent-memory with facts", async () => {
    const f = mockFetch(enveloped({ written: ["likes coffee"], skipped: [] }), 201);
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.rememberMemory({ projectId: "p", sessionKey: "u1", facts: ["likes coffee"] });
    expect(f.mock.calls[0][0]).toContain("/agent-memory");
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toMatchObject({ projectId: "p", sessionKey: "u1", facts: ["likes coffee"] });
    expect(out.written).toEqual(["likes coffee"]);
  });

  it("rememberMemory: throws when neither facts nor turns provided", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.rememberMemory({ projectId: "p", sessionKey: "u1" })).rejects.toThrow(/facts|turns/);
    expect(f).not.toHaveBeenCalled();
  });

  it("recallMemory: GET /agent-memory with query params", async () => {
    const f = mockFetch(enveloped({ semantic: [{ content: "likes coffee", score: 0.9 }] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.recallMemory({ projectId: "p", sessionKey: "u1", query: "coffee", limit: 3 });
    const url = f.mock.calls[0][0] as string;
    expect(url).toContain("/agent-memory?");
    expect(url).toContain("query=coffee");
    expect(url).toContain("limit=3");
    expect(out.semantic[0].content).toBe("likes coffee");
  });

  it("forgetMemory: DELETE /agent-memory", async () => {
    const f = mockFetch(enveloped({ forgotten: 2 }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.forgetMemory({ projectId: "p", sessionKey: "u1" });
    expect((f.mock.calls[0][1] as RequestInit).method).toBe("DELETE");
    expect(out.forgotten).toBe(2);
  });
});

describe("EvalGuard SDK — voice ML", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("transcribeVoice: POST /voice/transcribe and returns word timings", async () => {
    const f = mockFetch(enveloped({ language: "en", text: "hi", words: [{ word: "hi", startMs: 0, endMs: 200 }] }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.transcribeVoice({ projectId: "p", audioBase64: "d2F2", language: "en" });
    expect(f.mock.calls[0][0]).toContain("/voice/transcribe");
    expect(out.words[0].word).toBe("hi");
  });

  it("transcribeVoice: throws on missing audio before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.transcribeVoice({ projectId: "p", audioBase64: "" })).rejects.toThrow(/audioBase64/);
    expect(f).not.toHaveBeenCalled();
  });

  it("scoreVoiceDeepfake: POST /voice/deepfake-score and returns probability", async () => {
    const f = mockFetch(enveloped({ probability: 0.97, model: "x" }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.scoreVoiceDeepfake({ projectId: "p", audioBase64: "d2F2" });
    expect(f.mock.calls[0][0]).toContain("/voice/deepfake-score");
    expect(out.probability).toBeCloseTo(0.97, 5);
  });
});

describe("EvalGuard SDK — language detection", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("detectLanguage: POST /language/detect and returns the detection", async () => {
    const f = mockFetch(enveloped({ iso6393: "fra", iso6391: "fr", name: "French", confidence: 0.4, reliable: true }));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.detectLanguage({ projectId: "p", text: "Bonjour tout le monde" });
    expect(f.mock.calls[0][0]).toContain("/language/detect");
    expect(out.iso6391).toBe("fr");
    expect(out.reliable).toBe(true);
  });

  it("detectLanguage: throws on missing text before any fetch", async () => {
    const f = mockFetch(enveloped({}));
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.detectLanguage({ projectId: "p", text: "" })).rejects.toThrow(/text/);
    expect(f).not.toHaveBeenCalled();
  });
});
