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

describe("EvalGuard SDK — ragIngest", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("POSTs documents to /rag/ingest and unwraps the data envelope", async () => {
    const f = mockFetch({
      success: true,
      data: { chunks: [{ id: "d::0", documentId: "d", index: 0, text: "hi", startChar: 0, endChar: 2 }], chunkCount: 1, embedded: false },
    });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    const out = await c.ragIngest({ documents: [{ text: "hi" }], chunking: { strategy: "recursive" } });

    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/rag/ingest");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string).documents[0].text).toBe("hi");
    expect(out.chunkCount).toBe(1);
    expect(out.embedded).toBe(false);
  });

  it("throws before any fetch when documents is empty", async () => {
    const f = mockFetch({ success: true, data: {} });
    globalThis.fetch = f;
    const c = new EvalGuard({ apiKey: "eg_k" });
    await expect(c.ragIngest({ documents: [] })).rejects.toThrow(/at least one document/i);
    expect(f).not.toHaveBeenCalled();
  });
});
