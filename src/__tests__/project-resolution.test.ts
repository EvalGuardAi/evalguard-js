import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, EvalGuardError } from "../client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * A fetch mock that routes by URL so a single client call can transparently
 * make two requests (GET /project/current then the project-scoped call). Each
 * response body is returned RAW; /project/current intentionally returns the
 * un-enveloped `{ projectId, orgId }` shape the #622 endpoint emits.
 */
function routedFetch(routes: Array<{ match: string; body: unknown; status?: number }>) {
  return vi.fn().mockImplementation((url: string) => {
    const route = routes.find((r) => url.includes(r.match));
    const status = route?.status ?? 200;
    return Promise.resolve({
      ok: status >= 200 && status < 300,
      status,
      statusText: status === 200 ? "OK" : "Error",
      headers: { get: () => null },
      json: vi.fn().mockResolvedValue(route?.body ?? {}),
    });
  });
}

const PROJECT_CURRENT = "/project/current";

describe("EvalGuard project auto-resolution", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("fetches /project/current and uses the returned id when projectId is omitted", async () => {
    const mockFn = routedFetch([
      { match: PROJECT_CURRENT, body: { projectId: "proj-resolved", orgId: "org-1" } },
      { match: "/evals", body: { id: "eval-1" } },
    ]);
    globalThis.fetch = mockFn;

    const client = new EvalGuard({ apiKey: "key" });
    await client.eval({
      name: "no-project",
      model: "gpt-4o",
      prompt: "{{input}}",
      cases: [{ input: "hi" }],
      scorers: ["contains"],
    });

    // First call resolves the project (Bearer apiKey, GET).
    expect(mockFn).toHaveBeenNthCalledWith(
      1,
      "https://evalguard.ai/api/v1/project/current",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: "Bearer key" }),
      })
    );

    // Second call is the eval POST, carrying the resolved projectId.
    const evalCall = mockFn.mock.calls[1];
    expect(evalCall[0]).toBe("https://evalguard.ai/api/v1/evals");
    expect(JSON.parse(evalCall[1].body).projectId).toBe("proj-resolved");
  });

  it("skips /project/current when an explicit projectId is passed", async () => {
    const mockFn = routedFetch([
      { match: PROJECT_CURRENT, body: { projectId: "should-not-be-used", orgId: "org-1" } },
      { match: "/security", body: { id: "scan-1" } },
    ]);
    globalThis.fetch = mockFn;

    const client = new EvalGuard({ apiKey: "key" });
    await client.securityScan({
      projectId: "explicit-proj",
      model: "gpt-4o",
      prompt: "system",
      attackTypes: ["jailbreak"],
    });

    // Only the security call fired — no /project/current lookup.
    expect(mockFn).toHaveBeenCalledTimes(1);
    const url = mockFn.mock.calls[0][0] as string;
    expect(url).toContain("/security");
    expect(url).not.toContain(PROJECT_CURRENT);
    expect(JSON.parse(mockFn.mock.calls[0][1].body).projectId).toBe("explicit-proj");
  });

  it("caches the resolved project across calls (one /project/current fetch total)", async () => {
    const mockFn = routedFetch([
      { match: PROJECT_CURRENT, body: { projectId: "proj-cached", orgId: "org-1" } },
      { match: "/evals", body: [] },
      { match: "/security", body: { id: "scan-2" } },
    ]);
    globalThis.fetch = mockFn;

    const client = new EvalGuard({ apiKey: "key" });
    await client.eval({
      name: "first",
      model: "gpt-4o",
      prompt: "{{input}}",
      cases: [{ input: "a" }],
      scorers: ["contains"],
    });
    await client.listEvals();

    const projectCalls = mockFn.mock.calls.filter((c) =>
      (c[0] as string).includes(PROJECT_CURRENT)
    );
    expect(projectCalls).toHaveLength(1);

    // The cached id is reused on the second (list) call.
    const listCall = mockFn.mock.calls.find((c) => (c[0] as string).includes("/evals?"));
    expect(listCall?.[0]).toBe("https://evalguard.ai/api/v1/evals?projectId=proj-cached");
  });

  it("throws a clear error when no project can be resolved", async () => {
    const mockFn = routedFetch([{ match: PROJECT_CURRENT, body: { projectId: "", orgId: "" } }]);
    globalThis.fetch = mockFn;

    const client = new EvalGuard({ apiKey: "key" });
    await expect(
      client.eval({
        name: "x",
        model: "gpt-4o",
        prompt: "{{input}}",
        cases: [{ input: "a" }],
        scorers: ["contains"],
      })
    ).rejects.toThrow(/pass projectId explicitly/);

    // resolveProjectId surfaces a typed error.
    await expect(client.resolveProjectId()).rejects.toBeInstanceOf(EvalGuardError);
  });
});
