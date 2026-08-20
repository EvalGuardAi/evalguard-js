// Phase 2 — SDK surface tests for named environments and the
// managed Tool system (create/get/list/version/deploy + env-vars).
//
// Verifies the value re-exports are reachable from `@evalguard/sdk` and that the
// new client methods (a) validate client-side where the core validators exist,
// and (b) forward the expected path/method/body on the wire.

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  EvalGuard,
  EvalGuardError,
  ENVIRONMENT_TAG_VALUES,
  SEEDED_ENVIRONMENTS,
  validateToolConfig,
} from "../index";
import type { ToolConfig } from "../index";

function mockFetchResponse(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: vi.fn().mockResolvedValue(body),
  });
}

function lastCall(mockFn: ReturnType<typeof vi.fn>) {
  const [url, init] = mockFn.mock.calls[mockFn.mock.calls.length - 1] as [
    string,
    { method: string; body?: string },
  ];
  return {
    url,
    method: init.method,
    body: init.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
  };
}

describe("SDK Phase 2 value re-exports", () => {
  it("re-exports the standard environment tag values", () => {
    expect(ENVIRONMENT_TAG_VALUES).toEqual(["default", "other"]);
    expect(SEEDED_ENVIRONMENTS).toEqual([
      { name: "production", tag: "default" },
      { name: "staging", tag: "other" },
    ]);
  });

  it("re-exports validateToolConfig (requires function OR sourceCode)", () => {
    expect(validateToolConfig({ sourceCode: "return 1;" }).valid).toBe(true);
    expect(validateToolConfig({}).valid).toBe(false);
  });
});

describe("SDK environments surface", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("createEnvironment forwards name + tag on the wire", async () => {
    const mockFn = mockFetchResponse({ id: "env_1" });
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await client.createEnvironment({ projectId: "proj-1", name: "eu-prod", tag: "other" });
    const call = lastCall(mockFn);
    expect(call.method).toBe("POST");
    expect(call.url).toMatch(/\/environments$/);
    expect(call.body).toMatchObject({ name: "eu-prod", tag: "other" });
  });

  it("createEnvironment rejects an empty name before any network call", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await expect(
      client.createEnvironment({ projectId: "proj-1", name: "  " }),
    ).rejects.toBeInstanceOf(EvalGuardError);
    expect(mockFn).not.toHaveBeenCalled();
  });

  it("listEnvironments + removeEnvironment use the right method + path", async () => {
    const mockFn = mockFetchResponse([]);
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });

    await client.listEnvironments("proj-1");
    expect(lastCall(mockFn).method).toBe("GET");
    expect(lastCall(mockFn).url).toContain("/environments?projectId=proj-1");

    await client.removeEnvironment("proj-1", "eu-prod");
    expect(lastCall(mockFn).method).toBe("DELETE");
    // Flat route: DELETE /environments?name= (NOT the 404 path style /environments/{name}).
    expect(lastCall(mockFn).url).toContain("/environments?name=eu-prod");
    expect(lastCall(mockFn).url).not.toMatch(/\/environments\/eu-prod/);
  });

  it("setPromptDeployment posts to the flat route with { name, version, env }", async () => {
    const mockFn = mockFetchResponse({ id: "d1" });
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await client.setPromptDeployment({
      projectId: "proj-1",
      name: "greeter",
      environment: "staging",
      version: 3,
    });
    const call = lastCall(mockFn);
    expect(call.method).toBe("POST");
    // Flat route: POST /prompts/deployments (NOT /prompts/{name}/deployments).
    expect(call.url).toMatch(/\/prompts\/deployments$/);
    expect(call.url).not.toMatch(/\/prompts\/greeter\/deployments/);
    // Body uses the route's contract: { name, version, env } — NOT { environment }.
    expect(call.body).toMatchObject({ name: "greeter", version: 3, env: "staging" });
    expect(call.body).not.toHaveProperty("environment");
  });

  it("removePromptDeployment throws (no server-side DELETE route)", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });

    await expect(
      client.removePromptDeployment({ projectId: "proj-1", name: "greeter", environment: "staging" }),
    ).rejects.toBeInstanceOf(EvalGuardError);
    // It must not silently fire a 404-ing DELETE.
    expect(mockFn).not.toHaveBeenCalled();
  });

  it("listPromptEnvironments hits the flat deployments route", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });

    await client.listPromptEnvironments("proj-1", "greeter");
    expect(lastCall(mockFn).method).toBe("GET");
    // Flat route: GET /prompts/deployments?name= (NOT /prompts/{name}/environments).
    expect(lastCall(mockFn).url).toContain("/prompts/deployments?name=greeter");
    expect(lastCall(mockFn).url).not.toMatch(/\/prompts\/greeter\/environments/);
  });
});

describe("SDK tools surface", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  const weatherConfig: ToolConfig = {
    function: {
      name: "get_weather",
      description: "Get the current weather for a location.",
      parameters: { type: "object", properties: { location: { type: "string" } } },
    },
    sourceCode: "return 'sunny';",
  };

  it("createTool validates the config and forwards it on the wire", async () => {
    const mockFn = mockFetchResponse({ id: "tl_1" });
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await client.createTool({ projectId: "proj-1", name: "weather", config: weatherConfig });
    const call = lastCall(mockFn);
    expect(call.method).toBe("POST");
    expect(call.url).toMatch(/\/tools$/);
    expect((call.body as { config: ToolConfig }).config.function?.name).toBe("get_weather");
  });

  it("createTool rejects a config with no callable identity before any network call", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await expect(
      client.createTool({ projectId: "proj-1", name: "bad", config: {} as ToolConfig }),
    ).rejects.toBeInstanceOf(EvalGuardError);
    expect(mockFn).not.toHaveBeenCalled();
  });

  it("getTool / listTools / listToolVersions build the right flat paths", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });

    await client.getTool("proj-1", "weather", 2);
    // Flat route: GET /tools?name=&version= (NOT /tools/{name}).
    expect(lastCall(mockFn).url).toContain("/tools?name=weather&version=2");
    expect(lastCall(mockFn).url).not.toMatch(/\/tools\/weather/);

    await client.getTool("proj-1", "weather");
    expect(lastCall(mockFn).url).toContain("/tools?name=weather");
    expect(lastCall(mockFn).url).not.toContain("version=");

    await client.listTools("proj-1");
    expect(lastCall(mockFn).url).toMatch(/\/tools\?projectId=proj-1/);

    await client.listToolVersions("proj-1", "weather");
    // Flat route: GET /tools?name= (NOT /tools/{name}/versions).
    expect(lastCall(mockFn).url).toContain("/tools?name=weather");
    expect(lastCall(mockFn).url).not.toMatch(/\/tools\/weather\/versions/);
  });

  it("setToolDeployment / removeToolDeployment / listToolEnvironments hit the flat route", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });

    await client.setToolDeployment({ projectId: "proj-1", name: "weather", environment: "production", version: 1 });
    let call = lastCall(mockFn);
    expect(call.method).toBe("POST");
    // Flat route: POST /tools/deployments (NOT /tools/{name}/deployments).
    expect(call.url).toMatch(/\/tools\/deployments$/);
    expect(call.url).not.toMatch(/\/tools\/weather\/deployments/);
    // Body uses the route's contract: { toolName, version, env } — NOT { name, environment }.
    expect(call.body).toMatchObject({ toolName: "weather", version: 1, env: "production" });
    expect(call.body).not.toHaveProperty("environment");

    await client.removeToolDeployment({ projectId: "proj-1", name: "weather", environment: "production" });
    call = lastCall(mockFn);
    expect(call.method).toBe("DELETE");
    // Flat route: DELETE /tools/deployments?name=&env=.
    expect(call.url).toMatch(/\/tools\/deployments\?/);
    expect(call.url).toContain("name=weather");
    expect(call.url).toContain("env=production");
    expect(call.url).not.toMatch(/\/tools\/weather\/deployments/);

    await client.listToolEnvironments("proj-1", "weather");
    // Flat route: GET /tools/deployments?name= (NOT /tools/{name}/environments).
    expect(lastCall(mockFn).url).toContain("/tools/deployments?name=weather");
    expect(lastCall(mockFn).url).not.toMatch(/\/tools\/weather\/environments/);
  });

  it("tool environment variables: get / add / delete hit the flat env-vars route", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });

    await client.getToolEnvironmentVariables("proj-1", "weather");
    // Flat route: GET /tools/env-vars?name= (NOT /tools/{name}/environment-variables).
    expect(lastCall(mockFn).url).toContain("/tools/env-vars?name=weather");
    expect(lastCall(mockFn).url).not.toMatch(/\/tools\/weather\/environment-variables/);

    await client.addToolEnvironmentVariable({
      projectId: "proj-1",
      name: "weather",
      variable: { name: "API_KEY", value: "k1" },
    });
    let call = lastCall(mockFn);
    expect(call.method).toBe("POST");
    expect(call.url).toMatch(/\/tools\/env-vars$/);
    // Body uses the route's contract: { name, variables: [{ name, value }] } — NOT { variable }.
    expect(call.body).toMatchObject({ name: "weather", variables: [{ name: "API_KEY", value: "k1" }] });
    expect(call.body).not.toHaveProperty("variable");

    await client.deleteToolEnvironmentVariable("proj-1", "weather", "API_KEY");
    call = lastCall(mockFn);
    expect(call.method).toBe("DELETE");
    // Flat route: DELETE /tools/env-vars?name=&varName=.
    expect(call.url).toMatch(/\/tools\/env-vars\?/);
    expect(call.url).toContain("name=weather");
    expect(call.url).toContain("varName=API_KEY");
    expect(call.url).not.toMatch(/\/tools\/weather\/environment-variables/);
  });

  it("addToolEnvironmentVariable rejects an empty var name before any network call", async () => {
    const mockFn = mockFetchResponse({});
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await expect(
      client.addToolEnvironmentVariable({
        projectId: "proj-1",
        name: "weather",
        variable: { name: "  ", value: "x" },
      }),
    ).rejects.toBeInstanceOf(EvalGuardError);
    expect(mockFn).not.toHaveBeenCalled();
  });
});
