// Typed prompt artifact — SDK surface tests.
//
// Verifies that the typed `PromptConfig` / template / `.prompt` (de)serialize
// helpers are reachable from `@evalguard/sdk` (value re-exports of the core
// implementation) and that `createPrompt` accepts + validates the typed fields
// without breaking the legacy opaque-content path.

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  EvalGuard,
  EvalGuardError,
  // Value re-exports under test:
  MODEL_ENDPOINT_VALUES,
  MODEL_PROVIDER_VALUES,
  TEMPLATE_LANGUAGE_VALUES,
  OPENAI_REASONING_EFFORT_VALUES,
  RESPONSE_FORMAT_TYPE_VALUES,
  CHAT_ROLE_VALUES,
  validatePromptConfig,
  isChatTemplate,
  extractTemplateVariables,
  validateTemplateInputs,
  renderPromptTemplate,
  renderStringTemplate,
  MissingTemplateInputError,
  serializePromptFile,
  parsePromptFile,
  promptFileFrom,
} from "../index";
import type { PromptConfig, PromptFile, ChatTemplate } from "../index";

function mockFetchResponse(body: unknown, status = 200, ok = true) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? "OK" : "Error",
    json: vi.fn().mockResolvedValue(body),
  });
}

describe("SDK typed prompt artifact surface", () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── Enum VALUE arrays are re-exported and match the standard LLM identifiers ──
  it("re-exports the standard enum value arrays", () => {
    expect(MODEL_ENDPOINT_VALUES).toEqual(["complete", "chat", "edit"]);
    expect(MODEL_PROVIDER_VALUES).toEqual([
      "anthropic",
      "bedrock",
      "cohere",
      "deepseek",
      "google",
      "groq",
      "mock",
      "openai",
      "openai_azure",
      "replicate",
    ]);
    expect(TEMPLATE_LANGUAGE_VALUES).toEqual(["default", "jinja"]);
    expect(OPENAI_REASONING_EFFORT_VALUES).toEqual(["high", "medium", "low"]);
    expect(RESPONSE_FORMAT_TYPE_VALUES).toEqual(["json_object", "json_schema"]);
    expect(CHAT_ROLE_VALUES).toEqual(["user", "assistant", "system", "tool", "developer"]);
  });

  // ── validatePromptConfig ──────────────────────────────────────────────────
  it("validates a good config and rejects out-of-range knobs", () => {
    expect(validatePromptConfig({ model: "gpt-4o", temperature: 0.7 }).valid).toBe(true);

    const bad = validatePromptConfig({ model: "", topP: 2, presencePenalty: 5 });
    expect(bad.valid).toBe(false);
    expect(bad.errors.length).toBeGreaterThanOrEqual(3);
  });

  // ── Template helpers ──────────────────────────────────────────────────────
  it("extracts, validates and renders template variables", () => {
    const chat: ChatTemplate = [
      { role: "system", content: "You are {{persona}}." },
      { role: "user", content: "{{question}}" },
    ];
    expect(isChatTemplate(chat)).toBe(true);
    expect(extractTemplateVariables(chat)).toEqual(["persona", "question"]);

    const v = validateTemplateInputs(chat, { persona: "a helpful bot" });
    expect(v.valid).toBe(false);
    expect(v.missing).toEqual(["question"]);

    const rendered = renderPromptTemplate(chat, { persona: "a bot", question: "hi" });
    expect(rendered).toEqual([
      { role: "system", content: "You are a bot." },
      { role: "user", content: "hi" },
    ]);
  });

  it("throws MissingTemplateInputError in strict mode", () => {
    expect(() => renderStringTemplate("Hello {{name}}", {})).toThrow(MissingTemplateInputError);
    try {
      renderStringTemplate("Hello {{name}}", {});
    } catch (err) {
      expect(err).toBeInstanceOf(MissingTemplateInputError);
      expect((err as MissingTemplateInputError).missing).toEqual(["name"]);
    }
  });

  // ── .prompt (de)serialize round-trip ──────────────────────────────────────
  it("round-trips a .prompt file losslessly", () => {
    const file: PromptFile = {
      config: {
        model: "gpt-4o",
        provider: "openai",
        maxTokens: 1024,
        temperature: 0.7,
        responseFormat: { type: "json_object" },
        tools: [{ name: "search", description: "Search the web" }],
      },
      template: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "{{question}}" },
      ],
      templateLanguage: "jinja",
    };
    const text = serializePromptFile(file);
    expect(parsePromptFile(text)).toEqual(file);
    // Idempotent on the serialized form too.
    expect(serializePromptFile(parsePromptFile(text))).toBe(text);
  });

  it("produces the canonical cross-language .prompt byte layout", () => {
    const file: PromptFile = {
      config: { model: "gpt-4o", provider: "openai", maxTokens: 1024, temperature: 0.7 },
      template: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "{{question}}" },
      ],
    };
    const expected =
      "---\n" +
      'model: "gpt-4o"\n' +
      'provider: "openai"\n' +
      "maxTokens: 1024\n" +
      "temperature: 0.7\n" +
      "---\n" +
      "\n" +
      "<system>\nYou are a helpful assistant.\n</system>\n" +
      "<user>\n{{question}}\n</user>\n";
    expect(serializePromptFile(file)).toBe(expected);
  });

  it("serializePromptFile throws on invalid config", () => {
    expect(() => serializePromptFile({ config: { model: "" } })).toThrow();
  });

  it("promptFileFrom bridges a typed version and rejects content-only", () => {
    const cfg: PromptConfig = { model: "claude-3-5-sonnet" };
    expect(promptFileFrom({ config: cfg }).config).toEqual(cfg);
    expect(() => promptFileFrom({})).toThrow();
  });

  // ── createPrompt typed path ───────────────────────────────────────────────
  it("createPrompt still accepts opaque content (back-compat)", async () => {
    const mockFn = mockFetchResponse({ id: "p1" });
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await client.createPrompt({ projectId: "proj-1", name: "greeter", content: "Say hi" });
    const body = JSON.parse((mockFn.mock.calls[0][1] as { body: string }).body) as Record<
      string,
      unknown
    >;
    expect(body.content).toBe("Say hi");
    expect(body.config).toBeUndefined();
  });

  it("createPrompt forwards the typed config/template on the wire", async () => {
    const mockFn = mockFetchResponse({ id: "p2" });
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await client.createPrompt({
      projectId: "proj-1",
      name: "greeter",
      content: "unused",
      config: { model: "gpt-4o", temperature: 0.5 },
      template: [{ role: "system", content: "You are helpful." }],
      templateLanguage: "default",
    });
    const body = JSON.parse((mockFn.mock.calls[0][1] as { body: string }).body) as {
      config: PromptConfig;
      templateLanguage: string;
    };
    expect(body.config.model).toBe("gpt-4o");
    expect(body.templateLanguage).toBe("default");
  });

  it("createPrompt rejects an invalid config before any network call", async () => {
    const mockFn = mockFetchResponse({ id: "p3" });
    globalThis.fetch = mockFn;
    const client = new EvalGuard({ apiKey: "eg_test" });
    await expect(
      client.createPrompt({
        projectId: "proj-1",
        name: "bad",
        content: "x",
        config: { model: "", temperature: 0.5 } as PromptConfig,
      }),
    ).rejects.toBeInstanceOf(EvalGuardError);
    expect(mockFn).not.toHaveBeenCalled();
  });
});
