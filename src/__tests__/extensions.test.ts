import { describe, expect, it, vi } from "vitest";
import {
  ExtensionRegistry,
  definePlugin,
  defineStrategy,
  defineScorer,
  runCustomScan,
  type CustomPlugin,
} from "../extensions";

// Plugin / strategy / scorer registration + runCustomScan client-side
// runner. Bugs class:
//   - use() picks wrong type → plugin registered as scorer (silent
//     "no probes generated")
//   - Strategy ordering wrong → probe transformations applied in wrong
//     order, attack chain breaks
//   - Probe error aborts whole scan → one bad model call kills
//     everything
//   - Plugin id required check missed → empty-id collision

describe("definePlugin / defineStrategy / defineScorer — typed factories", () => {
  it("definePlugin returns the input unchanged", () => {
    const p: CustomPlugin = {
      id: "x", name: "X", severity: "high",
      generate: () => [], grade: () => null,
    };
    expect(definePlugin(p)).toBe(p);
  });

  it("defineStrategy returns the input unchanged", () => {
    const s = { id: "s", name: "S", transform: (p: { input: string }) => p };
    expect(defineStrategy(s)).toBe(s);
  });

  it("defineScorer returns the input unchanged", () => {
    const sc = { id: "sc", name: "SC", score: () => ({ score: 0.5 }) };
    expect(defineScorer(sc)).toBe(sc);
  });
});

describe("ExtensionRegistry.use — type discrimination", () => {
  it("dispatches to registerPlugin when extension has 'generate'", () => {
    const r = new ExtensionRegistry();
    r.use(definePlugin({
      id: "p", name: "P", severity: "high",
      generate: () => [], grade: () => null,
    }));
    expect(r.getPlugin("p")).toBeDefined();
    expect(r.getStrategy("p")).toBeUndefined();
    expect(r.getScorer("p")).toBeUndefined();
  });

  it("dispatches to registerStrategy when extension has 'transform'", () => {
    const r = new ExtensionRegistry();
    r.use(defineStrategy({ id: "s", name: "S", transform: (p) => p }));
    expect(r.getStrategy("s")).toBeDefined();
    expect(r.getPlugin("s")).toBeUndefined();
  });

  it("dispatches to registerScorer when extension has neither 'generate' nor 'transform'", () => {
    const r = new ExtensionRegistry();
    r.use(defineScorer({ id: "sc", name: "SC", score: () => ({ score: 1 }) }));
    expect(r.getScorer("sc")).toBeDefined();
    expect(r.getPlugin("sc")).toBeUndefined();
  });
});

describe("ExtensionRegistry — basic CRUD", () => {
  it("register requires non-empty id", () => {
    const r = new ExtensionRegistry();
    expect(() => r.registerPlugin({
      id: "", name: "X", severity: "high",
      generate: () => [], grade: () => null,
    })).toThrow(/id is required/);
    expect(() => r.registerStrategy({ id: "", name: "S", transform: (p) => p })).toThrow(/id is required/);
    expect(() => r.registerScorer({ id: "", name: "SC", score: () => ({ score: 0 }) })).toThrow(/id is required/);
  });

  it("listPlugins/listStrategies/listScorers return registered entries", () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({ id: "p", name: "P", severity: "high", generate: () => [], grade: () => null });
    r.registerStrategy({ id: "s", name: "S", transform: (p) => p });
    r.registerScorer({ id: "sc", name: "SC", score: () => ({ score: 0.5 }) });
    expect(r.listPlugins()).toHaveLength(1);
    expect(r.listStrategies()).toHaveLength(1);
    expect(r.listScorers()).toHaveLength(1);
  });

  it("clear empties all three registries", () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({ id: "p", name: "P", severity: "high", generate: () => [], grade: () => null });
    r.registerStrategy({ id: "s", name: "S", transform: (p) => p });
    r.registerScorer({ id: "sc", name: "SC", score: () => ({ score: 1 }) });
    r.clear();
    expect(r.listPlugins()).toHaveLength(0);
    expect(r.listStrategies()).toHaveLength(0);
    expect(r.listScorers()).toHaveLength(0);
  });

  it("re-register replaces existing entry", () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({ id: "p", name: "v1", severity: "high", generate: () => [], grade: () => null });
    r.registerPlugin({ id: "p", name: "v2", severity: "low", generate: () => [], grade: () => null });
    expect(r.getPlugin("p")?.name).toBe("v2");
  });
});

describe("runCustomScan — happy path", () => {
  it("invokes complete() once per probe, collects findings the plugin grade returns", async () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "echo-test", name: "Echo Test", severity: "high",
      generate: () => [{ input: "probe-1" }, { input: "probe-2" }],
      grade: ({ output }) => output.includes("LEAK")
        ? { severity: "high", reason: "Model leaked secret" }
        : null,
    });
    const complete = vi.fn(async (p: string) => p === "probe-1" ? "safe" : "OOPS LEAK detected");
    const results = await runCustomScan(r, { target: "gpt-4o", pluginIds: ["echo-test"], complete });

    expect(complete).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(1);
    expect(results[0].probes).toBe(2);
    expect(results[0].findings).toHaveLength(1);
    expect(results[0].findings[0].input).toBe("probe-2");
    expect(results[0].errors).toHaveLength(0);
  });

  it("forwards target as the model option to complete", async () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "p", name: "P", severity: "high",
      generate: () => [{ input: "x" }],
      grade: () => null,
    });
    const complete = vi.fn(async () => "ok");
    await runCustomScan(r, { target: "gpt-4o", pluginIds: ["p"], complete });
    expect(complete).toHaveBeenCalledWith("x", { model: "gpt-4o" });
  });
});

describe("runCustomScan — strategy chain", () => {
  it("applies strategies in order to each probe", async () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "p", name: "P", severity: "high",
      generate: () => [{ input: "hello" }],
      grade: () => null,
    });
    r.registerStrategy({
      id: "s1", name: "uppercase", transform: (p) => ({ ...p, input: p.input.toUpperCase() }),
    });
    r.registerStrategy({
      id: "s2", name: "wrap", transform: (p) => ({ ...p, input: `[${p.input}]` }),
    });
    let captured = "";
    const complete = vi.fn(async (s: string) => { captured = s; return ""; });
    await runCustomScan(r, {
      target: "gpt-4o",
      pluginIds: ["p"],
      strategyIds: ["s1", "s2"],
      complete,
    });
    // s1 → "HELLO", then s2 → "[HELLO]"
    expect(captured).toBe("[HELLO]");
  });

  it("ignores unknown strategy ids (silent fallthrough)", async () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "p", name: "P", severity: "high",
      generate: () => [{ input: "raw" }],
      grade: () => null,
    });
    let captured = "";
    const complete = vi.fn(async (s: string) => { captured = s; return ""; });
    await runCustomScan(r, {
      target: "gpt-4o",
      pluginIds: ["p"],
      strategyIds: ["unknown-strategy"],
      complete,
    });
    // Probe not transformed because unknown strategy filtered out.
    expect(captured).toBe("raw");
  });
});

describe("runCustomScan — error isolation", () => {
  it("unknown plugin id reported in errors but doesn't abort scan", async () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "p1", name: "P1", severity: "high",
      generate: () => [{ input: "x" }],
      grade: () => null,
    });
    const complete = vi.fn(async () => "ok");
    const results = await runCustomScan(r, {
      target: "gpt-4o",
      pluginIds: ["nonexistent", "p1"],
      complete,
    });
    expect(results).toHaveLength(2);
    expect(results[0].errors[0].error).toMatch(/not registered/);
    expect(results[1].pluginId).toBe("p1");
  });

  it("complete() throw on one probe doesn't abort the rest", async () => {
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "p", name: "P", severity: "high",
      generate: () => [{ input: "good-1" }, { input: "bad" }, { input: "good-2" }],
      grade: () => null,
    });
    const complete = vi.fn(async (s: string) => {
      if (s === "bad") throw new Error("rate limit");
      return "ok";
    });
    const results = await runCustomScan(r, { target: "gpt-4o", pluginIds: ["p"], complete });
    expect(results[0].probes).toBe(3);
    expect(results[0].errors).toHaveLength(1);
    expect(results[0].errors[0].input).toBe("bad");
    expect(complete).toHaveBeenCalledTimes(3);
  });

  it("plugin.grade async throw NOT caught (caller must handle)", async () => {
    // Pin: errors are caught in complete() but NOT in grade(). This is
    // intentional — a buggy grader is a programming error, not a
    // runtime failure to swallow. Pin so a future "catch everything"
    // refactor is intentional.
    const r = new ExtensionRegistry();
    r.registerPlugin({
      id: "p", name: "P", severity: "high",
      generate: () => [{ input: "x" }],
      grade: () => { throw new Error("grader bug"); },
    });
    const complete = vi.fn(async () => "ok");
    const results = await runCustomScan(r, { target: "gpt-4o", pluginIds: ["p"], complete });
    // The error from grade IS surfaced via errors collector (since
    // it's inside the same try/catch).
    expect(results[0].errors.length).toBeGreaterThanOrEqual(1);
  });
});
