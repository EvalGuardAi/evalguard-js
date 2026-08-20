/**
 * Sandbox awareness (SDK 3.1.0).
 *
 * The value of this module is entirely in DETECTION and in NOT firing: a
 * diagnostic that warns on a working deployment is worse than no diagnostic,
 * and one that stays quiet when egress is genuinely blocked leaves the
 * original `TypeError: fetch failed` in place. Both directions are pinned
 * here.
 *
 * The detection/parsing logic is duplicated by design with
 * `@evalguard/nemoclaw` and held identical by
 * scripts/duplicated-source-drift-check.mjs.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  detectSandbox,
  isNemoClawEnv,
  readSandboxPolicy,
  isHostAllowedByPolicy,
  isEvalGuardAllowed,
  diagnoseSandboxEgress,
} from "../sandbox";
import { warnIfSandboxBlocks, resetSandboxWarnings } from "../sandbox";
// Static, not dynamic: client.ts pulls in @evalguard/core and takes seconds
// to evaluate, which blew the 5s per-test budget when imported inside the test.
import { EvalGuard } from "../client";

const ENV_KEYS = [
  "OPENCLAW_SANDBOX_ID",
  "NEMOCLAW_SANDBOX_ID",
  "NVIDIA_NEMOCLAW_ID",
  "OPENCLAW_AGENT_ID",
  "OPENCLAW_VERSION",
  "OPENCLAW_NETWORK",
  "NEMOCLAW_NETWORK",
  "OPENCLAW_POLICY_FILE",
  "NEMOCLAW_POLICY_FILE",
  "EVALGUARD_SUPPRESS_SANDBOX_WARNING",
];

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "eg-sandbox-"));
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    delete process.env[k];
    delete (Object.prototype as Record<string, unknown>)[k];
  }
  resetSandboxWarnings();
  rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

/** Write a policy file and point the detector at it. */
function policyFile(yaml: string): string {
  const p = join(dir, "openclaw-sandbox.yaml");
  writeFileSync(p, yaml);
  process.env.OPENCLAW_POLICY_FILE = p;
  return p;
}

// ── detection ───────────────────────────────────────────────────────────────

describe("detectSandbox", () => {
  it("reports no sandbox in an ordinary process", () => {
    // The host running this test is not a NemoClaw sandbox, so nothing may be
    // inferred from the ambient filesystem.
    expect(isNemoClawEnv()).toBe(false);
  });

  it("detects a sandbox from the env var and carries the ids through", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_abc123";
    process.env.OPENCLAW_AGENT_ID = "agent_xyz";
    process.env.OPENCLAW_VERSION = "0.4.2";

    const info = detectSandbox();
    expect(info.isNemoClaw).toBe(true);
    expect(info.sandboxId).toBe("sb_abc123");
    expect(info.agentId).toBe("agent_xyz");
    expect(info.runtimeVersion).toBe("0.4.2");
    expect(info.hasNetwork).toBe(true);
  });

  it("reports hasNetwork=false when the sandbox declares egress disabled", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_1";
    process.env.OPENCLAW_NETWORK = "disabled";
    expect(detectSandbox().hasNetwork).toBe(false);
  });

  it("leaves hasNetwork undefined outside a sandbox", () => {
    // Reporting "no network" for a normal process would be a lie about an
    // environment we never detected.
    expect(detectSandbox().hasNetwork).toBeUndefined();
  });

  // ── prototype pollution ──────────────────────────────────────────────────
  //
  // `process.env[name]` walks the prototype chain: Node's env interceptor
  // declines a name absent from the real environment and V8 falls through to
  // Object.prototype. This is the same defect class that shipped a fail-open
  // in @evalguard/nemoclaw 1.0.2.

  it("an INHERITED sandbox id does not fake a sandbox", () => {
    (Object.prototype as Record<string, unknown>).OPENCLAW_SANDBOX_ID = "sb_forged";
    // The plain read returns the forged value — that is the defect being contained.
    expect((process.env as Record<string, unknown>).OPENCLAW_SANDBOX_ID).toBe("sb_forged");
    expect(isNemoClawEnv()).toBe(false);
    expect(detectSandbox().sandboxId).toBeUndefined();
  });

  it("an INHERITED network flag cannot claim a real sandbox is offline", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_real";
    (Object.prototype as Record<string, unknown>).OPENCLAW_NETWORK = "disabled";
    expect(detectSandbox().hasNetwork).toBe(true);
  });

  it("an INHERITED policy path cannot redirect the policy read", () => {
    const p = policyFile("network:\n  egress:\n    - example.com\n");
    delete process.env.OPENCLAW_POLICY_FILE;
    (Object.prototype as Record<string, unknown>).OPENCLAW_POLICY_FILE = p;
    // Falls back to the well-known locations, which do not exist here.
    expect(detectSandbox().policyFile).toBeUndefined();
  });
});

// ── policy parsing ──────────────────────────────────────────────────────────

describe("readSandboxPolicy", () => {
  it("parses egress, filesystem, inference and resources", () => {
    const p = policyFile(
      [
        "network:",
        "  egress:",
        "    - api.evalguard.ai",
        "    - api.openai.com",
        "filesystem:",
        "  writable:",
        "    - /sandbox",
        "    - /tmp",
        "inference:",
        "  backend: nim",
        "  max_tokens: 4096",
        "  models:",
        "    - meta/llama-3.1-70b-instruct",
        "resources:",
        "  max_memory_mb: 2048",
        "  timeout: 300",
      ].join("\n"),
    );

    const policy = readSandboxPolicy(p);
    expect(policy).not.toBeNull();
    expect(policy!.network.allowedEgress).toEqual(["api.evalguard.ai", "api.openai.com"]);
    expect(policy!.filesystem.writablePaths).toEqual(["/sandbox", "/tmp"]);
    expect(policy!.inference.backend).toBe("nim");
    expect(policy!.inference.maxTokens).toBe(4096);
    expect(policy!.inference.allowedModels).toEqual(["meta/llama-3.1-70b-instruct"]);
    expect(policy!.resources?.maxMemoryMb).toBe(2048);
    expect(policy!.resources?.timeoutSeconds).toBe(300);
  });

  it("a list under a nested key does not destroy its sibling scalars", () => {
    // REGRESSION. The shipped parser held one pending container per top-level
    // key and flushed it on sight of the other kind, so `models:` overwrote the
    // whole `inference` map. Probed against the pre-fix logic with exactly the
    // policy shape @evalguard/nemoclaw's README documents:
    //   parsed.inference === ["meta/llama-3.1-70b-instruct"]   // backend GONE
    // making the README's own `policy.inference.backend` example print
    // "unknown" for every policy that also listed models.
    const p = policyFile(
      [
        "inference:",
        "  backend: nim",
        "  max_tokens: 4096",
        "  models:",
        "    - meta/llama-3.1-70b-instruct",
        "    - meta/llama-3.1-8b-instruct",
      ].join("\n"),
    );
    const policy = readSandboxPolicy(p)!;
    expect(policy.inference.backend).toBe("nim");
    expect(policy.inference.maxTokens).toBe(4096);
    expect(policy.inference.allowedModels).toEqual([
      "meta/llama-3.1-70b-instruct",
      "meta/llama-3.1-8b-instruct",
    ]);
  });

  it("a scalar AFTER a nested list still lands on the map", () => {
    const p = policyFile(
      ["inference:", "  models:", "    - m1", "  backend: openai"].join("\n"),
    );
    const policy = readSandboxPolicy(p)!;
    expect(policy.inference.allowedModels).toEqual(["m1"]);
    expect(policy.inference.backend).toBe("openai");
  });

  it("still accepts a list directly under a top-level key", () => {
    // The older flat form, which extractPolicy reads via `parsed.egress`.
    const p = policyFile(["egress:", "  - evalguard.ai", "  - api.openai.com"].join("\n"));
    expect(readSandboxPolicy(p)!.network.allowedEgress).toEqual([
      "evalguard.ai",
      "api.openai.com",
    ]);
  });

  it("still accepts a list directly under `network:`", () => {
    // The shape that used to work only by accident, via extractPolicy's
    // Array.isArray(network) fallback. It must keep working.
    const p = policyFile(["network:", "  - evalguard.ai"].join("\n"));
    expect(readSandboxPolicy(p)!.network.allowedEgress).toEqual(["evalguard.ai"]);
  });

  it("reads egressBlocked from the YAML booleans operators actually write", () => {
    for (const truthy of ["true", "yes", "on", "1"]) {
      const p = policyFile(["network:", `  blocked: ${truthy}`, "  egress:", "    - a.com"].join("\n"));
      expect(readSandboxPolicy(p)!.network.egressBlocked, truthy).toBe(true);
    }
    const p = policyFile(["network:", "  blocked: false", "  egress:", "    - a.com"].join("\n"));
    expect(readSandboxPolicy(p)!.network.egressBlocked).toBe(false);
  });

  it("returns null rather than throwing for a missing file", () => {
    expect(readSandboxPolicy(join(dir, "nope.yaml"))).toBeNull();
  });

  it("a policy key of __proto__ cannot reach Object.prototype", () => {
    // `__proto__` matches the parser's key regex, and a plain `{}` accumulator
    // would let the file re-parent the parsed object.
    const p = policyFile(["__proto__:", "  polluted: yes", "network:", "  egress:", "    - a.com"].join("\n"));
    const policy = readSandboxPolicy(p);
    expect(policy).not.toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
    // The real keys still parse — containment must not cost correctness.
    expect(policy!.network.allowedEgress).toEqual(["a.com"]);
  });
});

// ── host matching ───────────────────────────────────────────────────────────

describe("isHostAllowedByPolicy", () => {
  const withEgress = (...entries: string[]) =>
    ({
      network: { allowedEgress: entries, egressBlocked: false },
      filesystem: { writablePaths: [], readOnlyPaths: [] },
      inference: { allowedModels: [], backend: "unknown" },
      raw: {},
    }) as Parameters<typeof isHostAllowedByPolicy>[0];

  it.each([
    ["exact", "api.evalguard.ai", true],
    ["bare parent domain covers subdomains", "evalguard.ai", true],
    ["explicit wildcard subdomain", "*.evalguard.ai", true],
    ["global wildcard", "*", true],
    ["scheme and port are ignored", "https://api.evalguard.ai:443", true],
    ["trailing dot is ignored", "api.evalguard.ai.", true],
    ["uppercase", "API.EvalGuard.AI", true],
    ["an unrelated host", "api.openai.com", false],
    ["a suffix that is not a domain boundary", "notevalguard.ai", false],
  ])("%s -> %s", (_label, entry, expected) => {
    expect(isHostAllowedByPolicy(withEgress(entry), "api.evalguard.ai")).toBe(expected);
  });

  it("a wildcard subdomain does NOT match the apex", () => {
    expect(isHostAllowedByPolicy(withEgress("*.evalguard.ai"), "evalguard.ai")).toBe(false);
  });

  it("egressBlocked wins over any allowlist", () => {
    const p = withEgress("*")!;
    p.network.egressBlocked = true;
    expect(isHostAllowedByPolicy(p, "api.evalguard.ai")).toBe(false);
  });

  it("is permissive where the input is ambiguous", () => {
    // No policy, and an empty list — indistinguishable from "the parser found
    // no egress key". Both must resolve to allowed; the alternative is telling
    // an operator their working deployment is broken.
    expect(isHostAllowedByPolicy(null, "api.evalguard.ai")).toBe(true);
    expect(isHostAllowedByPolicy(withEgress(), "api.evalguard.ai")).toBe(true);
    expect(isEvalGuardAllowed(null)).toBe(true);
  });

  it("honours a self-hosted host, not just evalguard.ai", () => {
    // The whole reason this is host-parameterised: a BYO baseUrl needs its own
    // host allowed, and isEvalGuardAllowed() would answer the wrong question.
    const p = withEgress("guard.internal.acme.com");
    expect(isHostAllowedByPolicy(p, "guard.internal.acme.com")).toBe(true);
    expect(isEvalGuardAllowed(p)).toBe(false);
  });
});

// ── the diagnostic ──────────────────────────────────────────────────────────

describe("diagnoseSandboxEgress", () => {
  it("stays quiet outside a sandbox", () => {
    expect(diagnoseSandboxEgress("api.evalguard.ai").blocked).toBe(false);
  });

  it("stays quiet in a sandbox whose policy allows the host", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_1";
    policyFile("network:\n  egress:\n    - evalguard.ai\n");
    expect(diagnoseSandboxEgress("api.evalguard.ai").blocked).toBe(false);
  });

  it("stays quiet in a sandbox with NO policy file", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_1";
    expect(diagnoseSandboxEgress("api.evalguard.ai").blocked).toBe(false);
  });

  it("REPORTS a policy that lists egress and omits the host", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_1";
    const p = policyFile("network:\n  egress:\n    - api.openai.com\n");

    const d = diagnoseSandboxEgress("api.evalguard.ai");
    expect(d.blocked).toBe(true);
    expect(d.policyFile).toBe(p);
    // The message has to be actionable on its own: the host, where the verdict
    // came from, and the exact YAML to add.
    expect(d.message).toContain("api.evalguard.ai");
    expect(d.message).toContain(p);
    expect(d.message).toContain("egress:");
    expect(d.message).toContain("- api.evalguard.ai");
  });
});

describe("warnIfSandboxBlocks", () => {
  function blockedSandbox() {
    process.env.OPENCLAW_SANDBOX_ID = "sb_1";
    policyFile("network:\n  egress:\n    - api.openai.com\n");
  }

  it("warns once per host, not once per client", () => {
    blockedSandbox();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfSandboxBlocks("https://api.evalguard.ai/v1");
    warnIfSandboxBlocks("https://api.evalguard.ai/v1");
    warnIfSandboxBlocks("https://api.evalguard.ai/other");
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("is silenced by EVALGUARD_SUPPRESS_SANDBOX_WARNING", () => {
    blockedSandbox();
    process.env.EVALGUARD_SUPPRESS_SANDBOX_WARNING = "1";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfSandboxBlocks("https://api.evalguard.ai/v1");
    expect(warn).not.toHaveBeenCalled();
  });

  it("never throws on a malformed baseUrl", () => {
    blockedSandbox();
    expect(() => warnIfSandboxBlocks("not a url")).not.toThrow();
  });

  it("does not warn for an allowed host", () => {
    process.env.OPENCLAW_SANDBOX_ID = "sb_1";
    policyFile("network:\n  egress:\n    - evalguard.ai\n");
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    warnIfSandboxBlocks("https://api.evalguard.ai/v1");
    expect(warn).not.toHaveBeenCalled();
  });

  it("constructing a client outside a sandbox prints nothing", () => {
    // The regression that matters most: every existing user constructs a
    // client, and none of them may start seeing new console output.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    new EvalGuard({ apiKey: "eg_test_key" });
    expect(warn).not.toHaveBeenCalled();
  });

  it("constructing a client INSIDE a blocked sandbox warns once", () => {
    // The other half: the warning has to actually reach the operator through
    // the constructor, not just through a directly-called helper.
    blockedSandbox();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    new EvalGuard({ apiKey: "eg_test_key" });
    new EvalGuard({ apiKey: "eg_test_key" });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("egress:");
  });
});
