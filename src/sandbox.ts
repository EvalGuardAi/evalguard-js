// ── Sandbox awareness ───────────────────────────────────────────────────────
//
// WHY THIS IS IN THE SDK (2026-08-05)
// -----------------------------------
// `@evalguard/nemoclaw` has detected NemoClaw/OpenClaw sandboxes since 1.0.0,
// but that plugin is only reachable if you already know it exists. Everyone
// else runs plain `@evalguard/sdk` inside the sandbox, and when the sandbox's
// egress allowlist omits our host, EVERY call fails as an undifferentiated
// `TypeError: fetch failed` with no cause chain worth reading. The fix is one
// line in a YAML file the operator already owns; finding that out currently
// costs an afternoon.
//
// The detection and policy-parsing logic below is duplicated BY DESIGN with
// `@evalguard/nemoclaw` — that package ships with zero runtime dependencies
// because it runs with the filesystem confined to /sandbox and /tmp — and the
// two copies are held identical by `scripts/duplicated-source-drift-check.mjs`
// (regions `sandbox-detect` and `sandbox-policy`). Do not edit one copy alone;
// the gate will fail, which is the entire point. The last time this codebase
// relied on a COMMENT to keep two copies in step, they drifted and shipped a
// fail-open to npm.
//
// ADVISORY, NEVER FATAL
// ---------------------
// Nothing here throws, and nothing here blocks a call. The policy file belongs
// to the sandbox operator, we parse a subset of YAML with regexes, and a
// parser bug that turned into a constructor exception would take down working
// deployments to protect them from a warning. Every ambiguous case resolves to
// "allowed" — see `isHostAllowedByPolicy`.

import { existsSync, readFileSync } from "node:fs";

// <<<DUPLICATED:sandbox-detect>>>
export interface SandboxInfo {
  /** Whether we're running inside a NemoClaw/OpenClaw sandbox */
  isNemoClaw: boolean;
  /** Unique sandbox instance ID (from OPENCLAW_SANDBOX_ID or NEMOCLAW_SANDBOX_ID) */
  sandboxId?: string;
  /** Agent ID within the sandbox */
  agentId?: string;
  /** Path to the sandbox policy file (openclaw-sandbox.yaml) */
  policyFile?: string;
  /** Sandbox runtime version */
  runtimeVersion?: string;
  /** Whether the sandbox has network access */
  hasNetwork?: boolean;
}

const SANDBOX_ENV_VARS = [
  "OPENCLAW_SANDBOX_ID",
  "NEMOCLAW_SANDBOX_ID",
  "NVIDIA_NEMOCLAW_ID",
] as const;

const AGENT_ENV_VARS = ["OPENCLAW_AGENT_ID", "NEMOCLAW_AGENT_ID", "NVIDIA_AGENT_ID"] as const;

const RUNTIME_ENV_VARS = [
  "OPENCLAW_VERSION",
  "NEMOCLAW_VERSION",
  "OPENCLAW_RUNTIME_VERSION",
] as const;

const SANDBOX_FILESYSTEM_MARKERS = [
  "/sandbox",
  "/sandbox/.openclaw",
  "/sandbox/.nemoclaw",
  "/opt/nemoclaw",
  "/opt/openclaw",
] as const;

const POLICY_FILE_LOCATIONS = [
  "/sandbox/openclaw-sandbox.yaml",
  "/sandbox/openclaw-sandbox.yml",
  "/sandbox/nemoclaw-sandbox.yaml",
  "/sandbox/nemoclaw-sandbox.yml",
  "/etc/openclaw/sandbox.yaml",
  "/etc/nemoclaw/sandbox.yaml",
  "./openclaw-sandbox.yaml",
  "./nemoclaw-sandbox.yaml",
] as const;

/** Own-property test, hoisted so the hot path does not re-resolve it. */
const OWN: (obj: object, key: string) => boolean = (() => {
  const hasOwn = (Object as { hasOwn?: (o: object, k: PropertyKey) => boolean }).hasOwn;
  if (typeof hasOwn === "function") return (obj, key) => hasOwn(obj, key);
  const hop = Object.prototype.hasOwnProperty;
  return (obj, key) => hop.call(obj, key);
})();

/**
 * Read one environment variable as an OWN property.
 *
 * `process.env[name]` is a plain property read, and a plain read walks the
 * prototype chain: Node's env interceptor declines a name that is not in the
 * real environment and V8 falls through to `Object.prototype`. So a single
 * `Object.prototype.OPENCLAW_SANDBOX_ID = "x"` from any pollution gadget in a
 * transitive dependency would make an ordinary process report itself as a
 * sandboxed agent — and `OPENCLAW_NETWORK = "disabled"` would make a sandbox
 * with working egress report itself as offline. Same defect class as the
 * legacy fail-open hatch, which shipped to npm before it was caught.
 */
function readEnv(name: string): string | undefined {
  if (typeof process === "undefined") return undefined;
  const env: unknown = process.env;
  if (env === null || typeof env !== "object") return undefined;
  if (!OWN(env, name)) return undefined;
  const raw = (env as Record<string, unknown>)[name];
  return typeof raw === "string" ? raw : undefined;
}

function findEnvVar(vars: readonly string[]): string | null {
  for (const name of vars) {
    const value = readEnv(name);
    if (value) return value;
  }
  return null;
}

function findPolicyFile(): string | null {
  // An explicitly configured path wins over the well-known locations.
  const envPath = readEnv("OPENCLAW_POLICY_FILE") ?? readEnv("NEMOCLAW_POLICY_FILE");
  if (envPath) {
    try {
      if (existsSync(envPath)) return envPath;
    } catch {
      // Unreadable path: fall through to the well-known locations.
    }
  }

  for (const path of POLICY_FILE_LOCATIONS) {
    try {
      if (existsSync(path)) return path;
    } catch {
      // A denied stat is not a policy file. Keep looking.
    }
  }

  return null;
}

/**
 * Detect whether the current runtime is a NemoClaw/OpenClaw sandbox.
 *
 * Detection strategy (in order):
 * 1. Well-known environment variables (most reliable)
 * 2. Sandbox filesystem markers
 * 3. Policy files
 *
 * Never throws — returns `{ isNemoClaw: false }` on any error.
 */
export function detectSandbox(): SandboxInfo {
  try {
    const sandboxId = findEnvVar(SANDBOX_ENV_VARS);
    const agentId = findEnvVar(AGENT_ENV_VARS);
    const runtimeVersion = findEnvVar(RUNTIME_ENV_VARS);

    const hasFilesystemMarker = SANDBOX_FILESYSTEM_MARKERS.some((path) => {
      try {
        return existsSync(path);
      } catch {
        return false;
      }
    });

    const policyFile = findPolicyFile();

    const networkEnv = readEnv("OPENCLAW_NETWORK") ?? readEnv("NEMOCLAW_NETWORK");
    const hasNetwork = networkEnv !== "disabled" && networkEnv !== "none";

    const isNemoClaw = Boolean(sandboxId) || hasFilesystemMarker || Boolean(policyFile);

    return {
      isNemoClaw,
      sandboxId: sandboxId ?? undefined,
      agentId: agentId ?? undefined,
      policyFile: policyFile ?? undefined,
      runtimeVersion: runtimeVersion ?? undefined,
      hasNetwork: isNemoClaw ? hasNetwork : undefined,
    };
  } catch {
    return { isNemoClaw: false };
  }
}

/**
 * Quick check: are we in a NemoClaw sandbox?
 * Lighter than `detectSandbox()` — only checks env vars, no filesystem access.
 */
export function isNemoClawEnv(): boolean {
  return Boolean(findEnvVar(SANDBOX_ENV_VARS));
}

/**
 * Read the raw content of the sandbox policy file.
 * Returns null if no policy file is found or it cannot be read.
 */
export function readPolicyFileRaw(policyPath?: string): string | null {
  const path = policyPath ?? findPolicyFile();
  if (!path) return null;

  try {
    return readFileSync(path, "utf-8");
  } catch {
    return null;
  }
}
// <<<END-DUPLICATED:sandbox-detect>>>

// <<<DUPLICATED:sandbox-policy>>>
export interface NemoClawPolicy {
  /** Network egress rules */
  network: {
    /** Allowed egress domains/IPs */
    allowedEgress: string[];
    /** Whether all egress is blocked (sandbox is fully isolated) */
    egressBlocked: boolean;
  };
  /** Filesystem access rules */
  filesystem: {
    /** Writable paths inside the sandbox */
    writablePaths: string[];
    /** Read-only paths */
    readOnlyPaths: string[];
  };
  /** Inference/LLM routing config */
  inference: {
    /** Allowed model identifiers */
    allowedModels: string[];
    /** Inference backend (e.g., "nim", "openai", "anthropic", "local") */
    backend: string;
    /** Max tokens per request (if configured) */
    maxTokens?: number;
  };
  /** Resource limits */
  resources?: {
    maxMemoryMb?: number;
    maxCpuCores?: number;
    maxDiskMb?: number;
    timeoutSeconds?: number;
  };
  /**
   * Raw parsed key-value pairs for anything we did not explicitly model.
   *
   * Null-prototype: the keys come from a file we do not control, and a policy
   * containing `__proto__:` must not be able to reach `Object.prototype` or
   * re-parent this object. That also means `raw.hasOwnProperty(...)` throws —
   * use `Object.prototype.hasOwnProperty.call(raw, k)` or `k in raw`.
   */
  raw: Record<string, unknown>;
}

/**
 * Read and parse a NemoClaw sandbox policy file.
 *
 * @param policyPath - Explicit path to the policy YAML. Auto-detected from the
 *                     well-known locations when omitted.
 * @returns Parsed policy, or null if no policy file is found or readable.
 */
export function readSandboxPolicy(policyPath?: string): NemoClawPolicy | null {
  const raw = readPolicyFileRaw(policyPath);
  if (!raw) return null;

  try {
    return extractPolicy(parseSimpleYaml(raw));
  } catch {
    return null;
  }
}

/** Strip scheme, path, port and trailing dot so `https://host:443/x` compares as `host`. */
function normaliseHost(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .replace(/\.$/, "");
}

/**
 * Is `host` reachable under this sandbox's egress policy?
 *
 * ADVISORY. Every ambiguous case resolves to `true`, deliberately: this
 * function's only consumer is a diagnostic, and a false "blocked" verdict
 * would tell an operator their working deployment is broken. Specifically,
 * `true` when there is no policy at all, and `true` for an EMPTY egress list —
 * an empty list is indistinguishable here from "this parser did not find the
 * key", and the second reading is far more likely than an operator writing a
 * policy that permits nothing.
 *
 * A bare `evalguard.ai` entry covers subdomains, matching how egress
 * allowlists are conventionally written.
 */
export function isHostAllowedByPolicy(policy: NemoClawPolicy | null, host: string): boolean {
  if (!policy) return true;
  if (policy.network.egressBlocked) return false;

  const allowed = policy.network.allowedEgress;
  if (allowed.length === 0) return true;

  const target = normaliseHost(host);
  if (!target) return true;

  return allowed.some((entry) => {
    if (entry === "*") return true;
    const e = normaliseHost(entry);
    if (!e) return false;
    if (e === "*") return true;
    if (e === target) return true;
    if (e.startsWith("*.")) return target.endsWith(e.slice(1));
    return target.endsWith("." + e);
  });
}

/**
 * Is the EvalGuard API allowed by the sandbox network policy?
 * Convenience wrapper over `isHostAllowedByPolicy` for the hosted endpoint.
 */
export function isEvalGuardAllowed(policy: NemoClawPolicy | null): boolean {
  return isHostAllowedByPolicy(policy, "api.evalguard.ai");
}

// ── Simple YAML parser ──────────────────────────────────────────────────────
// Handles the subset of YAML used in NemoClaw policy files:
// - Top-level keys with scalar values
// - Nested keys (one level deep), holding a scalar OR a list
// - Lists with "- item" syntax, directly under a top-level key or a nested one
// Does NOT handle: anchors, aliases, multiline strings, deeper nesting.
//
// FIXED 2026-08-05. The previous state machine held ONE pending container per
// top-level key and flushed it on sight of the other kind, so a nested key
// whose value was a list overwrote its own siblings. Against the exact policy
// shape @evalguard/nemoclaw's README tells operators to write:
//
//     inference:
//       backend: nim
//       max_tokens: 4096
//       models:
//         - meta/llama-3.1-70b-instruct
//
//   parsed.inference === ["meta/llama-3.1-70b-instruct"]   // backend GONE
//
// `readSandboxPolicy().inference.backend` therefore reported "unknown" and
// `maxTokens` `undefined` for every policy that also listed models — which is
// what the README's own Policy Reader example prints. `network.egress`
// survived only by accident, via the `Array.isArray(network)` fallback in
// extractPolicy below. A list under a nested key now lands on that key.

function parseSimpleYaml(content: string): Record<string, unknown> {
  // Null-prototype: `__proto__` matches the key regex below, so a plain `{}`
  // would let a policy file re-parent the result (or, for a nested map, write
  // through to a shared prototype).
  const result = Object.create(null) as Record<string, unknown>;
  const lines = content.split("\n");

  let topKey = "";
  let map: Record<string, unknown> | null = null;
  let nestedKey = "";
  let list: string[] | null = null;
  /** True when the open list hangs off the top-level key, not off `nestedKey`. */
  let listAtTop = false;

  /** Attach the open list to whichever key opened it. */
  const flushList = (): void => {
    if (!list) return;
    if (listAtTop) {
      if (topKey) result[topKey] = list;
    } else if (map && nestedKey) {
      map[nestedKey] = list;
    }
    list = null;
    nestedKey = "";
  };

  /** Close out the current top-level key: its list first, then its map. */
  const flushTop = (): void => {
    flushList();
    if (topKey && map) result[topKey] = map;
    map = null;
    nestedKey = "";
  };

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");

    // Skip comments and empty lines
    if (/^\s*#/.test(line) || /^\s*$/.test(line)) continue;

    // Top-level key: "key: value" or "key:"
    const topMatch = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*):\s*(.*)/);
    if (topMatch) {
      flushTop();
      topKey = topMatch[1];
      const value = topMatch[2].trim();
      if (value && !value.startsWith("#")) {
        result[topKey] = value;
        topKey = "";
      }
      continue;
    }

    // Nested key: "  subkey: value" or "  subkey:"
    const nestedMatch = line.match(/^\s{2,}([a-zA-Z_][a-zA-Z0-9_]*):\s*(.*)/);
    if (nestedMatch && topKey) {
      flushList();
      if (!map) map = Object.create(null) as Record<string, unknown>;
      const value = nestedMatch[2].trim();
      if (value && !value.startsWith("#")) {
        map[nestedMatch[1]] = value;
        nestedKey = "";
      } else {
        // Bare "subkey:" — a list or a scalar may follow on the next lines.
        nestedKey = nestedMatch[1];
      }
      continue;
    }

    // List item: "  - value"
    const listMatch = line.match(/^\s+-\s+(.*)/);
    if (listMatch && topKey) {
      if (!list) {
        list = [];
        // No pending nested key means the list hangs off the top-level key.
        listAtTop = !nestedKey;
      }
      const value = listMatch[1].trim();
      if (value && !value.startsWith("#")) {
        list.push(value);
      }
      continue;
    }
  }

  flushTop();
  return result;
}

/** YAML booleans this parser sees as strings; `true` is the only blocking value. */
function isTruthyScalar(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value !== "string") return false;
  const v = value.trim().toLowerCase();
  return v === "true" || v === "yes" || v === "on" || v === "1";
}

function extractPolicy(parsed: Record<string, unknown>): NemoClawPolicy {
  // ── Network ─────────────────────────────────────────────────────────────
  const network = parsed.network as Record<string, unknown> | undefined;
  const egress = parsed.egress as string[] | undefined;

  let allowedEgress: string[] = [];
  let egressBlocked = false;

  if (Array.isArray(egress)) {
    allowedEgress = egress;
  } else if (network && typeof network === "object") {
    if (Array.isArray(network)) {
      allowedEgress = network as unknown as string[];
    } else {
      const netEgress =
        (network as Record<string, unknown>).egress ??
        (network as Record<string, unknown>).allowedEgress ??
        (network as Record<string, unknown>).allowed_egress;
      if (Array.isArray(netEgress)) {
        allowedEgress = netEgress as string[];
      } else if (typeof netEgress === "string") {
        allowedEgress = netEgress.split(",").map((s) => s.trim());
      }
      const blocked =
        (network as Record<string, unknown>).blocked ??
        (network as Record<string, unknown>).egressBlocked;
      egressBlocked = isTruthyScalar(blocked);
    }
  }

  // ── Filesystem ──────────────────────────────────────────────────────────
  const filesystem = parsed.filesystem as Record<string, unknown> | undefined;
  let writablePaths: string[] = [];
  let readOnlyPaths: string[] = [];

  if (filesystem && typeof filesystem === "object") {
    const wp =
      (filesystem as Record<string, unknown>).writablePaths ??
      (filesystem as Record<string, unknown>).writable_paths ??
      (filesystem as Record<string, unknown>).writable;
    if (Array.isArray(wp)) writablePaths = wp as string[];
    else if (typeof wp === "string") writablePaths = [wp];

    const rp =
      (filesystem as Record<string, unknown>).readOnlyPaths ??
      (filesystem as Record<string, unknown>).readonly_paths ??
      (filesystem as Record<string, unknown>).readonly;
    if (Array.isArray(rp)) readOnlyPaths = rp as string[];
    else if (typeof rp === "string") readOnlyPaths = [rp];
  }

  // ── Inference ───────────────────────────────────────────────────────────
  const inference = parsed.inference as Record<string, unknown> | undefined;
  let allowedModels: string[] = [];
  let backend = "unknown";
  let maxTokens: number | undefined;

  if (inference && typeof inference === "object") {
    const models =
      (inference as Record<string, unknown>).allowedModels ??
      (inference as Record<string, unknown>).allowed_models ??
      (inference as Record<string, unknown>).models;
    if (Array.isArray(models)) allowedModels = models as string[];
    else if (typeof models === "string") allowedModels = models.split(",").map((s) => s.trim());

    const be = (inference as Record<string, unknown>).backend;
    if (typeof be === "string") backend = be;

    const mt =
      (inference as Record<string, unknown>).maxTokens ??
      (inference as Record<string, unknown>).max_tokens;
    if (typeof mt === "number") maxTokens = mt;
    else if (typeof mt === "string") maxTokens = parseInt(mt, 10) || undefined;
  }

  // ── Resources ───────────────────────────────────────────────────────────
  const resources = parsed.resources as Record<string, unknown> | undefined;
  let resourcesObj: NemoClawPolicy["resources"];

  if (resources && typeof resources === "object") {
    resourcesObj = {
      maxMemoryMb: parseNumeric(
        (resources as Record<string, unknown>).maxMemoryMb ??
          (resources as Record<string, unknown>).max_memory_mb,
      ),
      maxCpuCores: parseNumeric(
        (resources as Record<string, unknown>).maxCpuCores ??
          (resources as Record<string, unknown>).max_cpu_cores,
      ),
      maxDiskMb: parseNumeric(
        (resources as Record<string, unknown>).maxDiskMb ??
          (resources as Record<string, unknown>).max_disk_mb,
      ),
      timeoutSeconds: parseNumeric(
        (resources as Record<string, unknown>).timeoutSeconds ??
          (resources as Record<string, unknown>).timeout_seconds ??
          (resources as Record<string, unknown>).timeout,
      ),
    };
  }

  return {
    network: { allowedEgress, egressBlocked },
    filesystem: { writablePaths, readOnlyPaths },
    inference: { allowedModels, backend, maxTokens },
    resources: resourcesObj,
    raw: parsed,
  };
}

function parseNumeric(value: unknown): number | undefined {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const n = parseInt(value, 10);
    return Number.isNaN(n) ? undefined : n;
  }
  return undefined;
}
// <<<END-DUPLICATED:sandbox-policy>>>

// ── SDK-only diagnostic layer ───────────────────────────────────────────────
//
// Everything below is specific to `@evalguard/sdk` and is NOT duplicated with
// the plugin: the plugin surfaces sandbox facts to an agent author who went
// looking for them, whereas the SDK's job is to explain an otherwise opaque
// network failure to someone who did not know a sandbox was involved.

/** What the sandbox says about our ability to reach `host`. */
export interface SandboxEgressDiagnosis {
  /** True when a sandbox was detected AND its policy excludes `host`. */
  blocked: boolean;
  /** The host that was checked (the client's configured API host). */
  host: string;
  /** Policy file the verdict came from, when one was found. */
  policyFile?: string;
  /** Operator-facing explanation and fix. Present only when `blocked`. */
  message?: string;
}

/**
 * Diagnose whether the surrounding sandbox will let us reach `host`.
 *
 * Returns `blocked: false` whenever we are not in a sandbox, no policy was
 * found, the policy could not be parsed, or the policy permits the host. The
 * only `blocked: true` result comes from a policy we successfully read that
 * lists egress destinations and does not include `host`.
 */
export function diagnoseSandboxEgress(host: string): SandboxEgressDiagnosis {
  try {
    const info = detectSandbox();
    if (!info.isNemoClaw) return { blocked: false, host };

    const policy = readSandboxPolicy(info.policyFile);
    if (!policy) return { blocked: false, host, policyFile: info.policyFile };
    if (isHostAllowedByPolicy(policy, host)) {
      return { blocked: false, host, policyFile: info.policyFile };
    }

    const where = info.policyFile ?? "the sandbox policy";
    const listed = policy.network.egressBlocked
      ? "egress is blocked entirely"
      : `allowed egress: ${policy.network.allowedEgress.join(", ") || "(none)"}`;

    return {
      blocked: true,
      host,
      policyFile: info.policyFile,
      message:
        `[EvalGuard] Running inside a NemoClaw/OpenClaw sandbox whose network ` +
        `policy does not permit "${host}" (${where} — ${listed}).\n` +
        `Calls to EvalGuard will fail as an opaque network error until the host ` +
        `is allowed. Add it to the egress list:\n\n` +
        `  network:\n    egress:\n      - ${host}\n\n` +
        `This is a warning, not an error — the client is usable and nothing was ` +
        `blocked by the SDK. Set EVALGUARD_SUPPRESS_SANDBOX_WARNING=1 to silence it.`,
    };
  } catch {
    // A diagnostic that can fail a constructor is worse than no diagnostic.
    return { blocked: false, host };
  }
}

/** Hosts already warned about, so a per-request client does not warn per call. */
const warned = new Set<string>();

/**
 * Warn once per host when the sandbox policy blocks it. Called from the
 * `EvalGuard` constructor. Silent in every other case, including any internal
 * failure — see the module header on why this is advisory only.
 */
export function warnIfSandboxBlocks(baseUrl: string): void {
  try {
    if (readEnv("EVALGUARD_SUPPRESS_SANDBOX_WARNING")) return;
    const host = new URL(baseUrl).hostname;
    if (!host || warned.has(host)) return;
    const diagnosis = diagnoseSandboxEgress(host);
    if (!diagnosis.blocked || !diagnosis.message) return;
    warned.add(host);
    console.warn(diagnosis.message);
  } catch {
    // Unparseable baseUrl is the constructor's problem to report, not ours.
  }
}

/** Test seam: forget which hosts have already been warned about. */
export function resetSandboxWarnings(): void {
  warned.clear();
}
