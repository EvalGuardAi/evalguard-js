# @evalguard/sdk

[![npm version](https://img.shields.io/npm/v/%40evalguard%2Fsdk.svg)](https://www.npmjs.com/package/@evalguard/sdk)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Official Node.js/TypeScript SDK for the [EvalGuard](https://evalguard.ai) API -- evaluate, red-team, and guard LLM applications programmatically.

## Installation

```bash
npm install @evalguard/sdk
```

## Quick Start

```typescript
import { EvalGuard } from "@evalguard/sdk";

const client = new EvalGuard({ apiKey: "eg_live_..." });

// 1. Start an evaluation. eval() enqueues the run and returns immediately with a
//    STARTED-RUN STUB (id + status) — the model executes in the background.
const started = await client.eval({
  name: "qa-check",
  projectId: "my-project",
  model: "gpt-4o",
  prompt: "Answer: {{input}}",
  cases: [{ input: "What is 2+2?", expectedOutput: "4" }],
  scorers: ["exact-match", "contains"],
});
console.log(`Eval started: ${started.id} (${started.status})`);

// 2. Poll getEvalRun(id) for the scored result once the run finishes.
let run = await client.getEvalRun(started.id);
while (run.status === "running" || run.status === "pending") {
  await new Promise((r) => setTimeout(r, 2000));
  run = await client.getEvalRun(started.id);
}
console.log(`Status: ${run.status} · Score: ${run.score} · ${(run.passRate ?? 0) * 100}% pass`);

// Send trace data for observability
await client.trace({
  projectId: "my-project",
  sessionId: "session-123",
  steps: [{ type: "llm", input: "Hello", output: "Hi there!", duration: 450 }],
});
```

### Security scans

`securityScan()` also returns a **started-scan stub** (id + summary counts). The
per-finding detail is fetched separately with `getScan(id)`:

```typescript
// 1. Start the scan — resolves to the stub, not the findings.
const scan = await client.securityScan({
  projectId: "my-project",
  model: "gpt-4o",
  prompt: "You are a helpful assistant.",
  attackTypes: ["prompt-injection", "jailbreak", "data-extraction"],
});
console.log(
  `Scan ${scan.id}: ${scan.status} · ${scan.findingsCount} findings ` +
    `(${scan.severityCounts.critical} critical)`,
);

// 2. Fetch the full findings for the scan by its id.
const result = await client.getScan(scan.id);
for (const finding of result.findings) {
  console.log(`[${finding.severity}] ${finding.title}`);
}
```

## Configuration

```typescript
const client = new EvalGuard({
  apiKey: "eg_live_...",
  // Optional. The base is normalized to the versioned API root, so any of
  // `https://your-instance.com`, `.../api`, or `.../api/v1` resolve correctly.
  baseUrl: "https://your-self-hosted-instance.com/api",
});
```

## Methods

| Method | Description |
|---|---|
| `client.eval(params)` | Start an evaluation; returns a started-run stub (poll `getEvalRun`) |
| `client.getEvalRun(id)` | Fetch an eval run's status, score, pass rate, and per-case results |
| `client.listEvals(projectId?)` | List a project's eval runs |
| `client.securityScan(params)` | Start a red-team scan; returns a stub (poll `getScan`) |
| `client.getScan(id)` | Fetch a security scan's findings by id |
| `client.chatCompletions(params)` | OpenAI-compatible chat completion through the governed gateway (BYOK) |
| `client.gatewayChat(params)` | Router-aware chat with automatic provider selection / fallback |
| `client.runGuardrails(params)` | Run a runtime input/output guardrail check on text |
| `client.checkFirewall(params)` | Low-level firewall check (PII / injection / toxicity / topic rules) |
| `client.createAgent(params)` | Submit agent trace steps for observability |
| `client.listAgents(projectId?)` | List agents with aggregated call/latency/cost stats |
| `client.listScorers()` | List every available eval scorer |
| `client.listPlugins()` | List every available red-team attack plugin |
| `client.trace(params)` | Send agent/LLM trace data for monitoring |
| `traceable(fn, opts)` / `traced(...)` | Auto-instrument a function/block as a trace span |

See the [full API reference](https://evalguard.ai/docs/sdk) for the complete method surface.

## TypeScript

The SDK exports all types from `@evalguard/core` for full type safety:

```typescript
import type { EvalGuardConfig } from "@evalguard/sdk";
```

## Agent Memory Governance

Admin-managed policy that governs durable agent-memory writes for an org (or a
single project scope). The policy `mode` is `off` | `monitor` | `enforce`, plus
config knobs (poisoning-screen confidence threshold, human-approval-on-rewrite,
provenance-required). CRUD maps to `/agent-memory/governance` and requires the
**admin** role. `getMemoryGovernancePolicy` returns `{ policy: null }` when none
is set — memory writes are ungoverned until you set one.

| Method | Description |
|---|---|
| `client.getMemoryGovernancePolicy({ orgId, projectId? })` | Read the org (or project) policy; `{ policy: null }` when unset |
| `client.setMemoryGovernancePolicy({ orgId, projectId?, enabled?, mode?, config? })` | Create/update the policy (PUT); returns `{ policy }` |
| `client.deleteMemoryGovernancePolicy({ orgId, projectId? })` | Delete the policy (reverts to ungoverned); returns `{ deleted }` |

```typescript
// Enforce governance org-wide: screen poisoned memories, require provenance, and
// require human approval before an autonomous rewrite/consolidate proceeds.
const { policy } = await client.setMemoryGovernancePolicy({
  orgId: "org-uuid",
  mode: "enforce",
  enabled: true,
  config: {
    thresholds: { poisonMinConfidence: 0.7 },
    requireApprovalOnRewrite: true,
    requireProvenance: true,
  },
});
console.log(`${policy.mode} · enabled=${policy.enabled}`);

// Read the org-wide policy (omit projectId); pass projectId for a project scope.
const current = await client.getMemoryGovernancePolicy({ orgId: "org-uuid" });
```

## Gateway Guardrail Config

Per-project, **opt-in** inline guardrails the governed gateway proxy wires into
the request/response hot path: partner-vendor adapters (`aporia` / `lakera` / …,
each keyed by a stored `provider_keys` `secretRef`) and dependency-free local
presets. CRUD maps to `/gateway/guardrails` and requires the **admin** role.
`upsertGuardrailConfig` is idempotent on `(projectId, vendor)`.

The **local-vs-vendor secretRef rule** is modeled client-side so a bad config
throws immediately instead of round-tripping to a 400: a local preset makes no
external call and must **not** carry a `secretRef`; every other vendor
**requires** one. The local presets are exported as `LOCAL_GUARDRAIL_VENDORS`
(`local-firewall`, `moderated-firewall`, `data-not-instructions`,
`tool-call-circuit-breaker`), with an `isLocalGuardrailVendor(vendor)` guard.

| Method | Description |
|---|---|
| `client.listGuardrailConfigs(projectId)` | List a project's guardrail rows, ordered by priority |
| `client.upsertGuardrailConfig(params)` | Create/update a row; idempotent on `(projectId, vendor)` |
| `client.deleteGuardrailConfig({ projectId, id })` | Delete a row by id; returns `{ deleted }` |

```typescript
import { EvalGuard, LOCAL_GUARDRAIL_VENDORS } from "@evalguard/sdk";

// A local preset — no secretRef. `onFlag` is block | redact | flag.
await client.upsertGuardrailConfig({
  orgId: "org-uuid",
  projectId: "project-uuid",
  vendor: "tool-call-circuit-breaker",
  config: { maxRepeats: 3 },
  onFlag: "block",
  checkRequest: true,
  checkResponse: true,
  priority: 10,
});

// A partner adapter — secretRef (a stored provider_keys id) is required.
await client.upsertGuardrailConfig({
  orgId: "org-uuid",
  projectId: "project-uuid",
  vendor: "lakera",
  secretRef: "provider-key-uuid",
  onFlag: "block",
});

const rows = await client.listGuardrailConfigs("project-uuid");
```

## Importers

`importTraces` ingests an observability export into EvalGuard's neutral trace
store (POST `/traces/import`, **editor** role). The typed `platform` union covers
`helicone`, `langfuse`, `portkey`, and `huggingface`; the field also accepts any
platform string the server's importer registry supports.

```typescript
const result = await client.importTraces({
  platform: "helicone",
  projectId: "project-uuid",
  payload: heliconeExportJson, // the vendor-specific export JSON
});
console.log(
  `${result.platform}: ${result.inserted} inserted, ${result.failed} failed, ` +
    `${result.skippedDuplicates} duplicate(s) skipped`,
);
```

> The full 13-importer set — the config importer `promptfoo` plus the trace
> importers `helicone`, `langfuse`, `portkey`, `huggingface`, `humanloop`,
> `vellum`, `athina`, `maxim`, `langsmith`, `braintrust`, `deepeval`, and
> `ragas` — is exposed by the
> [`@evalguard/cli`](https://www.npmjs.com/package/@evalguard/cli) `import:*`
> commands, which convert competitor configs/datasets and normalize
> observability exports offline (no API key).

## Sandbox awareness

Running inside a NemoClaw/OpenClaw sandbox? If the sandbox's egress allowlist
omits the EvalGuard host, every call fails as an opaque
`TypeError: fetch failed`. Since 3.1.0 the client says so, once, with the fix:

```text
[EvalGuard] Running inside a NemoClaw/OpenClaw sandbox whose network policy
does not permit "api.evalguard.ai" (/sandbox/openclaw-sandbox.yaml — allowed
egress: api.openai.com).
...
  network:
    egress:
      - api.evalguard.ai
```

This is a **warning, not an error**: the SDK never blocks a call over a policy
file it does not own, and every ambiguous case (no policy, unparseable policy,
empty egress list) is treated as allowed. Set
`EVALGUARD_SUPPRESS_SANDBOX_WARNING=1` to silence it.

You can also query it directly — useful for self-hosted deployments, where the
host to check is yours, not ours:

```typescript
import {
  detectSandbox,
  readSandboxPolicy,
  isHostAllowedByPolicy,
  diagnoseSandboxEgress,
} from "@evalguard/sdk";

const info = detectSandbox();
if (info.isNemoClaw) {
  const policy = readSandboxPolicy(info.policyFile);
  console.log(isHostAllowedByPolicy(policy, "guard.internal.acme.com"));
}

const { blocked, message } = diagnoseSandboxEgress("api.evalguard.ai");
if (blocked) console.warn(message);
```

## Documentation

Full documentation at [evalguard.ai/docs/sdk](https://evalguard.ai/docs/sdk).

## License

Apache-2.0 -- see [LICENSE](./LICENSE) for details.
