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

// Run an evaluation
const evalResult = await client.eval({
  name: "qa-check",
  projectId: "my-project",
  model: "gpt-4o",
  prompt: "Answer: {{input}}",
  cases: [
    { input: "What is 2+2?", expectedOutput: "4" },
  ],
  scorers: ["exact-match", "contains"],
});
console.log(`Score: ${evalResult.score}/${evalResult.maxScore} · ${(evalResult.passRate * 100).toFixed(0)}% pass`);

// Run a security scan
const scan = await client.securityScan({
  projectId: "my-project",
  model: "gpt-4o",
  prompt: "You are a helpful assistant.",
  attackTypes: ["prompt-injection", "jailbreak", "data-extraction"],
});
console.log(`Scan ID: ${scan.id}`);

// Fetch a historical run by its id (run ids come from client.listEvals())
const run = await client.getEvalRun("evalrun_..." /* a run id from listEvals() */);
console.log(`Status: ${run.status}, Score: ${run.score}`);

// Send trace data
await client.trace({
  projectId: "my-project",
  sessionId: "session-123",
  steps: [
    { type: "llm", input: "Hello", output: "Hi there!", duration: 450 },
  ],
});
```

## Configuration

```typescript
const client = new EvalGuard({
  apiKey: "eg_live_...",
  baseUrl: "https://your-self-hosted-instance.com/api/v1", // optional
});
```

## Methods

| Method | Description |
|---|---|
| `client.eval(params)` | Run an evaluation with scorers and test cases |
| `client.getEvalRun(id)` | Fetch results of a specific eval run |
| `client.securityScan(params)` | Run a red-team security scan against a model |
| `client.trace(params)` | Send agent/LLM trace data for monitoring |

## TypeScript

The SDK exports all types from `@evalguard/core` for full type safety:

```typescript
import type { EvalGuardConfig } from "@evalguard/sdk";
```

## Documentation

Full documentation at [evalguard.ai/docs/sdk](https://evalguard.ai/docs/sdk).

## License

Apache-2.0 -- see [LICENSE](./LICENSE) for details.
