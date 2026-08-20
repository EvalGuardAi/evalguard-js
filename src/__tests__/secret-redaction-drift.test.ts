import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import * as wrapperCore from "@evalguard/wrapper-core";
import { _isSecretKey, _redactEmbeddedSecrets } from "../tracing";

/**
 * Locate a file relative to THIS test, without `import.meta`.
 *
 * `packages/sdk/tsconfig.json` compiles with `"module": "commonjs"` and its
 * `include` is `src/**\/*.ts`, so test files are type-checked under CJS —
 * where `import.meta` is a hard `error TS1343` and breaks `pnpm --filter
 * @evalguard/sdk run type-check`, the pre-push hook (ADR-0007) and CI's
 * verify-gate. `__dirname` is the CJS-legal spelling, it is typed by
 * `@types/node`, and vitest's module runner defines it at runtime (verified
 * 2026-07-31 in this package: `__dirname` resolved to
 * `packages/sdk/src/__tests__`). Unlike `process.cwd()` it does not depend on
 * which directory vitest was invoked from.
 */
const fromHere = (...segments: string[]): string => join(__dirname, ...segments);

/**
 * DRIFT GUARD (2026-07-30).
 *
 * The secret pattern list used to be defined literally inside `tracing.ts`.
 * `@evalguard/otel-sdk` needs the identical knowledge for its 55
 * `recordException()` egress points, and the file's own comments already warned
 * that "a drifted secret list fails silently — you only learn about it from the
 * leak". The list was therefore extracted to `@evalguard/wrapper-core`, the
 * repo's published zero-runtime-dependency leaf.
 *
 * These tests exist so that extraction cannot be quietly undone. A future edit
 * that re-inlines a local copy — or lets one list gain a pattern the other
 * lacks — fails HERE rather than in production telemetry.
 */

describe("@evalguard/sdk does not fork the secret list", () => {
  it("exports the SAME FUNCTION OBJECT as wrapper-core, not a copy of it", () => {
    // Identity, not behavioural equivalence: two independently-maintained
    // implementations can agree today and diverge next month. Identity cannot.
    expect(_redactEmbeddedSecrets).toBe(wrapperCore.redactEmbeddedSecrets);
    expect(_isSecretKey).toBe(wrapperCore.isSecretKey);
  });

  it("tracing.ts source contains no second literal copy of the pattern list", () => {
    const src = readFileSync(fromHere("..", "tracing.ts"), "utf8");
    // Each of these appeared verbatim in the old inline list. Any of them
    // reappearing in this file means someone re-forked the list.
    const FORKED_LITERALS = [
      "^eg_[A-Za-z0-9_-]",
      "^sk-ant-",
      "^AKIA[0-9A-Z]",
      "^ya29\\.",
      "^xox[baprs]-",
    ];
    for (const literal of FORKED_LITERALS) {
      expect(
        src.includes(literal),
        `tracing.ts re-declares ${literal} — the list must stay in @evalguard/wrapper-core`,
      ).toBe(false);
    }
  });
});

describe("the SDK's redaction behaviour is unchanged by the extraction", () => {
  // GROUND TRUTH: these exact strings are the ones the pre-extraction
  // implementation redacted. They are asserted against the credential the test
  // mints, never against what the implementation returns.
  const CASES: ReadonlyArray<readonly [string, string]> = [
    ["OpenAI", "sk-A1B2C3D4E5F6G7H8I9J0K1L2"],
    ["Anthropic", "sk-ant-A1B2C3D4E5F6G7H8I9J0K1L2"],
    ["EvalGuard", "eg_9fK2mQ7xB1nT4vZ8"],
    ["Postgres DSN", "postgres://admin:hunter2@db.internal:5432/prod"],
  ];

  it.each(CASES)("still redacts a %s credential embedded in an error message", (_l, cred) => {
    const out = _redactEmbeddedSecrets(`Error: 401 from ${cred} at retry 2`);
    expect(out).not.toContain(cred);
    expect(out).toContain("Error: 401 from");
    expect(out).toContain("at retry 2");
  });

  it("still leaves ordinary prose byte-identical", () => {
    const text = "the model returned a 429 and we backed off";
    expect(_redactEmbeddedSecrets(text)).toBe(text);
  });

  it("still classifies secret key names", () => {
    expect(_isSecretKey("apiKey")).toBe(true);
    expect(_isSecretKey("session.id")).toBe(false);
  });
});
