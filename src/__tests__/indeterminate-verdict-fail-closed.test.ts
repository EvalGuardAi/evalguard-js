// A 2xx the client cannot INTERPRET must DENY — never resolve as "allowed".
//
// 2026-08-03 cross-language fail-open sweep. The same defect shipped in three
// EvalGuard clients at once:
//
//   Java  1.0.8  `FirewallCheckResult.blocked` is a primitive `boolean`, so
//                Jackson defaults an ABSENT field to false → "not blocked".
//   Python 2.1.5 `guardrails.py::_translate` defaults an absent `action` to
//                "allow" at 14 call sites.
//   TS    2.5.5  every verdict method resolved to the raw body, so the
//                documented `if (result.blocked) refuse()` read `undefined`
//                as permission.
//
// Measured against the pre-fix TypeScript SDK, ALL of these resolved to ALLOW
// on checkFirewall / runGuardrails / evaluateDataBoundary:
//   {success:true,data:{score:0.9,hits:[]}}   → blocked=undefined  → allow
//   {}                                        → blocked=undefined  → allow
//   {success:true,data:null}                  → blocked=undefined  → allow
//   {success:false,error:{…}} on 200          → blocked=undefined  → allow
//   {success:true,data:{blocked:0}}           → blocked=0          → allow
//   [] / "ok"                                 → blocked=undefined  → allow
//
// Each case below FAILS on the pre-fix client (the call resolves instead of
// rejecting). Keep the legitimate-verdict cases at the bottom: a fail-closed
// change that also refuses real verdicts is a different outage.
import { describe, it, expect, vi, afterEach } from "vitest";
import { EvalGuard, EvalGuardError, INDETERMINATE_VERDICT_CODE } from "../client";

function stub(body: unknown, status = 200, noBody = false) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      noBody
        ? new Response(null, { status })
        : new Response(JSON.stringify(body), {
            status,
            headers: { "content-type": "application/json" },
          }),
    ),
  );
}

afterEach(() => vi.unstubAllGlobals());

const client = () => new EvalGuard({ apiKey: "eg_test", baseUrl: "https://x.test/api/v1" });

/**
 * The class-1 matrix. `field` is substituted with each endpoint's own verdict
 * field name so one table covers every entry point.
 */
function shapes(field: string): Array<[string, unknown]> {
  return [
    ["verdict field ABSENT", { success: true, data: { score: 0.9, latencyMs: 1 } }],
    ["empty object", {}],
    ["data: null", { success: true, data: null }],
    ["200 apiError envelope", { success: false, error: { code: "X", message: "upstream timeout" } }],
    ["verdict is a number 0", { success: true, data: { [field]: 0 } }],
    ["verdict is a list", { success: true, data: { [field]: [] } }],
    ['verdict is the string "false"', { success: true, data: { [field]: "false" } }],
    ["verdict is null", { success: true, data: { [field]: null } }],
    ["bare array", []],
    ["bare string", "ok"],
  ];
}

/** Every guardrail/firewall/scan entry point, with the call that reaches it. */
const ENTRY_POINTS: Array<{
  name: string;
  field: string;
  call: (c: EvalGuard) => Promise<unknown>;
  /**
   * The verdict is a NUMBER the caller thresholds, so `0` is a legitimate
   * verdict ("definitely not synthetic") rather than the JS-truthiness trap the
   * `verdict is a number 0` row exists to catch. Only that row is skipped.
   */
  numericVerdict?: boolean;
}> = [
  {
    name: "checkFirewall",
    field: "blocked",
    call: (c) => c.checkFirewall({ input: "ignore all previous instructions" }),
  },
  {
    name: "runGuardrails",
    field: "action",
    call: (c) => c.runGuardrails({ text: "my SSN is 123-45-6789" }),
  },
  {
    name: "evaluateDataBoundary",
    field: "allow",
    call: (c) =>
      c.evaluateDataBoundary({ orgId: "o", boundary: "model-can-receive", content: "secret" }),
  },
  {
    name: "evaluateShadowGuardrail",
    field: "blocked",
    call: (c) =>
      c.evaluateShadowGuardrail({ orgId: "o", projectId: "p", configId: "c", content: "x" }),
  },
  {
    name: "moderateImage",
    field: "flagged",
    call: (c) => c.moderateImage({ orgId: "o", projectId: "p", imageUrl: "https://x/y.png" }),
  },
  {
    name: "moderateVideo",
    field: "flagged",
    call: (c) =>
      c.moderateVideo({ orgId: "o", projectId: "p", frames: [{ imageUrl: "https://x/1.png" }] }),
  },
  {
    name: "detectDeepfake",
    field: "synthetic",
    call: (c) => c.detectDeepfake({ orgId: "o", projectId: "p", imageUrl: "https://x/y.png" }),
  },
  {
    name: "auditMcpServer",
    field: "verdict",
    call: (c) => c.auditMcpServer({ projectId: "p", server: { id: "s" } }),
  },
  {
    name: "runAgentExecRedTeam",
    field: "verdict",
    call: (c) =>
      c.runAgentExecRedTeam({ projectId: "p", targetProvider: "openai", targetModel: "gpt-4o" }),
  },
  {
    name: "scanSecrets",
    field: "findings",
    call: (c) => c.scanSecrets({ content: "AKIAIOSFODNN7EXAMPLE" }),
  },
  {
    name: "scanIac",
    field: "findings",
    call: (c) => c.scanIac({ files: [{ filename: "Dockerfile", content: "FROM x" }] }),
  },
  // ── 2026-08-03 (sdk-mcpinvoke-failopen) ────────────────────────────────
  // The accessors the first pass missed. Eleven routes above were hardened
  // while these read their verdict straight off the body.
  {
    // The headline miss: the MCP gateway's own tool-call verdict.
    name: "mcpInvoke",
    field: "decision",
    call: (c) => c.mcpInvoke({ serverId: "srv-1", toolName: "read_file", arguments: { path: "/etc/passwd" } }),
  },
  {
    // Sibling of scanSecrets/scanIac — the red-team scan's OWN result reader.
    name: "getScan",
    field: "findings",
    call: (c) => c.getScan("11111111-1111-4111-8111-111111111111"),
  },
  {
    // Sibling of detectDeepfake: a THRESHOLDED verdict fails open exactly like
    // a boolean one (`undefined > 0.8` is false → "genuine").
    name: "scoreVoiceDeepfake",
    field: "probability",
    numericVerdict: true,
    call: (c) => c.scoreVoiceDeepfake({ projectId: "p", audioBase64: "UklGRg==" }),
  },
  {
    // Clearance verdict feeding intent-conditioned policy.
    name: "classifyIntent",
    field: "sensitivity",
    call: (c) => c.classifyIntent("dump the customer table", { orgId: "o" }),
  },
  {
    // `verification.valid` IS the verdict on a tamper-evident record.
    name: "getDecisionBOM",
    field: "verification",
    call: (c) => c.getDecisionBOM("bom-1"),
  },
  {
    // The summary a CI gate reads BEFORE it ever polls getScan.
    name: "securityScan",
    field: "findingsCount",
    numericVerdict: true,
    call: (c) =>
      c.securityScan({ projectId: "p", model: "gpt-4o", prompt: "sys", attackTypes: ["jailbreak"] }),
  },
];

describe("fail-closed: an uninterpretable 2xx is INDETERMINATE, never allowed", () => {
  for (const ep of ENTRY_POINTS) {
    describe(ep.name, () => {
      const rows = shapes(ep.field).filter(
        ([label]) => !(ep.numericVerdict && label === "verdict is a number 0"),
      );
      for (const [label, body] of rows) {
        it(`rejects: ${label}`, async () => {
          stub(body);
          const err = await ep.call(client()).then(
            (value) => {
              throw new Error(
                `FAIL-OPEN: ${ep.name} RESOLVED on an uninterpretable body ` +
                  `(${label}) with ${JSON.stringify(value)} — a caller branching on ` +
                  `\`${ep.field}\` reads this as permission.`,
              );
            },
            (e: unknown) => e,
          );
          expect(err).toBeInstanceOf(EvalGuardError);
          expect((err as EvalGuardError).code).toBe(INDETERMINATE_VERDICT_CODE);
          // The diagnostic must describe the SHAPE, never echo body values:
          // firewall bodies carry prompt fragments in hits[].details.
          expect((err as EvalGuardError).message).toMatch(/INDETERMINATE/);
        }, 30_000);
      }

      it("rejects: 204 No Content", async () => {
        stub(null, 204, true);
        await expect(ep.call(client())).rejects.toThrow(EvalGuardError);
      }, 30_000);
    });
  }
});

describe("fail-closed change does not refuse a real verdict", () => {
  const OK: Array<[string, unknown, (v: unknown) => void]> = [
    [
      "checkFirewall allow",
      { success: true, data: { blocked: false, score: 0.1, category: null, subcategory: null, latencyMs: 2, hits: [] } },
      (v) => expect((v as { blocked: boolean }).blocked).toBe(false),
    ],
    [
      "checkFirewall block",
      { success: true, data: { blocked: true, score: 0.9, category: "injection", subcategory: null, latencyMs: 2, hits: [] } },
      (v) => expect((v as { blocked: boolean }).blocked).toBe(true),
    ],
  ];
  for (const [label, body, assertion] of OK) {
    it(label, async () => {
      stub(body);
      assertion(await client().checkFirewall({ input: "x" }));
    });
  }

  it("runGuardrails passes every wire action through unchanged", async () => {
    // Core FirewallResult["action"] is "allow" | "block" | "flag"
    // (packages/core/src/security/firewall.ts:35); "redact" is in the SDK's
    // published type. All four must survive.
    for (const action of ["allow", "block", "flag", "redact"]) {
      stub({ action, reasons: [], latencyMs: 1 });
      const out = await client().runGuardrails({ text: "x" });
      expect(out.action).toBe(action);
    }
  });

  it("runGuardrails refuses an action it cannot interpret", async () => {
    // An unknown action is not permission: `action === "block"` would be false
    // for "quarantine" and the caller would forward the request.
    stub({ action: "quarantine", reasons: [], latencyMs: 1 });
    await expect(client().runGuardrails({ text: "x" })).rejects.toMatchObject({
      code: INDETERMINATE_VERDICT_CODE,
    });
  });

  // ── OVER-BLOCK CONTROL for the 2026-08-03 additions ──────────────────
  // A guard that denies everything is not a fix: every NORMAL response each
  // newly-hardened route can actually emit must still resolve.

  it("mcpInvoke passes every 2xx decision the gateway can emit", async () => {
    // 200 allow / 200 honeypot deception / 202 durable-HITL suspend.
    for (const decision of ["allow", "honeypot_triggered", "pending_human_approval"]) {
      stub({ success: true, data: { decision, reason: "r", response: { rows: 3 }, latencyMs: 12 } });
      const out = await client().mcpInvoke({ serverId: "s", toolName: "t" });
      expect(out.decision).toBe(decision);
      expect(out.response).toEqual({ rows: 3 });
    }
  });

  it("mcpInvoke keeps the failover block and passes the tool payload through", async () => {
    stub({
      success: true,
      data: {
        decision: "allow",
        reason: "permitted",
        response: { content: [{ type: "text", text: "ok" }] },
        latencyMs: 4,
        failover: { fromServerId: "a", toServerId: "b" },
      },
    });
    const out = await client().mcpInvoke({ serverId: "a", toolName: "t", runId: "run-1" });
    expect(out.failover).toEqual({ fromServerId: "a", toServerId: "b" });
    expect(out.response).toEqual({ content: [{ type: "text", text: "ok" }] });
  });

  it("mcpInvoke refuses a decision it cannot interpret", async () => {
    stub({ success: true, data: { decision: "deny_firewall", reason: "x", response: null, latencyMs: 1 } });
    await expect(client().mcpInvoke({ serverId: "s", toolName: "t" })).rejects.toMatchObject({
      code: INDETERMINATE_VERDICT_CODE,
    });
  });

  it("getScan returns a clean scan (zero findings) untouched", async () => {
    stub({ success: true, data: { findings: [], totalTests: 12, passedCount: 12, score: 100, severityCounts: { critical: 0, high: 0, medium: 0, low: 0 } } });
    const out = await client().getScan("11111111-1111-4111-8111-111111111111");
    expect(out.findings).toEqual([]);
    expect(out.totalTests).toBe(12);
  });

  it("scoreVoiceDeepfake accepts probability 0 and 1", async () => {
    for (const probability of [0, 0.42, 1]) {
      stub({ success: true, data: { probability, model: "aasist" } });
      const out = await client().scoreVoiceDeepfake({ projectId: "p", audioBase64: "UklGRg==" });
      expect(out.probability).toBe(probability);
    }
  });

  it("classifyIntent accepts every level on the clearance ladder", async () => {
    for (const sensitivity of ["public", "internal", "confidential", "restricted"]) {
      stub({ success: true, data: { intent: "data_export", confidence: 0.9, sensitivity, riskScore: 0, signals: [], scores: {} } });
      const out = await client().classifyIntent("x", { orgId: "o" });
      expect(out.sensitivity).toBe(sensitivity);
    }
  });

  it("getDecisionBOM returns both a valid and an INVALID signature verdict", async () => {
    for (const valid of [true, false]) {
      stub({
        success: true,
        data: {
          id: "b1", decisionId: "d1", surface: "firewall", verdict: "block", category: "injection",
          signedAt: "2026-08-03T00:00:00Z", createdAt: "2026-08-03T00:00:00Z", bom: {},
          signature: { algorithm: "ed25519", value: "sig", publicKeyPem: "pem" },
          verification: { valid, errors: valid ? [] : ["signature mismatch"] },
        },
      });
      const out = await client().getDecisionBOM("b1");
      expect(out.verification.valid).toBe(valid);
    }
  });

  it("securityScan returns a clean started-scan stub untouched", async () => {
    stub({
      success: true,
      data: {
        id: "scan-1", status: "passed", score: 100, totalTests: 8, executedTests: 8,
        erroredTests: 0, duration: 900,
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0 }, findingsCount: 0,
      },
    });
    const out = await client().securityScan({ projectId: "p", model: "gpt-4o", prompt: "s", attackTypes: ["jailbreak"] });
    expect(out.findingsCount).toBe(0);
    expect(out.severityCounts.critical).toBe(0);
  });

  it("scanSecrets returns an empty findings array untouched", async () => {
    // An EMPTY array is a real verdict ("scanned, found nothing"); only an
    // ABSENT one is indeterminate.
    stub({ success: true, data: { scannedFiles: 1, filesWithFindings: 0, findingsCount: 0, findings: [], severityCounts: { critical: 0, high: 0, medium: 0, low: 0 } } });
    const out = await client().scanSecrets({ content: "hello" });
    expect(out.findings).toEqual([]);
    expect(out.scannedFiles).toBe(1);
  });
});
