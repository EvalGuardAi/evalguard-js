/**
 * SDK <-> api/v1 route parity gate.
 *
 * On 2026-07-08 (`6879c5d64`, PR #1012) all four SDKs shipped an
 * Environments/Tools surface written to a NESTED, Humanloop-shaped URL scheme
 * (`/tools/{name}/deployments`) while `apps/web` implemented it FLAT
 * (`/tools/deployments?name=`). PR #1071 repointed TypeScript and Python.
 * Go and Java were not, and shipped to proxy.golang.org and Maven Central
 * calling paths that resolve to `apps/web/src/app/api/v1/[...catch]/route.ts`
 * — a hard 404 for every customer on those methods.
 *
 * It survived a month of green CI because both SDK suites asserted the WRONG
 * path against a stub server that accepts every request. A test that asks
 * "did we send what we meant to send" can never notice that nothing is
 * listening. This gate asks the other question, against the only thing that
 * cannot be wrong about itself: the route tree on disk.
 */
import { describe, expect, it } from "vitest";
// The analyzer is plain CommonJS with no type declarations — it has to be
// runnable as a bare `node scripts/route-parity.cjs` outside any build step.
// @ts-expect-error -- untyped CJS analyzer, shape asserted below
import parityModule from "../../scripts/route-parity.cjs";

const parity = parityModule as {
  analyze: () => {
    routes: Array<{ route: string; methods: string[]; segments: string[] }>;
    calls: Array<{ sdk: string; method: string; path: string; file: string; line: number }>;
    orphanCalls: Array<{ sdk: string; method: string; path: string; file: string; line: number }>;
    unexcusedOrphans: Array<{
      sdk: string;
      method: string;
      path: string;
      file: string;
      line: number;
    }>;
    staleExceptions: Array<{ sdk: string; method: string; path: string }>;
    uncoveredRoutes: Array<{ route: string; methods: string[] }>;
    methodMismatches: Array<{ sdk: string; method: string; path: string; routeMethods: string[] }>;
  };
  resolve: (
    routes: Array<{ route: string; segments: string[] }>,
    callPath: string,
  ) => { route: string } | null;
  parsePathExpr: (expr: string) => string | null;
  normalisePath: (p: string | null) => string | null;
  FOUNDER_GATED: Array<{ sdk: string; method: string; path: string }>;
};

const analysis = parity.analyze();

const asRoutes = (routes: string[]) =>
  routes.map((route) => ({ route, segments: route.split("/").filter(Boolean) }));

describe("SDK route parity — the analyzer itself", () => {
  // A gate that reports "0 problems" because its extractor silently stopped
  // matching is indistinguishable from a clean tree. Both inputs must be
  // non-empty before any verdict it produces means anything.
  it("scans a non-empty route tree and a non-empty set of SDK call sites", () => {
    expect(analysis.routes.length).toBeGreaterThan(100);
    expect(analysis.calls.length).toBeGreaterThan(100);
    for (const sdk of ["go", "java", "node", "python"]) {
      expect(
        analysis.calls.filter((c) => c.sdk === sdk).length,
        `extractor produced no call sites for the ${sdk} SDK — it is broken, not clean`,
      ).toBeGreaterThan(0);
    }
  });

  // Positive control, both states: the same matcher must ACCEPT a path that
  // has a handler and REJECT one that does not. A matcher that only ever
  // says "fine" would pass the gate above while proving nothing.
  it("rejects a path with no handler and accepts one with a handler", () => {
    const routes = asRoutes(["/api/v1/tools", "/api/v1/tools/deployments"]);
    expect(parity.resolve(routes, "/api/v1/tools/deployments")?.route).toBe(
      "/api/v1/tools/deployments",
    );
    expect(parity.resolve(routes, "/api/v1/tools/{}/deployments")).toBeNull();
  });

  // Next.js resolves a static segment before a dynamic one. Getting this
  // backwards makes `/api/v1/security/[scanId]` swallow every static sibling
  // and fabricates ~20 phantom method mismatches.
  it("prefers a static segment over a dynamic one, like the App Router", () => {
    const routes = asRoutes(["/api/v1/security/[scanId]", "/api/v1/security/secret-scan"]);
    expect(parity.resolve(routes, "/api/v1/security/secret-scan")?.route).toBe(
      "/api/v1/security/secret-scan",
    );
    expect(parity.resolve(routes, "/api/v1/security/scan_123")?.route).toBe(
      "/api/v1/security/[scanId]",
    );
  });

  it("keeps a trailing interpolation as its own segment", () => {
    // `"/tools/" + enc(name)` must not normalise to `/tools/`, which would
    // falsely match the `/tools` collection route.
    expect(parity.normalisePath(parity.parsePathExpr('"/tools/" + enc(name)'))).toBe("/tools/{}");
    expect(
      parity.normalisePath(parity.parsePathExpr('"/tools/" + enc(name) + "/deployments"')),
    ).toBe("/tools/{}/deployments");
  });

  it("treats a trailing query interpolation as a query, not a path segment", () => {
    // `` `/exports${q}` `` where q === "?runId=..." is a call to /exports.
    expect(parity.normalisePath(parity.parsePathExpr("`/exports${q}`"))).toBe("/exports");
    expect(parity.normalisePath(parity.parsePathExpr("`/tools/deployments${q}`"))).toBe(
      "/tools/deployments",
    );
  });
});

describe("SDK route parity — the tree", () => {
  it("has no SDK call site targeting a path with no route handler", () => {
    const detail = analysis.unexcusedOrphans
      .map((o) => `  ${o.sdk} ${o.method} ${o.path}  (${o.file}:${o.line})`)
      .join("\n");
    expect(
      analysis.unexcusedOrphans.length,
      `These SDK methods 404 in production — the path reaches api/v1/[...catch]:\n${detail}\n\n` +
        "Repoint the call to the real route, or add it to FOUNDER_GATED in " +
        "packages/sdk/scripts/route-parity.cjs with the evidence and the decision being awaited.",
    ).toBe(0);
  });

  // An excuse list that outlives the problem it excused is how a gate rots
  // into a rubber stamp. If a listed call site is no longer orphaned, the
  // entry has to go.
  it("has no stale FOUNDER_GATED entry", () => {
    const detail = analysis.staleExceptions.map((e) => `  ${e.sdk} ${e.method} ${e.path}`).join("\n");
    expect(
      analysis.staleExceptions.length,
      `These FOUNDER_GATED entries no longer describe an orphan — delete them:\n${detail}`,
    ).toBe(0);
  });

  it("has no SDK call site using a verb the matched route does not export", () => {
    const detail = analysis.methodMismatches
      .map((m) => `  ${m.sdk} ${m.method} ${m.path} — route exports [${m.routeMethods.join(",")}]`)
      .join("\n");
    expect(analysis.methodMismatches.length, `Verb/route mismatches:\n${detail}`).toBe(0);
  });

  // The reverse population. Routes with no SDK caller are not a defect —
  // most of api/v1 is UI- or cron-only — but the number is a real signal and
  // a silent zero would mean the coverage side of the sweep stopped working.
  it("computes the reverse population (routes no SDK reaches)", () => {
    expect(analysis.uncoveredRoutes.length).toBeGreaterThan(0);
    expect(analysis.uncoveredRoutes.length).toBeLessThan(analysis.routes.length);
    // Routes the SDKs demonstrably do reach must not appear as uncovered.
    const uncovered = new Set(analysis.uncoveredRoutes.map((r) => r.route));
    for (const reached of [
      "/api/v1/tools",
      "/api/v1/tools/deployments",
      "/api/v1/tools/env-vars",
      "/api/v1/environments",
      "/api/v1/prompts/deployments",
    ]) {
      expect(uncovered.has(reached), `${reached} is reached by an SDK but reported uncovered`).toBe(
        false,
      );
    }
  });
});
