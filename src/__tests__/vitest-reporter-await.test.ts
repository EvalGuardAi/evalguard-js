import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { EvalGuardReporter } from "../vitest";

// Regression (audit 2026-07-25): `onFinished` did `void this._sendResults()`,
// returning synchronously with the upload still in flight. Vitest awaits
// `onFinished`; because the promise was discarded, vitest saw all reporters
// finish and exited, and Node tore down the process (and the socket) before the
// POST completed — CI eval results were silently lost, with no error and no
// retry. `onFinished` must RETURN the upload promise.

function fileWithTests(): Record<string, unknown> {
  return {
    filepath: "/repo/src/foo.test.ts",
    tasks: [
      { type: "test", name: "passes", result: { state: "pass", duration: 12 } },
      { type: "test", name: "fails", result: { state: "fail", duration: 3 } },
    ],
  };
}

/** Reach into the reporter and swap its client for a controllable stub. */
function stubClient(reporter: EvalGuardReporter) {
  let resolveRequest!: () => void;
  const settled = { done: false };
  const request = vi.fn(
    () =>
      new Promise<unknown>((res) => {
        resolveRequest = () => {
          settled.done = true;
          res({ ok: true });
        };
      }),
  );
  (reporter as unknown as { client: unknown }).client = { request };
  return { request, settle: () => resolveRequest(), settled };
}

beforeEach(() => {
  process.env.EVALGUARD_API_KEY = "eg_test_key";
});
afterEach(() => {
  delete process.env.EVALGUARD_API_KEY;
  vi.restoreAllMocks();
});

describe("EvalGuardReporter.onFinished", () => {
  it("**returns a promise that does not resolve until the upload completes**", async () => {
    const reporter = new EvalGuardReporter({ projectId: "proj_1" });
    const stub = stubClient(reporter);

    reporter.onInit();
    const finished = reporter.onFinished([fileWithTests()]);
    expect(finished).toBeInstanceOf(Promise);

    // The upload is in flight. Pre-fix `onFinished` had already returned
    // undefined here and vitest would have exited.
    let resolved = false;
    void finished.then(() => {
      resolved = true;
    });
    await Promise.resolve();
    expect(stub.request).toHaveBeenCalledTimes(1);
    expect(resolved).toBe(false);
    expect(stub.settled.done).toBe(false);

    stub.settle();
    await finished;
    expect(stub.settled.done).toBe(true);
  });

  it("posts the collected cases and a correct summary to /evals/ci", async () => {
    const reporter = new EvalGuardReporter({ projectId: "proj_1" });
    const request = vi.fn(async () => ({}));
    (reporter as unknown as { client: unknown }).client = { request };

    reporter.onInit();
    await reporter.onFinished([fileWithTests()]);

    expect(request).toHaveBeenCalledTimes(1);
    const [path, method, body] = request.mock.calls[0] as unknown as [string, string, Record<string, unknown>];
    expect(path).toBe("/evals/ci");
    expect(method).toBe("POST");
    expect(body.projectId).toBe("proj_1");
    expect(body.summary).toMatchObject({ total: 2, passed: 1, failed: 1 });
    expect((body.cases as unknown[]).length).toBe(2);
  });

  it("a failed upload still resolves (never breaks the test run)", async () => {
    const reporter = new EvalGuardReporter({ projectId: "proj_1" });
    const request = vi.fn(async () => {
      throw new Error("ECONNRESET");
    });
    (reporter as unknown as { client: unknown }).client = { request };
    vi.spyOn(console, "warn").mockImplementation(() => {});

    reporter.onInit();
    await expect(reporter.onFinished([fileWithTests()])).resolves.toBeUndefined();
  });

  it("resolves immediately when no API key is configured", async () => {
    delete process.env.EVALGUARD_API_KEY;
    const reporter = new EvalGuardReporter({});
    reporter.onInit();
    await expect(reporter.onFinished([fileWithTests()])).resolves.toBeUndefined();
  });
});
