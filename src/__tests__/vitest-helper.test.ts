import { describe, expect, it } from "vitest";
import { expectScore } from "../vitest";

// expectScore is the public assertion helper customers use in their
// vitest tests. Bugs class:
//   - Off-by-one bound (>= vs >) → tests pass when they should fail
//   - Range bounds inverted → "to be in [0.8, 0.95]" never matches
//   - Error message missing actual value → user can't debug

describe("expectScore.toBeGreaterThan", () => {
  it("passes when value > threshold", () => {
    expect(() => expectScore(0.9).toBeGreaterThan(0.8)).not.toThrow();
  });

  it("FAILS when value === threshold (strict greater-than)", () => {
    expect(() => expectScore(0.8).toBeGreaterThan(0.8)).toThrow(/expected 0\.8/);
  });

  it("FAILS when value < threshold", () => {
    expect(() => expectScore(0.5).toBeGreaterThan(0.8)).toThrow(/greater than 0\.8/);
  });

  it("error message includes both actual and threshold", () => {
    try {
      expectScore(0.5).toBeGreaterThan(0.8);
      expect.fail("should have thrown");
    } catch (e) {
      expect((e as Error).message).toContain("0.5");
      expect((e as Error).message).toContain("0.8");
    }
  });
});

describe("expectScore.toBeLessThan", () => {
  it("passes when value < threshold", () => {
    expect(() => expectScore(0.2).toBeLessThan(0.3)).not.toThrow();
  });

  it("FAILS when value === threshold (strict less-than)", () => {
    expect(() => expectScore(0.3).toBeLessThan(0.3)).toThrow();
  });

  it("FAILS when value > threshold", () => {
    expect(() => expectScore(0.9).toBeLessThan(0.3)).toThrow(/less than/);
  });
});

describe("expectScore.toBeInRange", () => {
  it("passes when min <= value <= max (inclusive bounds)", () => {
    expect(() => expectScore(0.85).toBeInRange(0.8, 0.95)).not.toThrow();
    expect(() => expectScore(0.8).toBeInRange(0.8, 0.95)).not.toThrow();
    expect(() => expectScore(0.95).toBeInRange(0.8, 0.95)).not.toThrow();
  });

  it("FAILS when value < min", () => {
    expect(() => expectScore(0.7).toBeInRange(0.8, 0.95)).toThrow(/range/);
  });

  it("FAILS when value > max", () => {
    expect(() => expectScore(1.0).toBeInRange(0.8, 0.95)).toThrow(/range/);
  });

  it("error message includes the [min, max] range", () => {
    try {
      expectScore(0.5).toBeInRange(0.8, 0.95);
      expect.fail("should have thrown");
    } catch (e) {
      expect((e as Error).message).toContain("0.8");
      expect((e as Error).message).toContain("0.95");
    }
  });
});

describe("expectScore.toBe", () => {
  it("passes when value === expected (strict equality)", () => {
    expect(() => expectScore(0.5).toBe(0.5)).not.toThrow();
  });

  it("FAILS for any non-equal value (no float tolerance)", () => {
    expect(() => expectScore(0.5).toBe(0.50001)).toThrow();
    expect(() => expectScore(0).toBe(0.0)).not.toThrow(); // strict 0 == 0
  });
});
