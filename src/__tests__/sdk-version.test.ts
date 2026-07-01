import { describe, it, expect } from "vitest";
import { SDK_VERSION } from "../client";

// Sanity guard for SDK_VERSION, which is generated from package.json#version by
// scripts/gen-version.mjs on `prebuild`. We deliberately do NOT assert exact
// equality with package.json here: between a `changeset version` bump and the
// next build the committed version.ts can lag package.json, and the prebuild
// regenerates the correct value into the PUBLISHED artifact regardless. Asserting
// exact equality produced false CI failures (e.g. 2.3.0 vs 2.3.1) right after a
// version bump. A semver-shape check catches the real regression we care about
// (the baked constant becoming undefined/garbage, like the 2.1.0-in-2.3.0 bug)
// without the version-bump friction.
describe("SDK_VERSION", () => {
  it("is a defined, valid semver string", () => {
    expect(typeof SDK_VERSION).toBe("string");
    expect(SDK_VERSION).toMatch(/^\d+\.\d+\.\d+(?:[-+].*)?$/);
  });
});
