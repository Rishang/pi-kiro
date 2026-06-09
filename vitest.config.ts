import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      // Measure only the shipped source, not tests/harness/config.
      include: ["src/**/*.ts"],
      reporter: ["text-summary", "html", "lcov"],
      // Floor thresholds: a safety net against coverage regressions, set
      // a few points below the current numbers (81% lines / 71% branches /
      // 84% functions). The gap to 100% is mostly network/streaming and
      // OAuth paths that only execute under the live-gated pi-mono suites
      // (KIRO_LIVE_TEST=1). Raise these as offline coverage grows.
      thresholds: {
        statements: 75,
        branches: 65,
        functions: 80,
        lines: 75,
      },
    },
  },
});
