import {defineConfig} from "vitest/config";

// Unit tests live next to their code under src/. e2e/ holds Playwright specs, which
// call test.beforeAll and friends from another runner, so Vitest must never collect
// them: it fails each file with "Playwright Test did not expect test.beforeAll()".
export default defineConfig({
  test: {
    include: ["src/**/*.test.{ts,tsx}"],
    exclude: ["e2e/**", "node_modules/**", ".next/**"],
  },
});
