import {defineConfig} from "@playwright/test";

// Config of lab.spec.ts alone. The shared Playwright config, the guard that fails on external
// requests and the Caddy setup are WP12's (spec 17.1); until they land, this one sets what the
// spec needs. WP12 can fold it in.
//
// The browser is the installed Edge: `playwright install` downloads from a CDN, which this project
// forbids. Run it from apps/panel against a production build started with CTRLZ_LAB=1:
//
//   CTRLZ_LAB=1 pnpm exec next build
//   CTRLZ_LAB=1 pnpm exec next start -p 3100
//   pnpm exec playwright test -c e2e/lab.config.ts
export default defineConfig({
  testDir: ".",
  testMatch: "lab.spec.ts",
  // One browser at a time: the timing budgets are measured, not a speed test.
  workers: 1,
  timeout: 120_000,
  reporter: "list",
  outputDir: "test-results",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3100",
    channel: "msedge",
    ignoreHTTPSErrors: true,
  },
});
