import {resolve} from "node:path";

import {defineConfig, type PlaywrightTestConfig} from "@playwright/test";

import {HEIGHTS, MATRIX, projectName} from "./matrix.ts";

// The one Playwright config of spec 17.1, used by `apps/*/playwright.config.ts`. It replaces the
// three configs that the earlier work packages kept next to their specs (mock, stack and lab).
//
// Mode, from E2E_MODE:
//
//   mock   (default) `context.route` answers `/api/v1` from typed fixtures, against `next start` over
//          http://localhost, which Chrome treats as a secure context, so `__Host-` cookies work.
//          Base URL http://localhost:3410 (panel) and :3411 (admin).
//   stack  the real Compose stack behind Caddy over HTTPS (`deploy/compose/e2e*.yml`, section 17.7).
//          Base URL https://panel.localhost and https://admin.localhost, `ignoreHTTPSErrors` for
//          Caddy's local CA. Runs `*.stack.spec.ts` only.
//   lab    `lab.spec.ts` alone, one worker, because its budgets are measured, not a speed test.
//
// E2E_BASE_URL overrides the base URL. E2E_CHANNEL overrides the browser (`chrome` by default:
// `playwright install` downloads from a CDN, which this project forbids, so the installed browser is
// the only one). E2E_START_SERVER=1 starts `next start` for the app, which is what `scripts/ci-web.sh`
// does; otherwise a server must already be listening.
//
// File names pick the project a spec runs in:
//
//   *.matrix.spec.ts  the 12 projects `w375-fa-dark` and so on: every screen's smoke case and axe run
//   *.stack.spec.ts   stack mode only
//   lab.spec.ts       lab mode only
//   any other *.spec.ts  one `functional` project, for specs that loop over language and theme themselves

export type E2eApp = "panel" | "admin";
export type E2eMode = "mock" | "stack" | "lab";

const MOCK_PORT: Record<E2eApp, number> = {panel: 3410, admin: 3411};
const STACK_URL: Record<E2eApp, string> = {panel: "https://panel.localhost", admin: "https://admin.localhost"};
const LAB_PORT = 3100;

const MATRIX_SPEC = /\.matrix\.spec\.ts$/;
const STACK_SPEC = /\.stack\.spec\.ts$/;
const LAB_SPEC = /(^|[\\/])lab\.spec\.ts$/;

export function readMode(value: string | undefined): E2eMode {
  if (value === undefined || value === "" || value === "mock") return "mock";
  if (value === "stack" || value === "lab") return value;
  throw new Error(`E2E_MODE must be mock, stack or lab, not "${value}"`);
}

export function baseUrlFor(app: E2eApp, mode: E2eMode, override?: string): string {
  if (override) return override;
  if (mode === "stack") return STACK_URL[app];
  if (mode === "lab") return `http://localhost:${LAB_PORT}`;
  return `http://localhost:${MOCK_PORT[app]}`;
}

export function defineE2eConfig(app: E2eApp, env: NodeJS.ProcessEnv = process.env): PlaywrightTestConfig {
  const mode = readMode(env.E2E_MODE);
  const baseURL = baseUrlFor(app, mode, env.E2E_BASE_URL);
  const base: PlaywrightTestConfig = {
    testDir: "e2e",
    outputDir: "e2e/test-results",
    // The second reporter prints the known axe failures and the undecided ones at the end (spec 17.5).
    // Playwright loads the app's config as CommonJS, so `import.meta` is not available here: the path is
    // from the app folder, which is where every run starts (`testDir` is relative to it too).
    reporter: [["list"], [resolve(process.cwd(), "../../packages/ui/src/testing/axeReporter.ts")]],
    timeout: 60_000,
    expect: {timeout: 10_000},
    // A failing test is a finding, so nothing is retried: a pass on the second try would hide a race.
    retries: 0,
    use: {
      baseURL,
      channel: env.E2E_CHANNEL ?? "chrome",
      // Caddy's local CA in stack mode. Harmless over http.
      ignoreHTTPSErrors: true,
    },
  };

  if (mode === "stack") {
    return defineConfig({...base, workers: 1, projects: [{name: "stack", testMatch: STACK_SPEC}]});
  }

  if (mode === "lab") {
    return defineConfig({
      ...base,
      workers: 1,
      timeout: 120_000,
      projects: [{name: "lab", testMatch: LAB_SPEC}],
    });
  }

  const port = new URL(baseURL).port || String(MOCK_PORT[app]);
  return defineConfig({
    ...base,
    // At most two browsers at once: the machine also runs other work (spec 17.1 asks for a modest load).
    workers: Math.min(Number(env.E2E_WORKERS ?? 2) || 2, 2),
    projects: [
      {name: "functional", testMatch: /\.spec\.ts$/, testIgnore: [MATRIX_SPEC, STACK_SPEC, LAB_SPEC]},
      ...MATRIX.map((matrix) => ({
        name: projectName(matrix),
        testMatch: MATRIX_SPEC,
        metadata: {matrix},
        use: {
          viewport: {width: matrix.width, height: HEIGHTS[matrix.width]},
          colorScheme: matrix.theme,
          locale: matrix.lang === "fa" ? "fa-IR" : "en-US",
        },
      })),
    ],
    webServer:
      env.E2E_START_SERVER === "1"
        ? {
            // `next start` reads CTRLZ_LAB per request, and only the panel has a lab group.
            command: `pnpm exec next start -p ${port}`,
            // A file in public/ or a root metadata file: it needs no session and no locale. The locale root
            // redirects to a login page that WP8 has not built, and Playwright takes a 404 for "not up yet".
            url: `${new URL(baseURL).origin}/icon.png`,
            env: {...(app === "panel" ? {CTRLZ_LAB: "1"} : {}), NEXT_TELEMETRY_DISABLED: "1"},
            reuseExistingServer: false,
            timeout: 120_000,
            stdout: "ignore",
            stderr: "pipe",
          }
        : undefined,
  });
}
