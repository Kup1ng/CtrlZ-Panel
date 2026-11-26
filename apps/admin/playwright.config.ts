import {defineE2eConfig} from "@ctrlz/ui/testing/config.ts";

// Spec 17.1. The projects, the modes and the environment variables are described in
// packages/ui/src/testing/config.ts. From apps/admin, after `pnpm exec next build`:
//
//   E2E_START_SERVER=1 pnpm exec playwright test      # mock mode, starts `next start` itself
export default defineE2eConfig("admin");
