import {defineConfig} from "vitest/config";

// The rule tests build a real ESLint with the repository config, which loads typescript-eslint and
// every plugin: the first sample takes seconds.
export default defineConfig({test: {testTimeout: 60_000, hookTimeout: 60_000}});
