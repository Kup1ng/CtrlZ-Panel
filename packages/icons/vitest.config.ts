import {defineConfig} from "vitest/config";

// tsconfig.base.json says jsx "preserve" for Next, which Vite would leave as JSX.
export default defineConfig({
  oxc: {jsx: {runtime: "automatic"}},
  test: {include: ["test/**/*.test.{ts,tsx,mjs}"]},
});
