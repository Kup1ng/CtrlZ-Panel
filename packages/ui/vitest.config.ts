import {defineConfig} from "vitest/config";

export default defineConfig({
  // tsconfig keeps `jsx: preserve` for Next, which compiles JSX itself; a test of a component compiles it here.
  oxc: {jsx: {runtime: "automatic"}},
  test: {
    // The 5 s default is a guess about one test, not a limit of ours. The suite runs next to other work (a CI runner, a second
    // workflow) and several tests do real work: a cold import of the real proxy.ts (next-intl and next/server through the transform), the
    // HeroUI Pro barrel (30 s alone, over 80 s under load) and whole-tree scans of the sources. At 5 s the matcher test of 15.4 was red for
    // load and not for the literal, so a real regression could not be told from it (gate-r3-1). A hung test is still caught: 30 s.
    testTimeout: 30_000,
    hookTimeout: 120_000,
    server: {
      // next-intl's ESM build imports "next/server" without the extension,
      // which Node's resolver refuses. Vite resolves it when it processes the
      // package itself.
      deps: {inline: ["next-intl"]},
    },
  },
});
