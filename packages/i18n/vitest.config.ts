import {defineConfig} from "vitest/config";

export default defineConfig({
  test: {
    server: {
      // next-intl's ESM build imports "next/server" without the extension,
      // which Node's resolver refuses. Vite resolves it when it processes the
      // package itself.
      deps: {inline: ["next-intl"]},
    },
  },
});
