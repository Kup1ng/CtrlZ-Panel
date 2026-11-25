// Flat config. WP0 lands the base: typescript-eslint, react-hooks and jsx-a11y.
// WP12 adds the custom rules of spec section 16.1 and then freezes this file.
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";
import {fileURLToPath} from "node:url";
import {readUrlAllow} from "./tools/web-lint/src/urlAllow.ts";
import {exemptFiles, restrictedImports, restrictedSyntax, syntaxExcept} from "./tools/web-lint/src/banned.ts";

export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/.next/**",
      "**/next-env.d.ts",
      "**/*.generated.*",
      "**/generated/**",
      "apps/*/e2e/test-results/**",
      "**/playwright-report/**",
      // Go and everything that is not web code.
      "cmd/**",
      "internal/**",
      "shared/**",
      "migrations/**",
      "docs/**",
      "deploy/**",
    ],
  },
  ...tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
  jsxA11y.flatConfigs.recommended,
  {
    files: ["**/*.{ts,tsx,mjs}"],
    rules: {
      // A type import stays a type import: required by verbatimModuleSyntax.
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
  {
    // The bans of spec 16.1 that need no plugin. Tests and generated code are not shipped.
    files: ["apps/*/src/**/*.{ts,tsx}", "packages/*/src/**/*.{ts,tsx}"],
    ignores: ["**/*.test.{ts,tsx}", "**/*.typecheck.ts", "**/generated/**"],
    rules: {
      "no-restricted-imports": ["error", restrictedImports],
      "no-restricted-syntax": ["error", ...restrictedSyntax.map(({selector, message}) => ({selector, message}))],
    },
  },
  {
    files: exemptFiles.rawIntl,
    rules: {"no-restricted-syntax": ["error", ...syntaxExcept("intl")]},
  },
  {
    // A reviewed list, one line and one reason each.
    files: readUrlAllow(fileURLToPath(new URL("./tools/web-lint/url-allow.txt", import.meta.url))),
    rules: {"no-restricted-syntax": ["error", ...syntaxExcept("url")]},
  },
  {
    files: exemptFiles.themeBranch,
    rules: {"no-restricted-syntax": ["error", ...syntaxExcept("dark")]},
  },
);
