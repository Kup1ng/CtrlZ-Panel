// Flat config. WP0 landed the base (typescript-eslint, react-hooks, jsx-a11y), WP12 added the rules
// of spec 16.1 and froze it: a new exception goes in a file under tools/web-lint, one line and one
// reason, and this file does not change.
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";
import {fileURLToPath} from "node:url";
import {readUrlAllow} from "./tools/web-lint/src/urlAllow.ts";
import ctrlz from "./tools/web-lint/src/plugin.ts";
import {exemptFiles, restrictedImports, restrictedSyntax, syntaxExcept} from "./tools/web-lint/src/banned.ts";

const SHIPPED = ["apps/*/src/**/*.{ts,tsx}", "packages/*/src/**/*.{ts,tsx}"];
const NOT_SHIPPED = ["**/*.test.{ts,tsx}", "**/*.typecheck.ts", "**/generated/**", "packages/ui/src/testing/**", "**/testing/fixtures.ts", "**/fixtures.ts"];
const readAllow = (name) => readUrlAllow(fileURLToPath(new URL(`./tools/web-lint/${name}`, import.meta.url)));

// ESLint refuses an empty `files`, and an allow file may have no lines yet.
const offFor = (name, rule) => {
  const files = readAllow(name);
  return files.length ? [{files, rules: {[rule]: "off"}}] : [];
};

// Where a browser test can live (spec 17.2): the apps' e2e files, the shared spec bodies and the helpers of the harness.
const SPEC_FILES = ["apps/*/e2e/**/*.ts", "packages/ui/src/proxy/*Spec.ts", "packages/ui/src/testing/**/*.ts"];
// The guard wraps Playwright's own test, and the unit tests of the harness run in vitest. routesSpec.ts has a block of its own below.
const SPEC_EXEMPT = ["packages/ui/src/testing/guard.ts", "packages/ui/src/testing/**/*.test.ts", "packages/ui/src/testing/routesSpec.ts"];
const SPEC_IMPORT = {
  name: "@playwright/test",
  importNames: ["test", "expect", "default"],
  allowTypeImports: true,
  message: "Import test and expect from @ctrlz/ui/testing/guard.ts, which adds the checks of spec 17.2.",
};
// A context or a browser that a spec opens itself has no external-request record, no CSP binding and no console check
// (gate-r1-5, gate-r1-7). A second visitor comes from guard.newContext(), a second page of the same visitor from
// context.newPage(). The APIRequest newContext (playwright.request.newContext) is not a browser and stays allowed.
const SPEC_SYNTAX = [
  {
    selector: "CallExpression[callee.property.name=/^(newContext|newPage)$/][callee.object.name='browser']",
    message: "Open a second visitor with guard.newContext(): browser.newContext() and browser.newPage() run with none of the checks of spec 17.2.",
  },
  {
    selector: "CallExpression[callee.property.name=/^(newContext|newPage)$/][callee.object.type='CallExpression'][callee.object.callee.property.name='browser']",
    message: "Open a second visitor with guard.newContext(): a context opened through browser() runs with none of the checks of spec 17.2.",
  },
  {
    selector: "CallExpression[callee.property.name=/^(newContext|newPage)$/][callee.object.type='TSNonNullExpression'][callee.object.expression.callee.property.name='browser']",
    message: "Open a second visitor with guard.newContext(): a context opened through browser() runs with none of the checks of spec 17.2.",
  },
  {
    // bypassCSP turns CSP enforcement off in the browser, so no violation is ever raised and the check of 17.2 passes on a broken page (gate-r3-5).
    selector: "Property[key.name='bypassCSP'], Property[key.value='bypassCSP'], Literal[value=/setBypassCSP/], Identifier[name='setBypassCSP']",
    message: "bypassCSP and Page.setBypassCSP turn the CSP check of spec 17.2 off: fix the page, never the check.",
  },
  {
    // The guard is an auto fixture of the exported `test`. A spec that extends test with a fixture of the same name, or of the one it hangs on,
    // replaces it and every check of 17.2 with it, and nothing fails (gate-r12-2). test.use is listed as well: it sets option fixtures by name.
    selector:
      "CallExpression[callee.property.name=/^(extend|use)$/] > ObjectExpression > Property[key.name=/^(guard|context|page|browser|request)$/], " +
      "CallExpression[callee.property.name=/^(extend|use)$/] > ObjectExpression > Property[key.value=/^(guard|context|page|browser|request)$/]",
    message: "Never override the guard, context, page or browser fixture: it switches off the checks of spec 17.2. Add a new fixture with another name, or use test.use for options.",
  },
  {
    // Dropping the listeners of a page or context drops the request, response and console records the guard reads (gate-r12-2).
    selector: "CallExpression[callee.property.name=/^(removeAllListeners|unrouteAll)$/]",
    message: "removeAllListeners and unrouteAll remove the records and routes of the guard (spec 17.2): remove one listener or one route by name instead.",
  },
  {
    // The document-open steps erase every listener of the document and the window, so the init script of the guard loses its CSP, pagehide and
    // pageshow listeners while its marker (a window property) survives. The guard reads Chrome's console for a CSP violation as well (gate-r28-2),
    // but a fixture that rewrites the document is also not the page production serves, so a spec builds its page with page.route and goto.
    selector:
      "CallExpression[callee.property.name='setContent'], " +
      "CallExpression[callee.object.name='document'][callee.property.name=/^(open|write|writeln)$/], " +
      "CallExpression[callee.object.property.name='document'][callee.property.name=/^(open|write|writeln)$/]",
    message: "page.setContent, document.open and document.write rewrite the document and erase the listeners of the guard (spec 17.2): serve the page with page.route and open it with page.goto.",
  },
  {
    selector: "CallExpression[callee.property.name=/^(launch|launchPersistentContext|connect|connectOverCDP)$/]",
    message: "A browser that a spec launches itself runs with none of the checks of spec 17.2.",
  },
];

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
    ignores: ["**/*.test.{ts,tsx}", "**/*.typecheck.ts", "**/generated/**", "packages/ui/src/testing/**"],
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
    files: readAllow("url-allow.txt"),
    rules: {"no-restricted-syntax": ["error", ...syntaxExcept("url")]},
  },
  {
    files: exemptFiles.themeBranch,
    rules: {"no-restricted-syntax": ["error", ...syntaxExcept("dark")]},
  },
  {
    // The rules of spec 16.1 that are plugins of ours. "Shipped code" is what a visitor can run:
    // tests, fixtures, the Playwright harness and generated files are not.
    files: SHIPPED,
    ignores: NOT_SHIPPED,
    plugins: {ctrlz},
    rules: {
      "ctrlz/hugeicons-only-in-allowlist": "error",
      "ctrlz/no-physical-style": "error",
      "ctrlz/no-protocol-relative-url": "error",
      "ctrlz/no-physical-arrow": "error",
      "ctrlz/no-email": "error",
      "ctrlz/no-secret-param": "error",
      "ctrlz/no-storage": "error",
      "ctrlz/no-raw-text": "error",
      "ctrlz/reduced-motion": "error",
      "ctrlz/use-on-press": "error",
      // ctrlz/no-console of the spec table is ESLint's own rule: nothing to add.
      "no-console": "error",
    },
  },
  {
    // Fetching belongs to the browser (spec 14.1): the web tier's app/ trees do none.
    files: ["apps/*/src/app/**/*.{ts,tsx}"],
    ignores: NOT_SHIPPED,
    plugins: {ctrlz},
    rules: {"ctrlz/no-next-fetch": "error"},
  },
  {
    // Playwright hands a fixture a function called `use`, which the hooks rule takes for React's.
    files: ["packages/ui/src/testing/**/*.ts", "apps/*/e2e/**/*.ts"],
    rules: {"react-hooks/rules-of-hooks": "off"},
  },
  {
    // Spec 17.2: a spec takes `test` and `expect` from the guard, which fails it on an external request,
    // a CSP violation or a console error. A value import of either from Playwright itself would run the
    // spec with none of those checks and be green (wp12-r1-4). Types stay importable. The rules cover every place
    // a browser test can live: the apps' e2e files and the shared spec bodies and helpers in packages/ui, which are
    // where the biggest tests are since WP5 (gate-r4-2, gate-r4-4). The guard is the one file that builds on Playwright's own `test`.
    files: SPEC_FILES,
    ignores: SPEC_EXEMPT,
    rules: {
      "no-restricted-syntax": ["error", ...SPEC_SYNTAX],
      "no-restricted-imports": ["error", {paths: [SPEC_IMPORT]}],
    },
  },
  {
    // The shared spec bodies of packages/ui/src/proxy are also shipped-code territory for the other lists (the file globs of SHIPPED
    // match them), and a rule that is set again replaces its array, so the two lists are joined here.
    files: ["packages/ui/src/proxy/*Spec.ts"],
    rules: {
      "no-restricted-syntax": ["error", ...restrictedSyntax.map(({selector, message}) => ({selector, message})), ...SPEC_SYNTAX],
      "no-restricted-imports": ["error", {...restrictedImports, paths: [...restrictedImports.paths, SPEC_IMPORT]}],
    },
  },
  {
    // routesSpec.ts reads files and starts no browser, so it uses Playwright's own `test` (the one reviewed exception to SPEC_IMPORT). What
    // keeps it from becoming a browser test is the second rule: it may not take a page, a context or a browser fixture, which is what a
    // spec that copies its header would need. A browser case belongs in a spec that imports the guard.
    files: ["packages/ui/src/testing/routesSpec.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        ...SPEC_SYNTAX,
        {
          selector: "ObjectPattern > Property[key.name=/^(page|context|browser|guard)$/]",
          message: "routesSpec.ts imports Playwright's own test and starts no browser: a case that needs a page belongs in a spec that imports the guard (spec 17.2).",
        },
      ],
      "no-restricted-imports": "off",
    },
  },
  {files: exemptFiles.hugeicons, rules: {"ctrlz/hugeicons-only-in-allowlist": "off"}},
  {files: exemptFiles.arrowKeys, rules: {"ctrlz/no-physical-arrow": "off"}},
  ...offFor("storage-allow.txt", "ctrlz/no-storage"),
  ...offFor("raw-text-allow.txt", "ctrlz/no-raw-text"),
);
