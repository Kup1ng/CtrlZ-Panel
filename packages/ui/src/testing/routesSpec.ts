import {existsSync, readFileSync} from "node:fs";
import {resolve} from "node:path";

import {expect, test} from "@playwright/test";

import {hasLoginPage} from "../proxy/loginPage.ts";
import {ADMIN_PROTECTED_PREFIXES, PANEL_PROTECTED_PREFIXES} from "../proxy/prefixes.ts";
import {ADMIN_ROUTES, fatalProblems, gateProblems, listRoutes, pageFiles, PANEL_LAB_ROUTES, PANEL_ROUTES, routeOf, strayRoutes, withoutLocale} from "./routes.ts";

// The body of `apps/*/e2e/routes.spec.ts` (spec 17.3, T-414, T-438). It reads files and starts no
// browser, so it uses Playwright's own `test` and not the guard. The two apps share it, with their
// own allowlist.

type Options = {
  app: "panel" | "admin";
  /** `apps/<app>`, from the config file's directory. */
  appDir: string;
};

// The pages that the proxy gates but that are not in the (shell) group: the admin's first-run setup, which is a login-style screen (spec 19.2).
const GATED_OUTSIDE_SHELL = {panel: [], admin: ["/setup"]} as const;
const PREFIXES = {panel: PANEL_PROTECTED_PREFIXES, admin: ADMIN_PROTECTED_PREFIXES} as const;

const ALLOWED = {panel: [...PANEL_ROUTES, ...PANEL_LAB_ROUTES], admin: [...ADMIN_ROUTES]} as const;

export function declareRoutesSpec({app, appDir}: Options): void {
  const appTree = resolve(appDir, "src/app");
  const repoRoot = resolve(appDir, "../..");
  const lab: readonly string[] = app === "panel" ? PANEL_LAB_ROUTES : [];

  test.describe(`routes of ${app}`, () => {
    test("every page is one of the screens of spec 19", () => {
      const found = listRoutes(appTree).map(withoutLocale);
      const stray = strayRoutes(found, ALLOWED[app]);
      expect(stray, `pages outside the allowlist of spec 19 (add the screen to spec 19 first, then to packages/ui/src/testing/routes.ts): ${stray.join(", ")}`).toEqual([]);
    });

    test("every page lives under [locale], so no route skips the language and proxy rules", () => {
      const outside = pageFiles(appTree).filter((file) => !file.startsWith("[locale]/"));
      expect(outside, "pages and route handlers outside [locale]").toEqual([]);
    });

    test("no Route Handler exists: the web tier serves pages and static files only", () => {
      const handlers = pageFiles(appTree).filter((file) => /(^|\/)route\.(ts|js)$/.test(file));
      expect(handlers).toEqual([]);
    });

    // gate-r2-10, gate-r2-15, gate-r2-19: the gate of 15.4 is a hand-kept list, and this is what keeps it the same set as the signed-in pages.
    test("every page of the (shell) group is behind a protected prefix, no other page is, and every prefix has a page", () => {
      const problems = gateProblems(pageFiles(appTree), PREFIXES[app], GATED_OUTSIDE_SHELL[app]);
      expect(problems, problems.join("\n")).toEqual([]);
    });

    // gate-r7-1: the fatal page. Next's own has a <style> element with no nonce, so an app with pages must have its own, made of style attributes.
    // The admin has only a stub page until WP10 builds its login page (hasLoginPage, as in headersSpec.ts). From then on this case fails until
    // WP10 has added apps/admin/src/app/global-error.tsx: the check starts by itself, with no edit of this file.
    test("an app with pages has its own global-error.tsx, with no style element (gate-r7-1)", () => {
      const file = resolve(appTree, "global-error.tsx");
      const problems = fatalProblems(app === "panel" || hasLoginPage(appDir), existsSync(file) ? readFileSync(file, "utf8") : null);
      expect(problems, problems.join("\n")).toEqual([]);
    });

    test("the allowlist names no page twice", () => {
      expect(new Set(ALLOWED[app]).size).toBe(ALLOWED[app].length);
    });

    if (app === "panel") {
      test("the lab pages sit in the (lab) group, and nothing else does", () => {
        const files = pageFiles(appTree);
        expect(files.some((file) => file.includes("/(lab)/")), "no page in the (lab) group").toBe(true);
        for (const file of files) {
          const route = withoutLocale(routeOf(file));
          if (file.includes("/(lab)/")) expect(lab, `${route} is in (lab) but is not listed as a lab page`).toContain(route);
          else expect(lab, `${route} is a lab page outside the gated (lab) group`).not.toContain(route);
        }
      });

      test("the (lab) layout answers 404 unless CTRLZ_LAB is 1", () => {
        const layout = readFileSync(resolve(appTree, "[locale]/(lab)/layout.tsx"), "utf8");
        expect(layout).toMatch(/process\.env\.CTRLZ_LAB\s*!==\s*"1"/);
        expect(layout).toMatch(/notFound\(\)/);
      });
    }

    test("content/{fa,en}/{guide,tech} exist (T-414, T-438)", () => {
      for (const lang of ["fa", "en"]) {
        for (const kind of ["guide", "tech"]) {
          expect(existsSync(resolve(repoRoot, "content", lang, kind)), `content/${lang}/${kind}`).toBe(true);
        }
      }
    });
  });
}
