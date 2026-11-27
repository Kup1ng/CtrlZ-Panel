import {resolve} from "node:path";

import {hasLoginPage} from "@ctrlz/ui/proxy/loginPage.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

// Spec 17.1 harness proof for the admin app, as in apps/panel/e2e/harness.matrix.spec.ts. The page is
// the admin login (spec 19.2), the first page of this app that renders the root document.
//
// It is skipped until WP10 builds that page, and the skip is visible in every run. Nothing else in
// apps/admin can stand in for it: an unknown path gets Next's own 404, which sits outside the
// `[locale]` layout, so it has no `lang`, no `dir` and no theme, and its inline scripts carry no
// CSP nonce, which the guard reports as `script-src-elem` violations. WP10's not-found page (19.2)
// is what fixes that, and `states.spec.ts` for the admin should then assert it.
// A route group such as (auth) does not change the URL, so the page may sit in one (wp5-r16-2).
const loginBuilt = hasLoginPage(resolve(__dirname, ".."));

test.skip(!loginBuilt, "apps/admin has no page yet that renders the root document (login is WP10's)");

test("the project's width, language and theme are what the page renders", async ({page, context, baseURL, matrix}) => {
  expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
  const {lang} = matrix!;
  const response = await page.goto(`/${lang}/login`);
  await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
});
