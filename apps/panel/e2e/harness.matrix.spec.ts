import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectMatrixPage} from "@ctrlz/ui/testing/matrixAssert.ts";

import {signIn} from "./feedback-support.ts";

// Spec 17.1 harness proof: the 12 projects (three widths, two languages, two themes) each get the
// width, the language and the theme they name, and the guard of 17.2 is on. It is not a screen's
// smoke case: each screen's work package adds its own `<screen>.matrix.spec.ts` beside this one and
// reads `matrix` the same way. The page is a stub of the shell, so no work package's screen is
// needed for the harness to be checked. The assertions are in packages/ui/src/testing/matrixAssert.ts.

test("the project's width, language and theme are what the page renders", async ({page, context, baseURL, matrix}) => {
  expect(matrix, "this spec runs only in the 12 matrix projects").not.toBeNull();
  await signIn(context, baseURL);
  const {lang} = matrix!;
  const response = await page.goto(`/${lang}/profiles`);
  await expectMatrixPage({page, context, response, baseURL, matrix: matrix!});
});
