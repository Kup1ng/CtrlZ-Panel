import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import enFeedback from "../../../packages/i18n/messages/en/feedback.json";
import faFeedback from "../../../packages/i18n/messages/fa/feedback.json";
import {acc, LANGS, open, row, sessionsFixture} from "./account-support.ts";

// T-121, spec 8.7. A shell page that throws while rendering lands in `(shell)/error.tsx`: the section error with the sidebar still
// there. Its Retry holds the keyboard focus and leaves with the error, so the boundary's `reset` goes through keepReset (as the
// admin's does), and the focus ends in the page and not on <body>, where the next Tab would start at the skip link.
//
// The crash is a session whose address is an object: the Sessions editor draws it as text and React refuses. The error is raised in
// the Account page, under the shell layout, so it is the shell's boundary that catches it, and not global-error.tsx.
test.use({allowConsole: [/Minified React error|Objects are not valid as a React child|The above error occurred|status of (404|500)/]});

const T = {fa: {common: faCommon, feedback: faFeedback}, en: {common: enCommon, feedback: enFeedback}} as const;

for (const {lang, dir} of LANGS) {
  test.describe(`the shell's error boundary, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("a page that throws shows the section error with the sidebar, and Retry by keyboard keeps the focus in the page", async ({page, context, baseURL}) => {
      const broken = sessionsFixture().map((session, i) => (i === 0 ? {...session, ip: {broken: true}} : session));
      await open(context, baseURL, {handlers: {"GET /account/sessions": {body: {sessions: broken}}}});
      await page.goto(`/${lang}/preferences/account`);
      await expect(row(page, "sessions")).toBeVisible();
      await row(page, "sessions").getByRole("button", {name: acc(lang, "sessions.manageAria")}).click();

      const alert = page.getByRole("alert").filter({hasText: T[lang].feedback.error.title});
      await expect(alert).toBeVisible();
      // The sidebar is the shell's, outside the boundary: it stays, and the visitor can go elsewhere.
      await expect(page.locator("aside.sidebar")).toBeVisible();
      const retry = alert.getByRole("button", {name: T[lang].common.retry});
      await expect(retry).toBeVisible();

      // By keyboard: the Retry takes the focus (as Tab would give it) and Enter presses it.
      await retry.focus();
      await expect(retry).toBeFocused();
      await page.keyboard.press("Enter");

      // The page renders again (the editor closed with the remount, so nothing throws), and the focus is inside the shell's page.
      await expect(alert).toHaveCount(0);
      await expect(row(page, "phone")).toBeVisible();
      await expect
        .poll(() =>
          page.evaluate(() => {
            const active = document.activeElement;
            return !!active && active !== document.body && !!active.closest("#main-content");
          }),
        )
        .toBe(true);
    });
  });
}
