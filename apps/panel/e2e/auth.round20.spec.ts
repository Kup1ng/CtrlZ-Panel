import {publicConfigFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  liveConfig,
  LANGS,
  openAnonymous,
  refetchConfig,
  text,
} from "./auth-support.ts";

// Round 20 of the review of WP8. wp8-r20-1 (the invite link and the language switch) is in auth.round10.spec.ts, beside
// the holds it replaced. Here: wp8-r20-2, a sign-in URL that asked for the SMS form shows the password form while
// /auth/config has failed or says SMS is down, and a later answer that says SMS works must add the SMS tab beside that
// form, not swap the form under what was typed.

test.beforeEach(({guard}) => allowAuthErrors(guard));

for (const {lang, dir} of LANGS) {
  test.describe(`round 20, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("wp8-r20-2: /auth/config failed at ?step=otp-phone, a later success keeps the password form and what was typed", async ({
      page,
      context,
    }) => {
      await page.clock.install();
      let asked = 0;
      let healthy = false;
      const mock = await openAnonymous(context, {
        // The first answer fails with its two retries (the retry rule of spec 14.4), then the API is back.
        "GET /auth/config": () => {
          asked += 1;
          return healthy ? {body: publicConfigFixture({sms_available: true})} : err(503, "service_unavailable");
        },
      });
      await page.goto(`/${lang}/login?step=otp-phone`);
      // The retries wait 1 s and 2 s on the page's clock.
      await expect
        .poll(async () => {
          await page.clock.fastForward(2_500);
          return asked;
        })
        .toBeGreaterThanOrEqual(3);
      await expect(field(page, "password")).toBeVisible();
      await expect(page.getByRole("tab", {name: T("login.tabOtp")})).toHaveCount(0);
      await field(page, "phone").fill("09123456789");
      await field(page, "password").fill("typed while the config failed");
      await field(page, "password").focus();

      healthy = true;
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      // The SMS tab arrives beside the form; the form is the one the visitor was typing into.
      await expect(page.getByRole("tab", {name: T("login.tabOtp")})).toBeVisible();
      await expect(page.getByRole("tab", {name: T("login.tabPassword")})).toHaveAttribute("aria-selected", "true");
      await expect(field(page, "password")).toHaveValue("typed while the config failed");
      await expect(field(page, "phone")).toHaveValue("09123456789");
      await expect(field(page, "password")).toBeFocused();
    });

    test("wp8-r20-2: the same when /auth/config answered that SMS is down and then that it works", async ({page, context}) => {
      await page.clock.install();
      const {answer, handlers} = liveConfig({sms_available: false});
      const mock = await openAnonymous(context, handlers);
      await page.goto(`/${lang}/login?step=otp-phone`);
      await expect(field(page, "password")).toBeVisible();
      await field(page, "password").fill("typed while SMS was down");
      await field(page, "password").focus();

      answer.value = {sms_available: true};
      await refetchConfig(page, () => callsTo(mock, "GET", "/auth/config").length);

      await expect(page.getByRole("tab", {name: T("login.tabOtp")})).toBeVisible();
      await expect(field(page, "password")).toHaveValue("typed while SMS was down");
      await expect(field(page, "password")).toBeFocused();
    });
  });
}
