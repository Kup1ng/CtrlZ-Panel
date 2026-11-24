import {publicConfigFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  field,
  gotoForm,
  inviteInfoFixture,
  LANGS,
  openAnonymous,
  submit,
  text,
} from "./auth-support.ts";

// Round 2 of the review of WP8: what a successful Resend leaves behind (wp8-r2-2), and a password typed while
// /auth/config is still loading (wp8-r2-3). The other findings of the round are held next to the screens they
// belong to (login.spec.ts, invite.spec.ts, password.spec.ts, forms.test.tsx, safeNext.test.ts).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(6);
// One second, so the real clock is enough to wake the button.
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 1}};
const CODE = "ABCDEFGHJKMNPQRSTVWX";

for (const {lang, dir} of LANGS) {
  test.describe(`resend, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    /** Presses Resend with the keyboard, as a keyboard user does, and checks where the focus ends up. */
    async function resendWithKeyboard(page: Page, mock: Awaited<ReturnType<typeof openAnonymous>>) {
      const resend = page.getByRole("button", {name: T("resend.action")});
      await expect(resend).toBeEnabled();
      await resend.focus();
      await page.keyboard.press("Enter");
      await expect.poll(() => callsTo(mock, "POST", "/auth/otp/request").length).toBe(2);
      // The button that had the focus was replaced by the new challenge's: the focus must not fall to the page.
      await expect(field(page, "code")).toBeFocused();
      await expect(page.getByRole("status").filter({hasText: T("resend.sent")})).toBeVisible();
      await expect(field(page, "code")).toHaveValue("");
    }

    test("wp8-r2-2: Login, the SMS code", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/login?step=otp-phone`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await resendWithKeyboard(page, mock);
    });

    test("wp8-r2-2: Register", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await resendWithKeyboard(page, mock);
    });

    test("wp8-r2-2: Invite", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/invites/lookup": {body: inviteInfoFixture()},
        "POST /auth/otp/request": issued,
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(submit(page)).toBeEnabled();
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await resendWithKeyboard(page, mock);
    });

    test("wp8-r2-2: Forgot Password", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/forgot-password`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await resendWithKeyboard(page, mock);
    });
  });

  test.describe(`login while /auth/config loads, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    // wp8-r2-3: the form is usable at once (10.1), so on a slow link the visitor types before the answer comes.
    // The answer must not rebuild the form: the password would be gone and the focus with it.
    for (const sms of [true, false]) {
      test(`a password typed during the load survives the answer (SMS ${sms ? "works" : "is down"})`, async ({page, context}) => {
        let release!: () => void;
        const gate = new Promise<void>((resolve) => {
          release = resolve;
        });
        let asked = 0;
        await openAnonymous(context, {
          "GET /auth/config": async () => {
            asked += 1;
            await gate;
            return {body: publicConfigFixture({sms_available: sms})};
          },
        });
        await gotoForm(page, `/${lang}/login`);
        await expect.poll(() => asked).toBeGreaterThan(0);
        await field(page, "phone").fill(PHONE);
        await field(page, "password").fill("correct horse");
        await expect(field(page, "password")).toBeFocused();
        release();
        if (sms) await expect(page.getByRole("tablist")).toBeVisible();
        else {
          await expect(page.getByText(T("login.smsDown"))).toBeVisible();
          // The list is kept in the page for the panel's label, and not shown.
          await expect(page.getByRole("tablist")).toHaveCount(0);
        }
        await expect(field(page, "password")).toHaveValue("correct horse");
        await expect(field(page, "password")).toBeFocused();
        await expect(field(page, "phone")).toHaveValue(PHONE);
      });
    }
  });
}
