import {errorBody, meFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock, type ApiMock} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  INVITE_TOKEN,
  allowAuthErrors,
  callsTo,
  err,
  field,
  formAlert,
  gotoForm,
  inviteInfoFixture,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  errorText,
  STRONG_PASSWORD,
  submit,
  text, typeWhenFocused} from "./auth-support.ts";

// Round 5 of the review of WP8: a success stays pending until the next page arrives (wp8-r5-1), a failure puts
// the focus back in the field the visitor was in (r5-2), the caret stays where it was in a code that is
// regrouped as it is typed (r5-3), a server field name that the page has no field for is still shown (r5-4),
// and a shown password is hidden again when the form is sent (r5-7).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const PASSWORD = "correct horse battery";
const OTP_ID = otpChallengeId(10);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 1}};
const INVITE = INVITE_TOKEN;

/** Holds the page that a sign-in goes to, as a slow network does, until `release` is called. */
async function holdProfiles(context: BrowserContext) {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const held = {count: 0};
  await context.route(/\/(fa|en)\/profiles/, async (route) => {
    held.count += 1;
    await gate;
    await route.continue();
  });
  return {held, release};
}

/** A submit that goes around the button, as a second press of Enter or a password manager does. */
const resubmit = (page: Page) =>
  page.evaluate(() => {
    document.querySelector("form")?.requestSubmit();
  });

for (const {lang, dir} of LANGS) {
  test.describe(`round 5, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    // wp8-r5-1: every success path that ends in a navigation. The page that was asked for is held, so the
    // moment between the answer and the arrival can be looked at.
    type Mock = ApiMock;
    type Leave = {
      name: string;
      /** Opens the page and sends the form with a success answer. Returns the mock and the route that signs in. */
      run: (page: Page, context: BrowserContext, baseURL: string | undefined) => Promise<{mock: Mock; route: string}>;
    };
    const LEAVES: Leave[] = [
      {
        name: "password login",
        run: async (page, context, baseURL) => {
          const mock = await openAnonymous(context, {"POST /auth/login/password": signedIn(context, baseURL), "GET /me": meReady()});
          await gotoForm(page, `/${lang}/login`);
          await field(page, "phone").fill(PHONE);
          await field(page, "password").fill(PASSWORD);
          await submit(page).click();
          return {mock, route: "/auth/login/password"};
        },
      },
      {
        name: "SMS code login",
        run: async (page, context, baseURL) => {
          const mock = await openAnonymous(context, {
            "POST /auth/otp/request": issued,
            "POST /auth/login/otp": signedIn(context, baseURL),
            "GET /me": meReady(),
          });
          await gotoForm(page, `/${lang}/login?step=otp-phone`);
          await field(page, "phone").fill(PHONE);
          await submit(page).click();
          await expect(field(page, "code")).toBeFocused();
          await page.keyboard.type("123456");
          return {mock, route: "/auth/login/otp"};
        },
      },
      {
        name: "second factor login",
        run: async (page, context, baseURL) => {
          const mock = await openAnonymous(context, {
            "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp"]}},
            "POST /auth/login/totp": signedIn(context, baseURL),
            "GET /me": meReady(),
          });
          await gotoForm(page, `/${lang}/login`);
          await field(page, "phone").fill(PHONE);
          await field(page, "password").fill(PASSWORD);
          await submit(page).click();
          await typeWhenFocused(page, "123456");
          return {mock, route: "/auth/login/totp"};
        },
      },
      {
        name: "registration",
        run: async (page, context, baseURL) => {
          const mock = await openAnonymous(
            context,
            {"POST /auth/otp/request": issued, "POST /auth/register": signedIn(context, baseURL), "GET /me": meReady()},
            {registration_mode: "open"},
          );
          await gotoForm(page, `/${lang}/register`);
          await field(page, "phone").fill(PHONE);
          await submit(page).click();
          await expect(field(page, "code")).toBeFocused();
          await page.keyboard.type("123456");
          await field(page, "password").fill(STRONG_PASSWORD);
          await submit(page).click();
          return {mock, route: "/auth/register"};
        },
      },
      {
        name: "invite acceptance",
        run: async (page, context, baseURL) => {
          const mock = await openAnonymous(context, {
            "POST /auth/invites/lookup": {body: inviteInfoFixture()},
            "POST /auth/otp/request": issued,
            "POST /auth/register": signedIn(context, baseURL),
            "GET /me": meReady(),
          });
          await page.goto(`/${lang}/invite#${INVITE}`);
          await expect(submit(page)).toBeEnabled();
          await submit(page).click();
          await expect(field(page, "code")).toBeFocused();
          await page.keyboard.type("123456");
          await field(page, "password").fill(STRONG_PASSWORD);
          await submit(page).click();
          return {mock, route: "/auth/register"};
        },
      },
      {
        name: "forced password change",
        run: async (page, context, baseURL) => {
          await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
          const mock = await installApiMock(context, {
            me: meFixture({user: {must_reset: true}}),
            handlers: {"POST /account/password": {status: 204}},
          });
          await gotoForm(page, `/${lang}/change-password`);
          await field(page, "new_password").fill(STRONG_PASSWORD);
          await submit(page).click();
          return {mock, route: "/account/password"};
        },
      },
    ];

    for (const leave of LEAVES) {
      test(`wp8-r5-1: ${leave.name}, the form stays pending while the next page loads and sends nothing twice`, async ({page, context, baseURL}) => {
        const {held, release} = await holdProfiles(context);
        try {
          const {mock, route} = await leave.run(page, context, baseURL);
          await expect.poll(() => held.count).toBeGreaterThan(0);
          // The answer is in and the page has not changed.
          await expect(page).not.toHaveURL(/\/profiles/);
          const button = page.locator("form button[data-pending=\"true\"]");
          await expect(button).toHaveCount(1);
          await expect(page.locator("form input:not([type=hidden]):not([data-account-name])").first()).toBeDisabled();
          expect(callsTo(mock, "POST", route)).toHaveLength(1);
          await resubmit(page);
          await page.waitForTimeout(300);
          expect(callsTo(mock, "POST", route)).toHaveLength(1);
        } finally {
          release();
        }
        await page.waitForURL(`**/${lang}/profiles`);
      });
    }

    // wp8-r5-2: Enter in the password field, and a 500. The test of round 4 asked for any field.
    test("wp8-r5-2: a failure with no field of its own gives the focus back to the field it was in", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/login/password": err(500, "internal", {request_id: "req-r5-2"})});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await field(page, "password").press("Enter");
      await expect(formAlert(page)).toHaveCount(1);
      await expect(field(page, "password")).toBeFocused();

      // The other field, too: the visitor was last in the number.
      await field(page, "phone").focus();
      await field(page, "phone").press("Enter");
      await expect(field(page, "phone")).toBeFocused();
    });

    test("wp8-r5-2: Register and Invite give it back to the password field, not the code", async ({page, context}) => {
      await openAnonymous(
        context,
        {"POST /auth/otp/request": issued, "POST /auth/register": err(500, "internal", {request_id: "req-r5-2b"})},
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await field(page, "password").fill(STRONG_PASSWORD);
      await field(page, "password").press("Enter");
      await expect(formAlert(page).filter({hasText: errorText(lang, "internal")})).toHaveCount(1);
      await expect(field(page, "password")).toBeFocused();
    });

    // wp8-r5-3 (D67): the invite field used to show a typed code in groups of four and kept the caret across the regrouping.
    // The invite is now one pasted link, so the field is plain: what is typed stays as typed, and an edit in the middle keeps the caret.
    // The recovery code below is still grouped.
    test("wp8-r5-3: the invite field is not regrouped, and an edit in the middle keeps the caret", async ({page, context}) => {
      await openAnonymous(context, {});
      await gotoForm(page, `/${lang}/invite`);
      const token = field(page, "token");
      await token.focus();
      await token.pressSequentially("abcdefghjkmn");
      await expect(token).toHaveValue("abcdefghjkmn");
      await token.press("Home");
      await token.press("ArrowRight");
      await token.press("ArrowRight");
      await token.press("Backspace");
      await expect(token).toHaveValue("acdefghjkmn");
      expect(await token.evaluate((el: HTMLInputElement) => el.selectionStart)).toBe(1);
      await token.pressSequentially("Z");
      await expect(token).toHaveValue("aZcdefghjkmn");
      expect(await token.evaluate((el: HTMLInputElement) => el.selectionStart)).toBe(2);
    });

    test("wp8-r5-3: the recovery code behaves the same", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp", "recovery_code"]}},
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(PASSWORD);
      await submit(page).click();
      await page.getByRole("button", {name: T("login.twoFactor.useRecovery")}).click();
      const recovery = field(page, "recovery_code");
      await expect(recovery).toBeFocused();
      await recovery.pressSequentially("ABCDEFGHJKMN");
      await recovery.press("Home");
      await recovery.press("ArrowRight");
      await recovery.press("ArrowRight");
      await recovery.press("Backspace");
      await expect(recovery).toHaveValue("ACDE-FGHJ-KMN");
      expect(await recovery.evaluate((el: HTMLInputElement) => el.selectionStart)).toBe(1);
    });

    // wp8-r5-4: the server named a field and the page has none of that name.
    test("wp8-r5-4: a field name no field has is shown as the form's own message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/login/password": {status: 422, body: errorBody("validation_failed", {fields: [{name: "no_such_field", code: "required"}]})},
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await field(page, "password").press("Enter");
      await expect(formAlert(page).filter({hasText: errorText(lang, "validation_failed")})).toHaveCount(1);
      await expect(field(page, "password")).toBeFocused();
    });

    test("wp8-r5-4: a reauth that names `password` is shown under the current password field", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, {
        me: meFixture({user: {must_reset: true}}),
        handlers: {
          "POST /account/password": err(403, "reauth_required"),
          "POST /auth/reauth": {status: 422, body: errorBody("validation_failed", {fields: [{name: "password", code: "too_long"}]})},
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(field(page, "reauth_password")).toBeFocused();
      await field(page, "reauth_password").fill("x".repeat(10));
      await submit(page).click();
      await expect(page.getByText(T("fields.password.tooLong"))).toBeVisible();
      await expect(field(page, "reauth_password")).toHaveAttribute("aria-invalid", "true");
      await expect(field(page, "new_password")).not.toHaveAttribute("aria-invalid", "true");
    });

    // wp8-r5-7: a shown password is a plain text input to the browser, whose form history may keep it.
    test("wp8-r5-7: a shown password is hidden again when the form is sent, and stays hidden after a failure", async ({page, context}) => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      await openAnonymous(context, {
        "POST /auth/login/password": async () => {
          await gate;
          return err(503, "service_unavailable");
        },
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(PASSWORD);
      await page.getByRole("button", {name: T("fields.password.showLabel")}).click();
      await expect(field(page, "password")).toHaveAttribute("type", "text");
      await field(page, "password").press("Enter");
      // The request is still unanswered.
      await expect(field(page, "password")).toHaveAttribute("type", "password");
      release();
      await expect(formAlert(page)).toHaveCount(1);
      await expect(field(page, "password")).toHaveAttribute("type", "password");
      await expect(field(page, "password")).toHaveValue(PASSWORD);
      await expect(page.getByRole("button", {name: T("fields.password.showLabel")})).toBeVisible();
    });

    test("wp8-r5-7: a submit with no submit event (the sixth digit of a code) hides it too", async ({page, context, baseURL}) => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, {
        me: meFixture({user: {must_reset: true}, security: {totp_enabled: true}}),
        handlers: {
          "POST /account/password": async () => {
            await gate;
            return err(503, "service_unavailable");
          },
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: T("fields.password.showLabel")}).click();
      await expect(field(page, "new_password")).toHaveAttribute("type", "text");
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect(field(page, "new_password")).toHaveAttribute("type", "password");
      release();
      await expect(formAlert(page).filter({hasText: errorText(lang, "service_unavailable")})).toHaveCount(1);
      await expect(field(page, "new_password")).toHaveAttribute("type", "password");
    });
  });
}
