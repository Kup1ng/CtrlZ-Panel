import {errorBody, meFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  formAlert,
  gotoForm,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  submit,
  text, STRONG_PASSWORD} from "./auth-support.ts";

// Spec 17.3 `password.spec.ts` (T-100, T-092): the strength meter, and the forced password change of 10.7
// (with the suspended page of 10.8 that shares its way of working: signed in, outside the shell).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const STRONG = STRONG_PASSWORD;
const PHONE = "09123456789";
const OTP_ID = otpChallengeId(21);

for (const {lang, dir} of LANGS) {
  test.describe(`password meter, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    async function openRegisterStep(page: Page, context: BrowserContext, handlers = {}) {
      const mock = await openAnonymous(
        context,
        {"POST /auth/otp/request": {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}}, ...handlers},
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "password")).toBeVisible();
      return mock;
    }

    test("the meter appears with the first character, follows it, and the length hint comes first", async ({page, context}) => {
      await openRegisterStep(page, context);
      await expect(page.getByRole("meter")).toHaveCount(0);
      await field(page, "password").fill("abc");
      await expect(page.getByRole("meter")).toBeVisible();
      await expect(page.getByText(T("strength.short"))).toBeVisible();
      // The scorer loads on the first keystroke; a common password reads as weak or very weak.
      await expect(page.getByTestId("password-meter").locator(".meter__output").getByText(new RegExp(`${T("strength.level0")}|${T("strength.level1")}`))).toBeVisible();

      await field(page, "password").fill(STRONG);
      await expect(page.getByTestId("password-meter").locator(".meter__output").getByText(new RegExp(`${T("strength.level3")}|${T("strength.level4")}`))).toBeVisible();
      await expect(page.getByText(T("strength.advisory"))).toBeVisible();
      await expect(page.getByText(T("strength.short"))).toHaveCount(0);
    });

    test("a long but common password gets the 'try a longer one' hint, and the number it knows is weak", async ({page, context}) => {
      await openRegisterStep(page, context);
      await field(page, "password").fill("passwordpassword");
      await expect(page.getByText(T("strength.weak"))).toBeVisible();
      await field(page, "password").fill(PHONE);
      await expect(page.getByTestId("password-meter").locator(".meter__output").getByText(new RegExp(`${T("strength.level0")}|${T("strength.level1")}`))).toBeVisible();
    });

    // wp8-r24-2: the server refuses a password that holds the last 7 digits of the number (AUTH 4.3 item 3), also with
    // separators between them, so the meter must not call such a password good.
    test("a long random password that holds the last 7 digits of the number reads as the weakest level", async ({page, context}) => {
      await openRegisterStep(page, context);
      const level = page.getByTestId("password-meter").locator(".meter__output");
      await field(page, "password").fill("Tr1cky-Orchid-Lantern-3456789");
      await expect(level.getByText(T("strength.level0"))).toBeVisible();
      await field(page, "password").fill("Tr1cky-Orchid-345-6789-Lantern");
      await expect(level.getByText(T("strength.level0"))).toBeVisible();
      await field(page, "password").fill(STRONG);
      await expect(level.getByText(new RegExp(`${T("strength.level3")}|${T("strength.level4")}`))).toBeVisible();
    });

    test("it is advisory: a weak password is still sent, and nothing leaves while typing", async ({page, context, baseURL}) => {
      const mock = await openRegisterStep(page, context, {"POST /auth/register": signedIn(context, baseURL), "GET /me": meReady()});
      const before = mock.calls.length;
      await field(page, "password").pressSequentially("weakpass1", {delay: 20});
      await expect(page.getByRole("meter")).toBeVisible();
      // No request for any keystroke: the meter runs in the browser.
      expect(mock.calls.length).toBe(before);
      await field(page, "code").focus();
      await page.keyboard.type("123456");
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/register")).toMatchObject({password: "weakpass1"});
    });

    test("the server's reason is shown, whatever the meter said", async ({page, context}) => {
      await openRegisterStep(page, context, {
        "POST /auth/register": {status: 422, body: errorBody("password_weak", {fields: [{name: "password", code: "sequence"}]})},
      });
      await field(page, "password").fill(STRONG);
      await expect(page.getByTestId("password-meter").locator(".meter__output").getByText(new RegExp(`${T("strength.level3")}|${T("strength.level4")}`))).toBeVisible();
      await field(page, "code").focus();
      await page.keyboard.type("123456");
      await submit(page).click();
      await expect(page.getByText(lang === "fa" ? "دنباله" : "simple sequence")).toBeVisible();
    });

    test("too_long, which errors.json has no line for, reads as the page's own", async ({page, context}) => {
      await openRegisterStep(page, context, {
        "POST /auth/register": {status: 422, body: errorBody("password_weak", {fields: [{name: "password", code: "too_long"}]})},
      });
      await field(page, "password").fill(STRONG);
      await field(page, "code").focus();
      await page.keyboard.type("123456");
      await submit(page).click();
      await expect(page.getByText(T("fields.password.tooLong"))).toBeVisible();
    });
  });

  test.describe(`forced password change, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const restricted = (totp = false) => meFixture({user: {must_reset: true}, security: {totp_enabled: totp}});

    async function restrictedSession(page: Page, context: BrowserContext, baseURL: string | undefined, totp = false, handlers = {}) {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      const mock = await installApiMock(context, {
        me: restricted(totp),
        handlers: {
          "POST /account/password": (_c, s) => {
            s.me = {...s.me, user: {...s.me.user, must_reset: false}};
            return {status: 204};
          },
          ...handlers,
        },
      });
      return mock;
    }

    test("the page shows the form and no shell; the password goes to /account/password, then /profiles", async ({page, context, baseURL}) => {
      const mock = await restrictedSession(page, context, baseURL);
      await gotoForm(page, `/${lang}/change-password`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("changePassword.title"));
      await expect(page.locator(".shell-page, .sidebar")).toHaveCount(0);
      await expect(field(page, "new_password")).toBeFocused();
      await expect(field(page, "new_password")).toHaveAttribute("autocomplete", "new-password");
      // A user without an authenticator is not asked for a code.
      await expect(field(page, "totp_code")).toHaveCount(0);
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/account/password")).toEqual({new_password: STRONG});
      // /me is asked again, and the shell finds a ready user.
      await expect(page.locator(".shell-page")).toBeVisible();
      expect(mock.unhandled).toEqual([]);
      await expectNoSecretResidue(page, [STRONG], "the forced password change");
    });

    test("a user with an authenticator also gives the code", async ({page, context, baseURL}) => {
      const mock = await restrictedSession(page, context, baseURL, true);
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByText(T("fields.totp.required"))).toBeVisible();
      expect(callsTo(mock, "POST", "/account/password")).toHaveLength(0);
      await field(page, "totp_code").focus();
      await page.keyboard.type("۱۲۳۴۵۶");
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/account/password")).toEqual({new_password: STRONG, totp_code: "123456"});
      await expectNoSecretResidue(page, [STRONG, "123456", "۱۲۳۴۵۶"], "the forced password change with an authenticator code");
    });

    test("password_weak is under the field with the server's reason; totp_invalid under the code", async ({page, context, baseURL}) => {
      let answer: ReturnType<typeof err> = {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "repeated"}]})};
      await restrictedSession(page, context, baseURL, true, {"POST /account/password": () => answer});
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill("aaaaaaaaaaaaaaa");
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect(page.getByText(lang === "fa" ? "تکرار" : "repeats")).toBeVisible();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");

      answer = err(401, "totp_invalid");
      // The code of the first try is still in the slots, since the server blamed the password and not the code.
      await expect(field(page, "totp_code")).toHaveValue("123456");
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(page.getByRole("alert").filter({hasText: lang === "fa" ? "درست نیست" : "not correct"})).toBeVisible();
      await expect(field(page, "totp_code")).toHaveValue("");
    });

    // wp8-r1-3, r1-12: a restricted session that an SMS code or a passkey opened, or whose one-time password has
    // run out, is refused with reauth_required. The page asks for the current password in place and repeats once.
    const ONE_TIME = "OneTime-pass-1";
    function reauthHandlers(extra: {reauth?: () => ReturnType<typeof err> | {status: number}} = {}) {
      const state = {fresh: false};
      return {
        state,
        handlers: {
          "POST /account/password": (_c: unknown, s: {me: ReturnType<typeof restricted>}) => {
            if (!state.fresh) return err(403, "reauth_required");
            s.me = {...s.me, user: {...s.me.user, must_reset: false}};
            return {status: 204};
          },
          "POST /auth/reauth": () => {
            const answer = extra.reauth?.() ?? {status: 204};
            if (answer.status === 204) state.fresh = true;
            return answer;
          },
        },
      };
    }

    test("reauth_required: the current password is asked for here, then the change is sent again, once", async ({page, context, baseURL}) => {
      const {handlers} = reauthHandlers();
      const mock = await restrictedSession(page, context, baseURL, false, handlers);
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      // No dead end: no generic line, and a field with the focus to answer with.
      await expect(field(page, "reauth_password")).toBeFocused();
      await expect(formAlert(page)).toHaveCount(0);
      await expect(page.getByText(T("changePassword.reauth.text"))).toBeVisible();
      await expect(submit(page)).toHaveText(T("changePassword.reauth.submit"));
      expect(callsTo(mock, "POST", "/auth/reauth")).toHaveLength(0);
      await field(page, "reauth_password").fill(ONE_TIME);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/reauth")).toEqual({password: ONE_TIME});
      expect(callsTo(mock, "POST", "/account/password").map((c) => c.body)).toEqual([{new_password: STRONG}, {new_password: STRONG}]);
    });

    test("reauth_required with an authenticator: the code is used for the reauth, and the change then needs none", async ({page, context, baseURL}) => {
      const {handlers} = reauthHandlers();
      const mock = await restrictedSession(page, context, baseURL, true, handlers);
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG);
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect(field(page, "reauth_password")).toBeFocused();
      await field(page, "reauth_password").fill(ONE_TIME);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/reauth")).toEqual({password: ONE_TIME, totp_code: "123456"});
      expect(callsTo(mock, "POST", "/account/password").map((c) => c.body)).toEqual([
        {new_password: STRONG, totp_code: "123456"},
        {new_password: STRONG},
      ]);
    });

    test("reauth_required: a wrong current password is under its field, clears it, and the change is not sent", async ({page, context, baseURL}) => {
      const {handlers} = reauthHandlers({reauth: () => err(401, "invalid_credentials")});
      const mock = await restrictedSession(page, context, baseURL, false, handlers);
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await field(page, "reauth_password").fill("wrong");
      await submit(page).click();
      await expect(field(page, "reauth_password")).toHaveAttribute("aria-invalid", "true");
      await expect(page.getByText(lang === "fa" ? "درست نیست" : "not correct")).toBeVisible();
      await expect(field(page, "reauth_password")).toHaveValue("");
      await expect(field(page, "reauth_password")).toBeFocused();
      expect(callsTo(mock, "POST", "/account/password")).toHaveLength(1);
    });

    test("reauth_required: a weak new password after the reauth does not ask for the current one again", async ({page, context, baseURL}) => {
      const {state, handlers} = reauthHandlers();
      let weak = true;
      const change = handlers["POST /account/password"];
      const mock = await restrictedSession(page, context, baseURL, false, {
        ...handlers,
        "POST /account/password": (c: never, s: never) => {
          if (state.fresh && weak) return {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "repeated"}]})};
          return change(c, s);
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill("aaaaaaaaaaaaaaa");
      await submit(page).click();
      await field(page, "reauth_password").fill(ONE_TIME);
      await submit(page).click();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");
      // The window is open: the field of the current password is gone and the button says what it did before.
      await expect(field(page, "reauth_password")).toHaveCount(0);
      weak = false;
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(callsTo(mock, "POST", "/auth/reauth")).toHaveLength(1);
    });

    // wp8-r2-5, r2-8: the ten minutes of the window run out while the visitor retries weak passwords. The next
    // change is refused with reauth_required again, and the field of the current password has to come back.
    test("reauth_required after a reauth (the window lapsed): the current password is asked for again, with the focus", async ({page, context, baseURL}) => {
      const {state, handlers} = reauthHandlers();
      let weak = true;
      const change = handlers["POST /account/password"];
      const mock = await restrictedSession(page, context, baseURL, false, {
        ...handlers,
        "POST /account/password": (c: never, s: never) => {
          if (state.fresh && weak) return {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "repeated"}]})};
          return change(c, s);
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill("aaaaaaaaaaaaaaa");
      await submit(page).click();
      await field(page, "reauth_password").fill(ONE_TIME);
      await submit(page).click();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");
      await expect(field(page, "reauth_password")).toHaveCount(0);

      // The window lapses on the server, and the page, which keeps no clock, sends a change that is refused.
      state.fresh = false;
      weak = false;
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(field(page, "reauth_password")).toBeVisible();
      await expect(field(page, "reauth_password")).toBeFocused();
      await expect(formAlert(page)).toHaveCount(0);
      await expect(submit(page)).toHaveText(T("changePassword.reauth.submit"));

      await field(page, "reauth_password").fill(ONE_TIME);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(callsTo(mock, "POST", "/auth/reauth")).toHaveLength(2);
    });

    test("reauth_required after a reauth, with an authenticator: the code field comes back empty with the current password", async ({page, context, baseURL}) => {
      const {state, handlers} = reauthHandlers();
      let weak = true;
      const change = handlers["POST /account/password"];
      const mock = await restrictedSession(page, context, baseURL, true, {
        ...handlers,
        "POST /account/password": (c: never, s: never) => {
          if (state.fresh && weak) return {status: 422, body: errorBody("password_weak", {fields: [{name: "new_password", code: "repeated"}]})};
          return change(c, s);
        },
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill("aaaaaaaaaaaaaaa");
      await field(page, "totp_code").focus();
      await page.keyboard.type("123456");
      await expect(field(page, "reauth_password")).toBeFocused();
      await field(page, "reauth_password").fill(ONE_TIME);
      await submit(page).click();
      await expect(field(page, "new_password")).toHaveAttribute("aria-invalid", "true");
      await expect(field(page, "totp_code")).toHaveCount(0);

      state.fresh = false;
      weak = false;
      await field(page, "new_password").fill(STRONG);
      await submit(page).click();
      await expect(field(page, "reauth_password")).toBeFocused();
      await expect(field(page, "totp_code")).toHaveValue("");
      await field(page, "reauth_password").fill(ONE_TIME);
      await field(page, "totp_code").focus();
      await page.keyboard.type("654321");
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/reauth")).toEqual({password: ONE_TIME, totp_code: "654321"});
    });

    test("Log out ends the session and goes to the login page", async ({page, context, baseURL}) => {
      const mock = await restrictedSession(page, context, baseURL, false, {"POST /auth/logout": {status: 204}});
      await gotoForm(page, `/${lang}/change-password`);
      await page.getByRole("button", {name: T("logout")}).click();
      await page.waitForURL(`**/${lang}/login`);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(1);
    });

    test("a user who has no reason to be here goes on to /profiles", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context);
      await page.goto(`/${lang}/change-password`);
      await page.waitForURL(`**/${lang}/profiles`);
    });

    test("restricted sessions that open the shell are sent here (10.7), and nothing else is asked", async ({page, context, baseURL}) => {
      const mock = await restrictedSession(page, context, baseURL);
      await page.goto(`/${lang}/profiles`);
      await page.waitForURL(`**/${lang}/change-password`);
      expect(mock.calls.map((c) => c.path).filter((p) => p !== "/me")).toEqual([]);
    });
  });

  test.describe(`suspended, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("a suspended tenant sees the explanation and Log out, and nothing of the shell", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      const mock = await installApiMock(context, {me: meFixture({tenant: {status: "suspended"}}), handlers: {"POST /auth/logout": {status: 204}}});
      await page.goto(`/${lang}/profiles`);
      await page.waitForURL(`**/${lang}/suspended`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("suspended.title"));
      await expect(page.getByText(T("suspended.text"))).toBeVisible();
      await expect(page.locator(".shell-page")).toHaveCount(0);
      await page.getByRole("button", {name: T("logout")}).click();
      await page.waitForURL(`**/${lang}/login`);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(1);
    });

    test("a Log out that fails is shown and can be tried again", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, {me: meFixture({tenant: {status: "suspended"}}), handlers: {"POST /auth/logout": err(503, "service_unavailable")}});
      await page.goto(`/${lang}/suspended`);
      await page.getByRole("button", {name: T("logout")}).click();
      await expect(formAlert(page)).toBeVisible();
    });
  });
}
