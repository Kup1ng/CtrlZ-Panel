import type {BrowserContext, Page} from "@playwright/test";
import {adminMeFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import type {MockHandler} from "@ctrlz/api-client/testing/mock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  adm,
  authText,
  allowAdminErrors,
  bodies,
  commonText,
  err,
  errText,
  LANGS,
  loginOk,
  openAdmin,
  STRONG_PASSWORD,
  TOTP_URI,
  typeCode,
  type AdminMock,
} from "./admin-support.ts";

// Spec 17.3 admin-auth.spec.ts (T-323, T-324, T-325, T-326): the login with a TOTP code, the forced setup of a first admin on
// every shell route, the fresh-TOTP dialog with its retry, the end of a session, the user menu (Account, Log out) and the
// 404. All in mock mode (spec 17.1). The flows that need the real API (a real authenticator, the cookie that a password
// change rotates, `__Host-` cookies over HTTPS) are in admin.stack.spec.ts and run after the merge.

test.beforeEach(({guard}) => allowAdminErrors(guard));

const CODE = "123456";
/** The same code as a Persian keypad types it. */
const PERSIAN_CODE = "۱۲۳۴۵۶";

async function fillLogin(page: Page, {user = "admin", password = "Correct-Horse-9", code}: {user?: string; password?: string; code?: string} = {}) {
  await page.locator('input[name="username"]').fill(user);
  await page.locator('input[name="password"]').fill(password);
  if (code) await typeCode(page, "totp_code", code);
}

for (const {lang, dir} of LANGS) {
  test.describe(`admin login, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);
    const submit = (page: Page) => page.getByRole("button", {name: A("login.submit")});

    test("one form with a username, a password and a code field, and nothing else to choose", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false});
      await page.goto(`/${lang}/login`);
      await expect(page.getByRole("heading", {level: 1, name: A("login.title")})).toBeVisible();
      await expect(page.locator('input[name="username"]')).toHaveAttribute("autocomplete", "username");
      await expect(page.locator('input[name="password"]')).toHaveAttribute("autocomplete", "current-password");
      await expect(page.locator('input[name="totp_code"]')).toHaveAttribute("autocomplete", "one-time-code");
      // The code field is always there, with the hint that it stays empty the first time (spec 11.1).
      await expect(page.getByText(A("login.totpHint"))).toBeVisible();
      // No Remember me, no passkey (spec 11.1).
      await expect(page.getByRole("checkbox")).toHaveCount(0);
      await expect(page.getByText("Passkey")).toHaveCount(0);
      await expect(page.locator("html")).toHaveAttribute("dir", dir);
    });

    test("a first sign-in leaves the code empty and the request carries none", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": loginOk("ready")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page);
      await submit(page).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
      expect(bodies(mock, "POST", "/auth/login")).toEqual([{username: "admin", password: "Correct-Horse-9"}]);
    });

    test("a typed code is sent with the credentials, and six digits sent the form by themselves", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": loginOk("ready")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page, {code: CODE});
      await expect.poll(() => bodies(mock, "POST", "/auth/login").length).toBe(1);
      expect(bodies(mock, "POST", "/auth/login")[0]).toEqual({username: "admin", password: "Correct-Horse-9", totp_code: CODE});
    });

    test("a code typed in Persian digits before the credentials is sent as ASCII when the button is pressed (wp10-r3-4)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": loginOk("ready")}});
      await page.goto(`/${lang}/login`);
      // The password comes after the code, so the sixth digit cannot send the form (it has nothing to send yet): the button does.
      // The username is filled first because it proves the page has hydrated; typing into the slots before that loses digits.
      await page.locator('input[name="username"]').fill("admin");
      await typeCode(page, "totp_code", PERSIAN_CODE);
      await expect(page.locator('input[name="totp_code"]')).toHaveValue(PERSIAN_CODE);
      await page.locator('input[name="password"]').fill("Correct-Horse-9");
      expect(mock.count("POST /auth/login")).toBe(0);
      await submit(page).click();
      await expect.poll(() => bodies(mock, "POST", "/auth/login").length).toBe(1);
      expect(bodies(mock, "POST", "/auth/login")[0]).toEqual({username: "admin", password: "Correct-Horse-9", totp_code: CODE});
    });
    // merge-r1-7 and merge-r2-9. The server removes U+200C from a password before it stores or checks it (D64), so the half-space of the Persian
    // keyboard is sent as typed, and a direction mark (U+200F) is still refused under the field. The admin forms carry the same
    // call as the panel's (hasInvisiblePassword); a count of the call in a unit test passes if the call is there and wrong, this does not.
    test("a password with a half-space is sent as typed, and one with a direction mark is refused under its field (merge-r1-7)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": loginOk("ready")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page, {password: "pass\u200fword-1234"});
      await submit(page).click();
      await expect(page.getByText(authText(lang, "fields.password.invisible"))).toBeVisible();
      await expect(page.locator('input[name="password"]')).toHaveAttribute("aria-invalid", "true");
      expect(mock.count("POST /auth/login")).toBe(0);
      const typed = "Correct\u200c-Horse-9";
      await page.locator('input[name="password"]').fill(typed);
      await submit(page).click();
      await expect.poll(() => bodies(mock, "POST", "/auth/login").length).toBe(1);
      expect(bodies(mock, "POST", "/auth/login")[0]).toEqual({username: "admin", password: typed});
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
    });

    test("a wrong password or a wrong code is one neutral message, and both secrets are cleared", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": err(401, "invalid_credentials")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page, {code: CODE});
      await expect(page.getByText(errText(lang, "invalid_credentials"))).toBeVisible();
      await expect(page.locator('input[name="password"]')).toHaveValue("");
      await expect(page.locator('input[name="totp_code"]')).toHaveValue("");
      // The name is kept: it is not a secret and the next try is likely the same person.
      await expect(page.locator('input[name="username"]')).toHaveValue("admin");
      // The page says nothing of which of the three was wrong.
      await expect(page.getByText(errText(lang, "totp_invalid"))).toHaveCount(0);
    });

    test("a server failure keeps what was typed, and Retry sends the same body again (wp10-r5-1)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": err(503, "service_unavailable")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page, {code: CODE});
      await expect(page.getByText(errText(lang, "service_unavailable"))).toBeVisible();
      // A 503 says nothing about the credentials: only an invalid_credentials answer empties the fields.
      await expect(page.locator('input[name="password"]')).toHaveValue("Correct-Horse-9");
      await expect(page.locator('input[name="totp_code"]')).toHaveValue(CODE);
      await expect(page.locator('input[name="username"]')).toHaveValue("admin");
      await page.getByRole("button", {name: commonText(lang, "retry")}).click();
      await expect.poll(() => bodies(mock, "POST", "/auth/login").length).toBe(2);
      const sent = bodies(mock, "POST", "/auth/login");
      expect(sent[1]).toEqual(sent[0]);
      expect(sent[0]).toEqual({username: "admin", password: "Correct-Horse-9", totp_code: CODE});
      // The refusal "password required" is what the old code answered to Retry.
      await expect(page.getByText(authText(lang, "fields.password.required"))).toHaveCount(0);
    });

    test("a 429 keeps what was typed, so the countdown ends on a form that can be sent (wp10-r5-1)", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": err(429, "too_many_attempts", {retry_after_s: 30})}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page);
      await submit(page).click();
      await expect(page.getByRole("button", {name: /(30|۳۰)/})).toBeDisabled();
      await expect(page.locator('input[name="password"]')).toHaveValue("Correct-Horse-9");
    });

    test("a code that was just used says to wait for the next one, under the code field", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": err(401, "totp_step_reused")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page, {code: CODE});
      await expect(page.getByText(errText(lang, "totp_step_reused"))).toBeVisible();
    });

    test("too many attempts shows a countdown on the button and blocks it", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": err(429, "too_many_attempts", {retry_after_s: 30})}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page);
      await submit(page).click();
      // The label turns into the wait, with the figure in the language's digits.
      await expect(page.getByRole("button", {name: /(30|۳۰)/})).toBeDisabled();
    });

    test("a first admin is sent to the setup page", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, me: {must_change_password: true, totp_enrolled: false}, handlers: {"POST /auth/login": loginOk("setup_required")}});
      await page.goto(`/${lang}/login`);
      await fillLogin(page);
      await submit(page).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/setup$`));
    });

    test("a session that ended on its own says so, and a safe next page is kept after login", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": loginOk("ready")}});
      await page.goto(`/${lang}/login?ended=1&next=/audit`);
      await expect(page.getByTestId("session-ended")).toContainText(A("login.ended"));
      await fillLogin(page);
      await submit(page).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/audit$`));
    });

    test("a next page that leaves the site is not followed", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"POST /auth/login": loginOk("ready")}});
      await page.goto(`/${lang}/login?next=//evil.example/x`);
      await fillLogin(page);
      await submit(page).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
    });

    test("a protected page without a session goes to the login with a return path", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false});
      await page.goto(`/${lang}/sms`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/login\\?next=%2Fsms$`));
    });
  });

  test.describe(`admin setup, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);

    /** An account that needs both steps, with the API moving it along as the real one does. */
    async function firstAdmin(context: BrowserContext, baseURL: string | undefined, handlers: Record<string, MockHandler> = {}) {
      const mock: AdminMock = await openAdmin(context, baseURL, {
        me: {must_change_password: true, totp_enrolled: false},
        handlers: {
          "POST /me/password": () => {
            mock.me.current = adminMeFixture({must_change_password: false, totp_enrolled: false});
            return {status: 204};
          },
          "POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}},
          "POST /me/totp/confirm": () => {
            mock.me.current = adminMeFixture();
            return {status: 204};
          },
          ...handlers,
        },
      });
      return mock;
    }

    test("every shell route sends an account in setup to /setup, and the shell does not render", async ({page, context, baseURL}) => {
      await firstAdmin(context, baseURL);
      for (const route of ["/users", "/invites", "/sms", "/settings", "/audit"]) {
        await page.goto(`/${lang}${route}`);
        await expect(page).toHaveURL(new RegExp(`/${lang}/setup$`));
        await expect(page.getByRole("heading", {level: 1, name: A("setup.password.title")})).toBeVisible();
        await expect(page.getByRole("navigation", {name: commonText(lang, "appName")})).toHaveCount(0);
      }
    });

    test("an account that only lacks an authenticator is sent to /setup too, at the authenticator step", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {me: {must_change_password: false, totp_enrolled: false}, handlers: {"POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}}});
      await page.goto(`/${lang}/users`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/setup$`));
      await expect(page.getByRole("heading", {level: 1, name: A("setup.totp.title")})).toBeVisible();
      // Two steps, not three: the password was done.
      await expect(page.getByRole("list", {name: A("setup.stepsLabel")}).getByRole("listitem")).toHaveCount(2);
    });

    // gate-r33-2. The call replaces the one pending secret, and a page that a link from another site opens must not be able to make it with the
    // session's cookie. A page opened on this step, by a reload, a link or the shell's move, asks first.
    test("a page opened on the authenticator step makes no secret until it is asked for (gate-r33-2)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {me: {must_change_password: false, totp_enrolled: false}, handlers: {"POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}}});
      await page.goto(`/${lang}/users`);
      await expect(page.getByRole("heading", {level: 1, name: A("setup.totp.title")})).toBeVisible();
      const show = page.getByTestId("totp-show");
      await expect(show).toBeVisible();
      await expect(page.getByTestId("totp-qr")).toHaveCount(0);
      await page.reload();
      await expect(show).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(0);
      await show.click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(1);
    });

    // gate-r34-9. The server may hold the secret the admin scanned before a reload, and a confirm needs only the code: the field is there, and
    // typing the code confirms it with no new key (a press on Show would replace the key and kill the entry already scanned).
    test("a page opened on the authenticator step confirms the code of a key scanned before, and makes no new one (gate-r34-9)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {
        me: {must_change_password: false, totp_enrolled: false},
        handlers: {"POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}, "POST /me/totp/confirm": {status: 204}},
      });
      await page.goto(`/${lang}/setup`);
      await expect(page.getByTestId("totp-show")).toBeVisible();
      await expect(page.getByTestId("totp-show-note")).toContainText(A("setup.totp.showNote"));
      await typeCode(page, "totp_code", CODE);
      await expect.poll(() => bodies(mock, "POST", "/me/totp/confirm").length).toBe(1);
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(0);
    });

    // gate-r35-8. While the confirm of the key scanned before runs, a press on Show would make a new key beside it and the two would race.
    test("Show a new QR code waits while the confirm of a key scanned before is running (gate-r35-8)", async ({page, context, baseURL}) => {
      let release!: () => void;
      const held = new Promise<void>((resolve) => (release = resolve));
      const mock = await openAdmin(context, baseURL, {
        me: {must_change_password: false, totp_enrolled: false},
        handlers: {
          "POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}},
          "POST /me/totp/confirm": async () => {
            await held;
            return {status: 204};
          },
        },
      });
      await page.goto(`/${lang}/setup`);
      const show = page.getByTestId("totp-show");
      await expect(show).toBeEnabled();
      await typeCode(page, "totp_code", CODE);
      await expect.poll(() => bodies(mock, "POST", "/me/totp/confirm").length).toBe(1);
      await expect(show).toBeDisabled();
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(0);
      release();
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(0);
    });

    // The same page, when the server holds no secret: the refusal turns into a new key, shown with the notice.
    test("a code typed on a page opened on the authenticator step, with no pending key, makes a new one and says so", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {
        me: {must_change_password: false, totp_enrolled: false},
        handlers: {"POST /me/totp/setup": {body: {secret: "JBSWY3DPEHPK3PXP", otpauth_uri: TOTP_URI}}, "POST /me/totp/confirm": err(409, "totp_not_pending") as never},
      });
      await page.goto(`/${lang}/setup`);
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByTestId("totp-restarted")).toContainText(A("setup.totp.restarted"));
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(1);
    });

    test("the password step, the authenticator step and the done step, in that order", async ({page, context, baseURL}) => {
      const mock = await firstAdmin(context, baseURL);
      await page.goto(`/${lang}/setup`);
      await expect(page.getByRole("heading", {level: 1, name: A("setup.password.title")})).toBeVisible();
      // The one-time password lasts 24 hours and the neutral line names the console command (AUTH 10.1).
      await expect(page.getByText("ctrlz-admin reset-password")).toBeVisible();
      await page.locator('input[name="current_password"]').fill("one-time-OTP-secret");
      await page.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: A("setup.password.submit")}).click();

      await expect(page.getByRole("heading", {level: 1, name: A("setup.totp.title")})).toBeVisible();
      expect(bodies(mock, "POST", "/me/password")).toEqual([{current_password: "one-time-OTP-secret", new_password: STRONG_PASSWORD}]);
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      await expect(page.getByTestId("totp-secret")).toContainText("JBSW Y3DP EHPK 3PXP");
      // gate-r31-6: the secret on the screen is the server's one pending secret, and a language switch is a full load that would ask for
      // another. The corner menu keeps the other language off, with the reason, until the step is done.
      await page.getByRole("button", {name: authText(lang, "corner.label")}).click();
      const otherLanguage = page.getByRole("menuitemradio", {name: lang === "fa" ? "English" : "فارسی"});
      await expect(otherLanguage).toHaveAttribute("aria-disabled", "true");
      // gate-r32-5: this step has no way back, so the reason says "finish", not "go back to the first step".
      await expect(otherLanguage).toContainText(authText(lang, "corner.languageHeldSetup"));
      await expect(otherLanguage).not.toContainText(authText(lang, "corner.languageHeld"));
      await page.keyboard.press("Escape");
      // An admin has no recovery codes, and the screen says how the way back works.
      await expect(page.getByText("ctrlz-admin reset-totp")).toBeVisible();
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByRole("heading", {level: 1, name: A("setup.done.title")})).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/confirm")).toEqual([{code: CODE}]);
      // gate-r31-11: neither the secret nor the new password is left in the address, history, storage or console.
      await expectNoSecretResidue(page, ["JBSWY3DPEHPK3PXP", STRONG_PASSWORD, "one-time-OTP-secret"], "the first admin's setup");
      await page.getByRole("link", {name: A("setup.done.go")}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
    });

    test("a code typed in Persian digits on the authenticator step is sent as ASCII (wp10-r3-4)", async ({page, context, baseURL}) => {
      const mock = await firstAdmin(context, baseURL, {});
      await page.goto(`/${lang}/setup`);
      await page.locator('input[name="current_password"]').fill("one-time-OTP-secret");
      await page.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: A("setup.password.submit")}).click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      await typeCode(page, "totp_code", PERSIAN_CODE);
      await expect(page.getByRole("heading", {level: 1, name: A("setup.done.title")})).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/confirm")).toEqual([{code: CODE}]);
    });
    test("a 503 on the authenticator confirm keeps the code, and Retry sends the same one again (wp10-r9-2)", async ({page, context, baseURL}) => {
      let tries = 0;
      const mock = await firstAdmin(context, baseURL, {
        "POST /me/totp/confirm": () => {
          if (++tries === 1) return err(503, "service_unavailable");
          mock.me.current = adminMeFixture();
          return {status: 204};
        },
      });
      await page.goto(`/${lang}/setup`);
      await page.locator('input[name="current_password"]').fill("one-time-OTP-secret");
      await page.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: A("setup.password.submit")}).click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByText(errText(lang, "service_unavailable"))).toBeVisible();
      await expect(page.locator('input[name="totp_code"]')).toHaveValue(CODE);
      await page.getByRole("button", {name: commonText(lang, "retry")}).click();
      await expect(page.getByRole("heading", {level: 1, name: A("setup.done.title")})).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/confirm")).toEqual([{code: CODE}, {code: CODE}]);
      await expect(page.getByText(authText(lang, "fields.totp.required"))).toHaveCount(0);
    });

    test("a wrong one-time password is said on that field, and nothing moves on", async ({page, context, baseURL}) => {
      await firstAdmin(context, baseURL, {"POST /me/password": err(401, "invalid_credentials") as never});
      await page.goto(`/${lang}/setup`);
      await page.locator('input[name="current_password"]').fill("wrong-one");
      await page.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: A("setup.password.submit")}).click();
      await expect(page.getByText(A("setup.password.currentWrong"))).toBeVisible();
      await expect(page.getByRole("heading", {level: 1, name: A("setup.password.title")})).toBeVisible();
    });

    test("a weak new password shows what the API found wrong under the field", async ({page, context, baseURL}) => {
      await firstAdmin(context, baseURL, {"POST /me/password": err(422, "password_weak", {fields: [{name: "new_password", code: "too_short"}]}) as never});
      await page.goto(`/${lang}/setup`);
      await page.locator('input[name="current_password"]').fill("one-time-OTP-secret");
      await page.locator('input[name="new_password"]').fill("short");
      await page.getByRole("button", {name: A("setup.password.submit")}).click();
      await expect(page.getByText(errText(lang, "fields.too_short"))).toBeVisible();
    });

    test("a refused over-long new password reads \"too long\", not the SMS billed-part text (wp10-r18-1)", async ({page, context, baseURL}) => {
      await firstAdmin(context, baseURL, {"POST /me/password": err(422, "password_weak", {fields: [{name: "new_password", code: "too_long"}]}) as never});
      await page.goto(`/${lang}/setup`);
      await page.locator('input[name="current_password"]').fill("one-time-OTP-secret");
      await page.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await page.getByRole("button", {name: A("setup.password.submit")}).click();
      await expect(page.getByText(authText(lang, "fields.password.tooLong"))).toBeVisible();
      await expect(page.getByText(A("fieldErrors.body.too_long"))).toHaveCount(0);
    });

    test("the strength meter holds the admin to 14 characters", async ({page, context, baseURL}) => {
      await firstAdmin(context, baseURL);
      await page.goto(`/${lang}/setup`);
      await page.locator('input[name="new_password"]').fill("Abcdefgh1!xyz");
      await expect(page.getByText(A("password.short"))).toBeVisible();
      await page.locator('input[name="new_password"]').fill("Abcdefgh1!xyzq");
      await expect(page.getByText(A("password.short"))).toHaveCount(0);
    });

    test("a wrong authenticator code is inline, and the secret on screen is kept", async ({page, context, baseURL}) => {
      const mock = await firstAdmin(context, baseURL, {"POST /me/totp/confirm": err(401, "totp_invalid") as never});
      mock.me.current = adminMeFixture({must_change_password: false, totp_enrolled: false});
      await page.goto(`/${lang}/setup`);
      await page.getByTestId("totp-show").click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByText(errText(lang, "totp_invalid"))).toBeVisible();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      expect(bodies(mock, "POST", "/me/totp/setup")).toHaveLength(1);
    });

    test("a pending secret that ran out makes a new one and says so", async ({page, context, baseURL}) => {
      const mock = await firstAdmin(context, baseURL, {"POST /me/totp/confirm": err(409, "totp_not_pending") as never});
      mock.me.current = adminMeFixture({must_change_password: false, totp_enrolled: false});
      await page.goto(`/${lang}/setup`);
      await page.getByTestId("totp-show").click();
      await expect(page.getByTestId("totp-qr")).toBeVisible();
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByTestId("totp-restarted")).toContainText(A("setup.totp.restarted"));
      await expect.poll(() => bodies(mock, "POST", "/me/totp/setup").length).toBe(2);
    });

    test("an account that needs nothing is sent on to /users", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await page.goto(`/${lang}/setup`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
    });

    test("a 401 from the authenticator step's own call ends the session: the login page, with the notice", async ({page, context, baseURL}) => {
      // wp10-r1-7: this call is outside the query caches, so nothing else would notice that the session was over.
      const mock = await firstAdmin(context, baseURL, {"POST /me/totp/setup": err(401, "session_expired") as never});
      mock.me.current = adminMeFixture({must_change_password: false, totp_enrolled: false});
      await page.goto(`/${lang}/setup`);
      await page.getByTestId("totp-show").click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/login\\?(.*&)?ended=1`));
      await expect(page.getByTestId("session-ended")).toContainText(A("login.ended"));
    });

    test("Log out stays available on the setup page", async ({page, context, baseURL}) => {
      const mock = await firstAdmin(context, baseURL);
      await page.goto(`/${lang}/setup`);
      await page.getByRole("button", {name: A("setup.logout")}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/login`));
      expect(mock.count("POST /auth/logout")).toBe(1);
    });
  });

  test.describe(`admin session, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);

    test("a 401 from any admin call ends the session: the login page, with the notice", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: {"GET /users": err(401, "session_expired")}});
      await page.goto(`/${lang}/users`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/login\\?next=%2Fusers&ended=1$`));
      await expect(page.getByTestId("session-ended")).toContainText(A("login.ended"));
    });

    // gate-r33-11, gate-r32-1. Chrome marks a navigation that starts on another site `Sec-Fetch-Site: cross-site`, and the admin cookie is Strict, so it
    // arrives with none. The proxy serves the page and the shell asks `/me` from the page's own origin. A document under `Content-Security-Policy: sandbox` has an
    // opaque origin, so a link in it is such a start, and no second host is needed (the guard of 17.2 refuses every origin but the base URL).
    const fromAnotherSite = async (page: Page, baseURL: string, href: string) => {
      await page.route(`${baseURL}/link-from-elsewhere`, (route) =>
        route.fulfill({status: 200, contentType: "text/html", headers: {"content-security-policy": "sandbox allow-scripts; default-src 'none'; script-src 'nonce-link'; style-src 'nonce-link'"}, body: `<!doctype html><title>link</title><a id="go" href="${href}">go</a>`}),
      );
      await page.goto(`${baseURL}/link-from-elsewhere`);
      await page.click("#go");
    };

    test("a link from another site, with no session: the login page with next and no 'session ended' notice (gate-r33-11)", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {cookie: false, handlers: {"GET /me": err(401, "session_expired")}});
      await fromAnotherSite(page, baseURL!, `${baseURL}/${lang}/users`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/login\\?next=%2Fusers$`));
      await expect(page.getByTestId("session-ended")).toHaveCount(0);
    });

    test("a link from another site, with a live session: the page opens (gate-r32-1)", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await fromAnotherSite(page, baseURL!, `${baseURL}/${lang}/users`);
      await expect(page.getByRole("heading", {level: 1, name: A("pages.users.title")})).toBeVisible();
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
    });

    test("a 403 setup_required from a page call, after the console reset the account, goes to /setup", async ({page, context, baseURL}) => {
      const mock: AdminMock = await openAdmin(context, baseURL, {
        handlers: {
          "GET /users": () => {
            // The console reset the password between the shell's `/me` and this call.
            mock.me.current = adminMeFixture({must_change_password: true, totp_enrolled: true});
            return err(403, "setup_required");
          },
        },
      });
      await page.goto(`/${lang}/users`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/setup$`));
      await expect(page.getByRole("heading", {level: 1, name: A("setup.password.title")})).toBeVisible();
    });

    test("the user menu names the admin, offers Account and Log out, and Log out asks first", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL);
      await page.goto(`/${lang}/users`);
      const menu = page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first();
      await expect(menu).toBeVisible();
      await menu.click();
      await expect(page.getByRole("menuitem", {name: A("userMenu.account")})).toBeVisible();
      await page.getByRole("menuitem", {name: A("userMenu.logout")}).click();
      // A confirmation, and no call yet.
      const dialog = page.getByRole("alertdialog");
      await expect(dialog).toBeVisible();
      expect(mock.count("POST /auth/logout")).toBe(0);
      await dialog.getByRole("button", {name: lang === "fa" ? "خروج" : "Log out"}).click();
      await expect(page).toHaveURL(new RegExp(`/${lang}/login`));
      expect(mock.count("POST /auth/logout")).toBe(1);
    });

    test("Account changes the password with the current one, a strong new one and the authenticator code", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: {"POST /me/password": {status: 204}}});
      await page.goto(`/${lang}/users`);
      await page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: A("userMenu.account")}).click();
      const dialog = page.getByRole("dialog", {name: A("account.title")});
      await expect(dialog).toBeVisible();
      // State-only: nothing of it is in the address.
      expect(new URL(page.url()).search).toBe("");
      await dialog.locator('input[name="current_password"]').fill("Old-Password-1234!");
      await dialog.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await typeCode(page, "totp_code", CODE);
      await expect.poll(() => bodies(mock, "POST", "/me/password").length).toBe(1);
      expect(bodies(mock, "POST", "/me/password")[0]).toEqual({current_password: "Old-Password-1234!", new_password: STRONG_PASSWORD, totp_code: CODE});
      await expect(dialog).toHaveCount(0);
    });

    test("Account sends a new password with a half-space as typed, and refuses a direction mark (merge-r1-7, merge-r2-9)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: {"POST /me/password": {status: 204}}});
      await page.goto(`/${lang}/users`);
      await page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: A("userMenu.account")}).click();
      const dialog = page.getByRole("dialog", {name: A("account.title")});
      await expect(dialog).toBeVisible();
      await dialog.locator('input[name="current_password"]').fill("Old-Password-1234!");
      await dialog.locator('input[name="new_password"]').fill("pass\u200fword-Strong-1234!");
      await typeCode(page, "totp_code", CODE);
      await expect(dialog.getByText(authText(lang, "fields.password.invisible"))).toBeVisible();
      expect(mock.count("POST /me/password")).toBe(0);
      const typed = `${STRONG_PASSWORD.slice(0, 4)}\u200c${STRONG_PASSWORD.slice(4)}`;
      await dialog.locator('input[name="new_password"]').fill(typed);
      await dialog.getByRole("button", {name: A("account.submit")}).click();
      await expect.poll(() => bodies(mock, "POST", "/me/password").length).toBe(1);
      expect(bodies(mock, "POST", "/me/password")[0]).toEqual({current_password: "Old-Password-1234!", new_password: typed, totp_code: CODE});
    });

    test("Account: a refused over-long new password reads \"too long\", not the SMS billed-part text (wp10-r18-1)", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: {"POST /me/password": err(422, "password_weak", {fields: [{name: "new_password", code: "too_long"}]}) as never}});
      await page.goto(`/${lang}/users`);
      await page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: A("userMenu.account")}).click();
      const dialog = page.getByRole("dialog", {name: A("account.title")});
      await dialog.locator('input[name="current_password"]').fill("Old-Password-1234!");
      await dialog.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await typeCode(page, "totp_code", CODE);
      await expect(dialog.getByText(authText(lang, "fields.password.tooLong"))).toBeVisible();
      await expect(dialog.getByText(A("fieldErrors.body.too_long"))).toHaveCount(0);
    });

    test("Account sends a code typed in Persian digits first as ASCII when the button is pressed (wp10-r3-4)", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: {"POST /me/password": {status: 204}}});
      await page.goto(`/${lang}/users`);
      await page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: A("userMenu.account")}).click();
      const dialog = page.getByRole("dialog", {name: A("account.title")});
      await typeCode(page, "totp_code", PERSIAN_CODE);
      await dialog.locator('input[name="current_password"]').fill("Old-Password-1234!");
      await dialog.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      expect(mock.count("POST /me/password")).toBe(0);
      await dialog.getByRole("button", {name: A("account.submit")}).click();
      await expect.poll(() => bodies(mock, "POST", "/me/password").length).toBe(1);
      expect(bodies(mock, "POST", "/me/password")[0]).toEqual({current_password: "Old-Password-1234!", new_password: STRONG_PASSWORD, totp_code: CODE});
    });
    test("Account answers a wrong password or code with one neutral message and clears the secrets", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL, {handlers: {"POST /me/password": err(401, "invalid_credentials")}});
      await page.goto(`/${lang}/users`);
      await page.getByRole("button", {name: A("userMenu.label", {name: "admin"})}).first().click();
      await page.getByRole("menuitem", {name: A("userMenu.account")}).click();
      const dialog = page.getByRole("dialog", {name: A("account.title")});
      await dialog.locator('input[name="current_password"]').fill("Old-Password-1234!");
      await dialog.locator('input[name="new_password"]').fill(STRONG_PASSWORD);
      await typeCode(page, "totp_code", CODE);
      await expect(dialog.getByText(errText(lang, "invalid_credentials"))).toBeVisible();
      await expect(dialog.locator('input[name="current_password"]')).toHaveValue("");
      await expect(dialog.getByText(errText(lang, "totp_invalid"))).toHaveCount(0);
    });

    test("an unknown path is the admin 404, inside the shell with a session and with the right status", async ({page, context, baseURL, guard}) => {
      // The browser logs the 404 of the document itself as a failed resource.
      guard.allowConsole(/status of 404/);
      await openAdmin(context, baseURL);
      const response = await page.goto(`/${lang}/nothing-here`);
      expect(response?.status()).toBe(404);
      await expect(page.getByRole("heading", {name: lang === "fa" ? "صفحه پیدا نشد" : "Page not found"})).toBeVisible();
      await expect(page.locator("aside.sidebar")).toBeVisible();
    });

    test("the root of a language goes to Users", async ({page, context, baseURL}) => {
      await openAdmin(context, baseURL);
      await page.goto(`/${lang}`);
      await expect(page).toHaveURL(new RegExp(`/${lang}/users$`));
    });
  });
}

// The fresh-TOTP dialog (11.3, T-326) is driven from the Settings page, whose registration write is `admin-fresh`.
for (const {lang, dir} of LANGS) {
  test.describe(`fresh TOTP, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const A = (path: string, values?: Record<string, string | number>) => adm(lang, path, values);

    const settings = {
      "GET /settings/registration": {body: {mode: "invite", open_grace_days: 0, takeover_idle_days: 30}},
      "GET /settings/webauthn": {body: {rp_id: "panel.example.ir", allowed_origins: ["https://panel.example.ir"], enabled: false}},
      "GET /settings/registration/impact": {body: {graced: 3, suspended_at_once: 1}},
    } as const;

    async function requestChange(page: Page) {
      await page.goto(`/${lang}/settings`);
      await page.getByRole("radio", {name: A("settings.registration.mode.closed")}).click();
      await expect(page.getByTestId("registration-impact")).toBeVisible();
      await page.getByRole("button", {name: A("settings.registration.confirm", {mode: A("settings.registration.mode.closed")})}).click();
    }

    test("a write that needs a fresh code opens the dialog, and the call is repeated once after it", async ({page, context, baseURL}) => {
      let attempts = 0;
      const mock = await openAdmin(context, baseURL, {
        handlers: {
          ...settings,
          "PUT /settings/registration": () => {
            attempts += 1;
            return attempts === 1 ? err(403, "totp_fresh_required") : {body: {mode: "closed", open_grace_days: 0, takeover_idle_days: 30}};
          },
          "POST /auth/totp/fresh": () => ({body: {fresh_until: new Date(Date.now() + 5 * 60_000).toISOString()}}),
        },
      });
      await requestChange(page);
      const dialog = page.getByRole("dialog", {name: A("fresh.title")});
      await expect(dialog).toBeVisible();
      // State-only, and it asks for the code with the explanation.
      expect(new URL(page.url()).search).toBe("");
      await expect(dialog.getByText(A("fresh.text"))).toBeVisible();
      await typeCode(page, "totp_code", CODE);
      await expect(dialog).toHaveCount(0);
      expect(bodies(mock, "POST", "/auth/totp/fresh")).toEqual([{code: CODE}]);
      expect(bodies(mock, "PUT", "/settings/registration")).toEqual([{mode: "closed"}, {mode: "closed"}]);
      // The window is open: the indicator of the user menu says until when.
      await expect(page.getByText(A("userMenu.freshUntil", {time: ""}).trim(), {exact: false})).toBeVisible();
    });

    test("the fresh-TOTP dialog sends a code typed in Persian digits as ASCII (wp10-r3-4)", async ({page, context, baseURL}) => {
      let attempts = 0;
      const mock = await openAdmin(context, baseURL, {
        handlers: {
          ...settings,
          "PUT /settings/registration": () => (++attempts === 1 ? err(403, "totp_fresh_required") : {body: {mode: "closed", open_grace_days: 0, takeover_idle_days: 30}}),
          "POST /auth/totp/fresh": {body: {fresh_until: "2099-01-01T00:00:00Z"}},
        },
      });
      await requestChange(page);
      await typeCode(page, "totp_code", PERSIAN_CODE);
      await expect.poll(() => bodies(mock, "POST", "/auth/totp/fresh").length).toBe(1);
      expect(bodies(mock, "POST", "/auth/totp/fresh")).toEqual([{code: CODE}]);
    });
    // wp10-r9-2. Only a refused code is emptied: a 503 says nothing about the code, and Retry has to be able to resend it.
    test("a 503 on the fresh code keeps the code, and Retry sends the same one again (wp10-r9-2)", async ({page, context, baseURL}) => {
      let tries = 0;
      const mock = await openAdmin(context, baseURL, {
        handlers: {
          ...settings,
          "PUT /settings/registration": () => (mock.count("POST /auth/totp/fresh") === 0 ? err(403, "totp_fresh_required") : {body: {mode: "closed", open_grace_days: 0, takeover_idle_days: 30}}),
          "POST /auth/totp/fresh": () => (++tries === 1 ? err(503, "service_unavailable") : {body: {fresh_until: "2099-01-01T00:00:00Z"}}),
        },
      });
      await requestChange(page);
      const dialog = page.getByRole("dialog", {name: A("fresh.title")});
      await typeCode(page, "totp_code", CODE);
      await expect(dialog.getByText(errText(lang, "service_unavailable"))).toBeVisible();
      await expect(dialog.locator('input[name="totp_code"]')).toHaveValue(CODE);
      await dialog.getByRole("button", {name: commonText(lang, "retry")}).click();
      await expect(dialog).toHaveCount(0);
      expect(bodies(mock, "POST", "/auth/totp/fresh")).toEqual([{code: CODE}, {code: CODE}]);
      // The "six digits" refusal is what the old code answered to Retry.
      await expect(page.getByText(authText(lang, "fields.totp.required"))).toHaveCount(0);
    });

    test("a code that was just used says to wait, and the dialog stays for the next one", async ({page, context, baseURL}) => {
      let tries = 0;
      const mock = await openAdmin(context, baseURL, {
        handlers: {
          ...settings,
          "PUT /settings/registration": () => (mock.count("POST /auth/totp/fresh") === 0 ? err(403, "totp_fresh_required") : {body: {mode: "closed", open_grace_days: 0, takeover_idle_days: 30}}),
          "POST /auth/totp/fresh": () => {
            tries += 1;
            return tries === 1 ? err(401, "totp_step_reused") : {body: {fresh_until: new Date(Date.now() + 5 * 60_000).toISOString()}};
          },
        },
      });
      await requestChange(page);
      const dialog = page.getByRole("dialog", {name: A("fresh.title")});
      await typeCode(page, "totp_code", CODE);
      await expect(dialog.getByText(errText(lang, "totp_step_reused"))).toBeVisible();
      await expect(dialog.locator('input[name="totp_code"]')).toHaveValue("");
      await typeCode(page, "totp_code", "654321");
      await expect(dialog).toHaveCount(0);
      expect(bodies(mock, "POST", "/auth/totp/fresh")).toEqual([{code: CODE}, {code: "654321"}]);
    });

    test("giving up leaves the change unmade and says why under the form", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {handlers: {...settings, "PUT /settings/registration": err(403, "totp_fresh_required")}});
      await requestChange(page);
      const dialog = page.getByRole("dialog", {name: A("fresh.title")});
      await dialog.getByRole("button", {name: commonText(lang, "cancel")}).click();
      await expect(dialog).toHaveCount(0);
      await expect(page.getByText(errText(lang, "totp_fresh_required"))).toBeVisible();
      expect(bodies(mock, "PUT", "/settings/registration")).toHaveLength(1);
    });

    test("a repeat that is refused again is shown and never asks for the same proof twice", async ({page, context, baseURL}) => {
      const mock = await openAdmin(context, baseURL, {
        handlers: {
          ...settings,
          "PUT /settings/registration": err(403, "totp_fresh_required"),
          "POST /auth/totp/fresh": () => ({body: {fresh_until: new Date(Date.now() + 5 * 60_000).toISOString()}}),
        },
      });
      await requestChange(page);
      await typeCode(page, "totp_code", CODE);
      await expect(page.getByText(errText(lang, "totp_fresh_required"))).toBeVisible();
      expect(mock.count("POST /auth/totp/fresh")).toBe(1);
      expect(bodies(mock, "PUT", "/settings/registration")).toHaveLength(2);
    });
  });
}
