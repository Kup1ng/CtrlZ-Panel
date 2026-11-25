import {errorBody, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
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
  text, STRONG_PASSWORD, typeWhenFocused} from "./auth-support.ts";

// Spec 17.3 `register.spec.ts` (T-095, T-098), in mock mode: the tables of 10.4.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const OTP_ID = otpChallengeId(22);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
const OPEN = {registration_mode: "open"} as const;

for (const {lang, dir} of LANGS) {
  test.describe(`register, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("a closed registration shows the closed state with a login link and no form", async ({page, context}) => {
      await openAnonymous(context, {}, {registration_mode: "closed"});
      await page.goto(`/${lang}/register`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.closedTitle"));
      await expect(page.getByRole("link", {name: T("register.signIn")})).toHaveAttribute("href", `/${lang}/login`);
      await expect(page.getByRole("link", {name: T("login.invite")})).toHaveCount(0);
      await expect(page.locator("form")).toHaveCount(0);
    });

    test("invite mode closes it too, and adds the link to the invite page", async ({page, context}) => {
      await openAnonymous(context, {}, {registration_mode: "invite"});
      await page.goto(`/${lang}/register`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.closedTitle"));
      await expect(page.getByRole("link", {name: T("login.invite")})).toHaveAttribute("href", `/${lang}/invite`);
    });

    test("sms_available = false blocks registration with a notice, since it cannot complete", async ({page, context}) => {
      await openAnonymous(context, {}, {...OPEN, sms_available: false});
      await page.goto(`/${lang}/register`);
      await expect(page.getByText(T("register.smsDown"))).toBeVisible();
      await expect(page.locator("form")).toHaveCount(0);
    });

    test("/auth/config fails: the page cannot tell, says so and Retry asks again", async ({page, context, guard}) => {
      guard.allowConsole(/status of 5\d\d/);
      let up = false;
      const mock = await openAnonymous(context, {"GET /auth/config": () => (up ? {body: {registration_mode: "open", sms_available: true, passkey_enabled: false}} : err(503, "service_unavailable"))});
      await page.goto(`/${lang}/register`);
      await expect(formAlert(page)).toBeVisible();
      up = true;
      await formAlert(page).getByRole("button").click();
      await expect(field(page, "phone")).toBeVisible();
      expect(callsTo(mock, "GET", "/auth/config").length).toBeGreaterThanOrEqual(2);
    });

    test("step 1 asks for a signup code with the page language, step 2 shows the form", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued}, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await expect(field(page, "phone")).toBeFocused();
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      expect(lastBody(mock, "POST", "/auth/otp/request")).toEqual({purpose: "signup", phone: PHONE, locale: lang});
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.confirmTitle"));
      await expect(field(page, "code")).toBeFocused();
      await expect(field(page, "code")).toHaveAttribute("autocomplete", "one-time-code");
      await expect(field(page, "password")).toHaveAttribute("autocomplete", "new-password");
      // The wording does not say the number has an account or not.
      await expect(page.getByText(T("register.confirmDescriptionGeneric"))).toBeVisible();
    });

    test("with no password the warning is shown, and the body has no password", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/register": signedIn(context, baseURL, {status: "authenticated"}),
        "GET /me": meReady(),
      }, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(page.getByText(T("register.noPassword"))).toBeVisible();
      // Persian digits typed in the code field are sent as ASCII.
      await page.keyboard.type("۱۲۳۴۵۶");
      await expect(field(page, "code")).toHaveValue("۱۲۳۴۵۶");
      // Completing the code is not a submit here: the password is the other field, and the focus moves on.
      await expect(field(page, "password")).toBeFocused();
      expect(callsTo(mock, "POST", "/auth/register")).toHaveLength(0);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/register")).toEqual({phone: PHONE, challenge_id: OTP_ID, code: "123456", locale: lang});
    });

    test("with a password the warning goes, the meter shows, and the password is sent", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/register": signedIn(context, baseURL),
        "GET /me": meReady(),
      }, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "password").fill(STRONG_PASSWORD);
      await expect(page.getByText(T("register.noPassword"))).toHaveCount(0);
      await expect(page.getByRole("meter")).toBeVisible();
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/register")).toEqual({
        phone: PHONE,
        challenge_id: OTP_ID,
        code: "123456",
        password: STRONG_PASSWORD,
        locale: lang,
      });
      await expectNoSecretResidue(page, [STRONG_PASSWORD, "123456", OTP_ID], "registering");
    });

    test("password_weak shows the reason under the password and keeps the code", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/register": {status: 422, body: errorBody("password_weak", {fields: [{name: "password", code: "too_common"}]})},
      }, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "password").fill("password1234");
      await submit(page).click();
      await expect(page.getByText(lang === "fa" ? "رایج" : "too common")).toBeVisible();
      await expect(field(page, "password")).toHaveAttribute("aria-invalid", "true");
      await expect(field(page, "password")).toBeFocused();
      // The code is still there (AUTH 5.6 checks the password first, so the code was not spent).
      await expect(field(page, "code")).toHaveValue("123456");
      expect(callsTo(mock, "POST", "/auth/register")).toHaveLength(1);
      // Editing the password removes the reason.
      await field(page, "password").fill("password12345");
      await expect(page.getByText(lang === "fa" ? "رایج" : "too common")).toHaveCount(0);
    });

    test("otp_invalid is under the code and clears it; otp_expired goes back to the number", async ({page, context}) => {
      let answer = "otp_invalid";
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/register": () => err(401, answer),
      }, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await submit(page).click();
      await expect(field(page, "code")).toHaveValue("");
      await expect(field(page, "code")).toBeFocused();
      await expect(page.getByRole("alert").filter({hasText: lang === "fa" ? "درست نیست" : "not correct"})).toBeVisible();

      answer = "otp_expired";
      await page.keyboard.type("654321");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.title"));
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await expect(formAlert(page)).toContainText(lang === "fa" ? "منقضی" : "expired");
    });

    // wp8-r7-1: spec 10.4 handles otp_locked as login does: back to the number, with the wait in the message.
    test("otp_locked goes back to the number with the wait in the message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/register": err(429, "otp_locked", {retry_after_s: 300}),
      }, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.title"));
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await expect(formAlert(page)).toContainText(/300|۳۰۰/);
      await expect(field(page, "code")).toHaveCount(0);
    });

    test("registration_closed while submitting ends in the closed state", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued, "POST /auth/register": err(403, "registration_closed")}, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.closedTitle"));
    });

    test("invalid_phone is under the number; otp_limited makes the button wait", async ({page, context}) => {
      let answer: ReturnType<typeof err> = err(422, "invalid_phone");
      await openAnonymous(context, {"POST /auth/otp/request": () => answer}, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill("12");
      await submit(page).click();
      await expect(field(page, "phone")).toHaveAttribute("aria-invalid", "true");
      answer = err(429, "otp_limited", {retry_after_s: 45});
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(submit(page)).toBeDisabled();
      await expect(submit(page)).toContainText(/45|44|۴۵|۴۴/);
    });

    test("Use a different number goes back with the number kept", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued}, OPEN);
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await page.getByRole("button", {name: T("register.change")}).click();
      await expect(field(page, "phone")).toHaveValue(PHONE);
    });
  });
}
