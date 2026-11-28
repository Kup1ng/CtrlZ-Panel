import {meFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {INVITE_TOKEN, allowAuthErrors, field, gotoForm, inviteInfoFixture, LANGS, openAnonymous, submit, typeWhenFocused} from "./auth-support.ts";

// Spec 17.3 `no-email.spec.ts` (T-111), the auth screens' part: the product has no email address anywhere,
// so no screen asks for one, names one, or invites a browser to fill one in. It reads the visible text, the
// input types and the autocomplete values of every screen of 10, in both languages. The lint rule and the
// message test cover the source; this is what a visitor sees. The other screens add their own cases.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const issued = {status: 202, body: {challenge_id: otpChallengeId(19), expires_in_s: 300, resend_after_s: 60}};
const EMAIL_WORDS = /e-?mail|ایمیل|ای‌میل|پست الکترونیک|@/i;

async function expectNoEmail(page: Page, where: string) {
  const seen = await page.evaluate(() => {
    const controls = [...document.querySelectorAll("input, textarea, select")].map((el) => ({
      type: el.getAttribute("type") ?? "",
      name: el.getAttribute("name") ?? "",
      autocomplete: el.getAttribute("autocomplete") ?? "",
      inputmode: el.getAttribute("inputmode") ?? "",
      placeholder: el.getAttribute("placeholder") ?? "",
      label: el.getAttribute("aria-label") ?? "",
      accountName: el.hasAttribute("data-account-name"),
      value: (el as HTMLInputElement).value ?? "",
    }));
    return {text: document.body.innerText, title: document.title, controls};
  });
  expect(seen.text, `${where}: visible text`).not.toMatch(EMAIL_WORDS);
  expect(seen.title, `${where}: title`).not.toMatch(EMAIL_WORDS);
  for (const c of seen.controls) {
    expect(c.type, `${where}: input type`).not.toBe("email");
    expect(c.autocomplete, `${where}: autocomplete`).not.toMatch(/email/);
    // `username` is how a password manager names the account, and here the account is the phone (wp8-r17-5). It is
    // allowed only on a control that carries the number: the sign-in phone input (type tel), or the hidden account-name
    // field whose value is the typed digits. Anywhere else it would invite a browser to fill in an email address.
    if (/username/.test(c.autocomplete)) {
      const carriesPhone = c.type === "tel" || (c.accountName && /^[\p{Nd}+]+$/u.test(c.value));
      expect(carriesPhone, `${where}: autocomplete username only on a control that carries the phone`).toBe(true);
    }
    expect(c.inputmode, `${where}: inputmode`).not.toBe("email");
    expect(`${c.name} ${c.placeholder} ${c.label}`, `${where}: name, placeholder and label`).not.toMatch(EMAIL_WORDS);
  }
}

for (const {lang} of LANGS) {
  test.describe(`no email on the auth screens, ${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("login: password, SMS tab and the steps after", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/password": {body: {status: "mfa_required", ticket: "t", methods: ["totp", "recovery_code"]}},
      }, {passkey_enabled: true, registration_mode: "open"});
      await gotoForm(page, `/${lang}/login`);
      await expectNoEmail(page, "login password");
      // The phone is the account's name: a phone input, telephone keyboard, telephone autofill.
      await expect(field(page, "phone")).toHaveAttribute("type", "tel");
      // On the password sign-in the phone is the account name for the password manager (wp8-r17-5).
      await expect(field(page, "phone")).toHaveAttribute("autocomplete", "username");
      await expect(field(page, "password")).toHaveAttribute("autocomplete", "current-password");

      await page.getByRole("tab").nth(1).click();
      await expectNoEmail(page, "login sms");
      // The SMS number is not a saved credential: it stays a telephone field.
      await expect(field(page, "phone")).toHaveAttribute("autocomplete", "tel");
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "code")).toBeVisible();
      await expectNoEmail(page, "login code");

      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill("x");
      await submit(page).click();
      await expect(field(page, "totp_code")).toBeVisible();
      await expectNoEmail(page, "login 2fa");
      await page.getByRole("button").filter({hasText: lang === "fa" ? "کد بازیابی" : "recovery"}).click();
      await expectNoEmail(page, "login recovery");
    });

    test("register, invite, forgot password", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/invites/lookup": {body: inviteInfoFixture()},
        "POST /auth/password/reset/verify": {body: {ticket: "t", second_factor: "totp"}},
      }, {registration_mode: "open"});

      await gotoForm(page, `/${lang}/register`);
      await expectNoEmail(page, "register phone");
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "password")).toBeVisible();
      await expectNoEmail(page, "register confirm");

      await gotoForm(page, `/${lang}/invite`);
      await expectNoEmail(page, "invite code");
      await page.goto(`/${lang}/invite#${INVITE_TOKEN}`);
      await expect(page.locator("bdi", {hasText: "+98912***4567"})).toBeVisible();
      await expectNoEmail(page, "invite lookup");

      await gotoForm(page, `/${lang}/forgot-password`);
      await expectNoEmail(page, "forgot phone");
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await expect(field(page, "new_password")).toBeVisible();
      await expectNoEmail(page, "forgot new password");
    });

    test("change password and suspended", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      const mock = await installApiMock(context, {me: meFixture({user: {must_reset: true}, security: {totp_enabled: true}})});
      await gotoForm(page, `/${lang}/change-password`);
      await expectNoEmail(page, "change password");
      mock.state.me = meFixture({tenant: {status: "suspended"}});
      await page.goto(`/${lang}/suspended`);
      await expect(page.getByRole("heading", {level: 1})).toBeVisible();
      await expectNoEmail(page, "suspended");
    });
  });
}
