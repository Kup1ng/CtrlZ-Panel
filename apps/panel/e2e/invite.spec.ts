import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  formAlert,
  gotoForm,
  inviteInfoFixture,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  submit,
  text, STRONG_PASSWORD} from "./auth-support.ts";

// Spec 17.3 `invite.spec.ts` (T-095, T-330), in mock mode: the tables of 10.5. The fragment of the link is
// removed from the address bar at once and goes nowhere: it is read by the page and sent only in the body
// of the lookup.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const CODE = "ABCDEFGHJKMNPQRSTVWX";
const GROUPED = "ABCD-EFGH-JKMN-PQRS-TVWX";
const OTP_ID = otpChallengeId(17);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
const lookup = {body: inviteInfoFixture()};

for (const {lang, dir} of LANGS) {
  test.describe(`invite, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("the fragment is read and removed from the address bar, and the code is looked up in a POST body", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await page.goto(`/${lang}/invite#${GROUPED.toLowerCase()}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(new URL(page.url()).hash).toBe("");
      expect(page.url()).not.toContain(CODE.slice(0, 4).toLowerCase());
      // Canonical: upper case, no hyphens. And it is not in any URL the page asked for.
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
      for (const call of mock.calls) expect(call.path + call.query.toString()).not.toContain(CODE);
      // History holds no entry with the fragment either.
      expect(await page.evaluate(() => location.href)).not.toContain("#");
    });

    test("the lookup shows the masked number and the expiry in <Tech>, and Send code asks for an invite OTP", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup, "POST /auth/otp/request": issued});
      await page.goto(`/${lang}/invite#${CODE}`);
      const phone = page.locator("bdi", {hasText: "+98912***4567"});
      await expect(phone).toBeVisible();
      await expect(phone).toHaveAttribute("dir", "ltr");
      await submit(page).click();
      expect(lastBody(mock, "POST", "/auth/otp/request")).toEqual({purpose: "invite", invite_token: CODE, locale: lang});
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.confirmTitle"));
    });

    test("the whole flow: OTP, password, account created, then /profiles", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/invites/lookup": lookup,
        "POST /auth/otp/request": issued,
        "POST /auth/register": signedIn(context, baseURL),
        "GET /me": meReady(),
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("۱۲۳۴۵۶");
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/register")).toEqual({
        invite_token: CODE,
        challenge_id: OTP_ID,
        code: "123456",
        password: STRONG_PASSWORD,
        locale: lang,
      });
      await expectNoSecretResidue(page, [CODE, STRONG_PASSWORD, "123456", "۱۲۳۴۵۶", OTP_ID], "accepting an invite", {arrivedWith: [CODE]});
    });

    test("no fragment: a typed code is shown in groups, upper case, and sent canonical", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      const input = field(page, "token");
      await expect(input).toBeFocused();
      await input.pressSequentially("abcd efghjk-mnpqrstvwx");
      await expect(input).toHaveValue(GROUPED);
      expect(await input.evaluate((el) => el.closest("[dir]")?.getAttribute("dir") ?? (el as HTMLElement).dir)).toBe("ltr");
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
      // The code is not in the address bar after the lookup either.
      expect(page.url()).not.toContain(CODE);
    });

    test("a short code is a field error before any request", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      await field(page, "token").fill("ABCD");
      await submit(page).click();
      await expect(page.getByText(T("fields.inviteCode.required"))).toBeVisible();
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(0);
    });

    test("invite_invalid is one state with no detail, from a link and from a typed code", async ({page, context, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context, {"POST /auth/invites/lookup": err(404, "invite_invalid")}, {});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
      await expect(page.getByText(T("invite.invalidText"))).toBeVisible();
      await page.getByRole("button", {name: T("invite.another")}).click();
      await field(page, "token").fill(GROUPED);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
    });

    test("too_many_attempts on the lookup waits, with the code kept", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": err(429, "too_many_attempts", {retry_after_s: 40})});
      await gotoForm(page, `/${lang}/invite`);
      await field(page, "token").fill(GROUPED);
      await submit(page).click();
      await expect(formAlert(page)).toBeVisible();
      await expect(submit(page)).toBeDisabled();
      await expect(field(page, "token")).toHaveValue(GROUPED);
    });

    test("a link whose lookup is refused with a wait falls back to the typed field, with the code in it", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": err(429, "too_many_attempts", {retry_after_s: 40})});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(field(page, "token")).toHaveValue(GROUPED);
      await expect(formAlert(page)).toBeVisible();
      // wp8-r2-4: the wait of the 429 is on the button, as it is for a typed code, so a press cannot send another lookup.
      await expect(submit(page)).toBeDisabled();
      await expect(submit(page)).not.toHaveText(T("invite.submit"));
    });

    test("sms_available = false: step 2 says SMS is down and to ask the admin, and Send is off", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": lookup}, {sms_available: false});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByText(T("invite.smsDown"))).toBeVisible();
      await expect(submit(page)).toBeDisabled();
    });

    // wp8-r7-1: otp_locked on the invite's code returns to the invite step with the wait in the message.
    test("otp_locked returns to the invite step with the wait in the message", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/invites/lookup": lookup,
        "POST /auth/otp/request": issued,
        "POST /auth/register": err(429, "otp_locked", {retry_after_s: 300}),
      });
      await page.goto(`/${lang}/invite#${CODE}`);
      await submit(page).click();
      await expect(field(page, "code")).toBeFocused();
      await page.keyboard.type("123456");
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await expect(formAlert(page)).toContainText(/300|۳۰۰/);
      await expect(field(page, "code")).toHaveCount(0);
    });

    test("invite_invalid when asking for the code ends in the invalid state", async ({page, context, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context, {"POST /auth/invites/lookup": lookup, "POST /auth/otp/request": err(404, "invite_invalid")});
      await page.goto(`/${lang}/invite#${CODE}`);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
    });
  });
}
