import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expectNoSecretResidue} from "@ctrlz/ui/testing/secretResidue.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  errorText,
  field,
  formAlert,
  gotoForm,
  INVITE_TOKEN,
  inviteInfoFixture,
  inviteLinkFixture,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  submit,
  text, STRONG_PASSWORD} from "./auth-support.ts";

// Spec 17.3 `invite.spec.ts` (T-095, T-330, D67), in mock mode: the tables of 10.5. The fragment of the link is
// removed from the address bar at once and goes nowhere: it is read by the page and sent only in the body
// of the lookup. The token is 140 characters, case sensitive: no page uppercases, groups or strips it.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const CODE = INVITE_TOKEN;
const LINK = inviteLinkFixture(CODE);
const OTP_ID = otpChallengeId(17);
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
const lookup = {body: inviteInfoFixture()};

for (const {lang, dir} of LANGS) {
  test.describe(`invite, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("the fragment is read and removed from the address bar, and the token is looked up in a POST body as it came", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(new URL(page.url()).hash).toBe("");
      expect(page.url()).not.toContain(CODE.slice(0, 8));
      // Exactly as it came: case, hyphens and underscores kept. And it is not in any URL the page asked for.
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
      for (const call of mock.calls) expect(call.path + call.query.toString()).not.toContain(CODE);
      // History holds no entry with the fragment either.
      expect(await page.evaluate(() => location.href)).not.toContain("#");
    });

    // webi-r2-1, webi-r2-9: the address bar gives the fragment percent-encoded, so a mark a chat app put after the link arrives as %E2%80%8F.
    test("a link that ends in an invisible mark is the same invite: the lookup is made with the token alone", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await page.goto(`/${lang}/invite#${CODE}%E2%80%8F`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
      expect(new URL(page.url()).hash).toBe("");
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

    test("no fragment: a pasted link is cut out, cleaned of white space and invisible marks, and the token is sent as it is", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      const input = field(page, "token");
      await expect(input).toBeFocused();
      expect(await input.evaluate((el) => el.closest("[dir]")?.getAttribute("dir") ?? (el as HTMLElement).dir)).toBe("ltr");
      // A chat app's wrapping: spaces around, a left-to-right mark and a half-space inside.
      await input.fill(`  ${LINK.slice(0, 40)}\u200e ${LINK.slice(40, 90)}\u200c${LINK.slice(90)}  `);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
      // The token is not in the address bar after the lookup either.
      expect(page.url()).not.toContain(CODE.slice(0, 8));
    });

    test("no fragment: the bare token works, and a lower-case copy is not turned into upper case", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      await field(page, "token").fill(CODE.toLowerCase());
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE.toLowerCase()});
      expect(CODE.toLowerCase()).not.toBe(CODE);
    });

    test("something that is not an invite link is the invite_invalid text on the field, before any request", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      const bad = [
        "ABCD",
        CODE.slice(0, 139),
        `${CODE}a`,
        `${CODE.slice(0, 139)}!`,
        "https://panel.example.test/invite",
        // A Persian letter is not the token alphabet. (Persian digits are folded to ASCII like the server does: the next test.)
        `${CODE.slice(0, 139)}ب`,
      ];
      for (const pasted of bad) {
        await field(page, "token").fill(pasted);
        await submit(page).click();
        await expect(page.getByText(errorText(lang, "invite_invalid"))).toBeVisible();
      }
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(0);
    });

    // webi-r1-4: the server folds Persian digits before it opens a token, so a link that a chat app shows with them is the same invite.
    test("a paste that shows its digits as Persian is looked up with ASCII digits, like the server reads it", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      const shown = CODE.replace(/[0-9]/g, (d) => String.fromCharCode(0x06f0 + Number(d)));
      expect(shown).not.toBe(CODE);
      await field(page, "token").fill(shown);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toEqual({token: CODE});
    });

    test("an empty field asks for the link", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await gotoForm(page, `/${lang}/invite`);
      await submit(page).click();
      await expect(page.getByText(T("fields.inviteLink.required"))).toBeVisible();
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(0);
    });

    test("a fragment that is not a token is the invalid state with no lookup, and the page leaves it to try another link", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": lookup});
      await page.goto(`/${lang}/invite#${CODE.slice(0, 20)}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(0);
      await expect.poll(() => page.evaluate(() => location.hash)).toBe("");
      await page.getByRole("button", {name: T("invite.another")}).click();
      await expect(field(page, "token")).toHaveValue("");
    });

    test("invite_invalid is one state with no detail, from a link and from a pasted one", async ({page, context, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context, {"POST /auth/invites/lookup": err(404, "invite_invalid")}, {});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
      await expect(page.getByText(T("invite.invalidText"))).toBeVisible();
      await page.getByRole("button", {name: T("invite.another")}).click();
      await field(page, "token").fill(LINK);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
    });

    test("too_many_attempts on the lookup waits, with the link kept", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": err(429, "too_many_attempts", {retry_after_s: 40})});
      await gotoForm(page, `/${lang}/invite`);
      await field(page, "token").fill(LINK);
      await submit(page).click();
      await expect(formAlert(page)).toBeVisible();
      await expect(submit(page)).toBeDisabled();
      await expect(field(page, "token")).toHaveValue(LINK);
    });

    test("a link whose lookup is refused with a wait falls back to the paste field, with the token in it", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": err(429, "too_many_attempts", {retry_after_s: 40})});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(field(page, "token")).toHaveValue(CODE);
      await expect(formAlert(page)).toBeVisible();
      // wp8-r2-4: the wait of the 429 is on the button, as it is for a pasted link, so a press cannot send another lookup.
      await expect(submit(page)).toBeDisabled();
      await expect(submit(page)).not.toHaveText(T("invite.submit"));
    });

    test("sms_available = false: step 2 says SMS is down and to ask the admin, and Send is off", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": lookup}, {sms_available: false});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByText(T("invite.smsDown"))).toBeVisible();
      await expect(submit(page)).toBeDisabled();
    });

    // wp8-r7-1: otp_locked on the invite's token returns to the invite step with the wait in the message.
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

    test("invite_invalid when asking for the SMS code ends in the invalid state", async ({page, context, guard}) => {
      guard.allowConsole(/status of 404/);
      await openAnonymous(context, {"POST /auth/invites/lookup": lookup, "POST /auth/otp/request": err(404, "invite_invalid")});
      await page.goto(`/${lang}/invite#${CODE}`);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.invalidTitle"));
    });
  });
}
