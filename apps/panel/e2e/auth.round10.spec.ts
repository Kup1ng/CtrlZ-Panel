import type {Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  gotoForm,
  inviteInfoFixture,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  STRONG_PASSWORD,
  submit,
  text,
  typeWhenFocused,
} from "./auth-support.ts";

// Round 10 of the review of WP8: what a paste brings along (wp8-r10-1), a language switch that would throw a ticket
// or a challenge away (wp8-r10-2), and a language switch that is cancelled (wp8-r10-3).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const OTP_ID = otpChallengeId(2);
const PHONE = "09123456789";
const LRM = "‎";
const RLM = "‏";
const ZWNJ = "‌";
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};

for (const {lang, dir} of LANGS) {
  test.describe(`round 10, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const OTHER = lang === "fa" ? "en" : "fa";
    const otherName = lang === "fa" ? "English" : "فارسی";
    const openCorner = async (page: Page) => {
      await page.getByRole("button", {name: T("corner.label")}).click();
      await expect(page.getByRole("menu")).toBeVisible();
    };

    // wp8-r10-1: the API refuses a string with a format character as a bare 400, whatever the field is.
    test("wp8-r10-1: a number pasted with LRM and RLM reaches the password sign-in clean", async ({page, context, baseURL}) => {
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {"POST /auth/login/password": sign, "GET /me": meReady()});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(`${LRM}${PHONE}${RLM}`);
      // The field shows what will be sent.
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(lastBody(mock, "POST", "/auth/login/password")).toMatchObject({phone: PHONE});
    });

    test("wp8-r10-1: the same on the SMS tab, and a number of nothing but format characters is 'required'", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("tab", {name: T("login.tabOtp")}).click();
      await field(page, "phone").fill(`${LRM}${RLM}`);
      await submit(page).click();
      await expect(page.getByText(T("fields.phone.required"))).toBeVisible();
      expect(callsTo(mock, "POST", "/auth/otp/request")).toHaveLength(0);
      await field(page, "phone").fill(`${RLM}${PHONE}${LRM}`);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.otpCode.title"));
      expect(lastBody(mock, "POST", "/auth/otp/request")).toMatchObject({phone: PHONE});
    });

    test("wp8-r10-1: Register sends the number clean", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(`${LRM}${PHONE}${LRM}`);
      await submit(page).click();
      await expect(field(page, "password")).toBeVisible();
      expect(lastBody(mock, "POST", "/auth/otp/request")).toMatchObject({phone: PHONE});
    });

    test("wp8-r10-1: a password with a direction mark is refused under its field, before anything is sent; a half-space (ZWNJ) is sent as typed (merge-r1-7)", async ({page, context, baseURL}) => {
      // The reply sets the session cookie, as the API does. Without it the gate answers the page's /profiles fetch with
      // a redirect to login, which the page's upgrade-insecure-requests turns into an https hop: the guard counts that as
      // another origin whenever the hop is issued before the test ends (gate-r1-3).
      const mock = await openAnonymous(context, {"POST /auth/login/password": signedIn(context, baseURL), "GET /me": meReady()});
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(`pass${RLM}word-1234`);
      await submit(page).click();
      await expect(page.getByText(T("fields.password.invisible"))).toBeVisible();
      await expect(field(page, "password")).toHaveAttribute("aria-invalid", "true");
      expect(callsTo(mock, "POST", "/auth/login/password")).toHaveLength(0);
      // merge-r1-7: main's server accepts U+200C in a password and removes it at set and at verify (D64), so the Persian
      // keyboard's half-space is no reason to refuse: the password goes out exactly as typed.
      await field(page, "password").fill(`${STRONG_PASSWORD.slice(0, 4)}${ZWNJ}${STRONG_PASSWORD.slice(4)}`);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      expect(lastBody(mock, "POST", "/auth/login/password")).toMatchObject({password: `${STRONG_PASSWORD.slice(0, 4)}${ZWNJ}${STRONG_PASSWORD.slice(4)}`});
      // The page settles before the test ends, so no request of its own is left in flight.
      await page.waitForURL(`**/${lang}/profiles`);
    });

    test("wp8-r10-1: Register refuses a password with a format character before it sends", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/otp/request": issued}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "password").fill(`${STRONG_PASSWORD}${RLM}`);
      await submit(page).click();
      await expect(page.getByText(T("fields.password.invisible"))).toBeVisible();
      expect(callsTo(mock, "POST", "/auth/register")).toHaveLength(0);
    });

    // wp8-r10-2: the reload of the switch would lose the ticket or the challenge, so the other language waits.
    test("wp8-r10-2: on a step that holds a challenge the other language is off, with the reason; at the first step it is on", async ({
      page,
      context,
    }) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/login`);
      await openCorner(page);
      await expect(page.getByRole("menuitemradio", {name: otherName})).not.toHaveAttribute("aria-disabled", "true");
      await page.keyboard.press("Escape");
      await page.getByRole("tab", {name: T("login.tabOtp")}).click();
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.otpCode.title"));
      await openCorner(page);
      const item = page.getByRole("menuitemradio", {name: otherName});
      await expect(item).toHaveAttribute("aria-disabled", "true");
      await expect(item).toContainText(T("corner.languageHeld"));
      await item.click({force: true});
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      await page.keyboard.press("Escape");
      await page.getByRole("button", {name: T("login.otpCode.change")}).click();
      await openCorner(page);
      await expect(page.getByRole("menuitemradio", {name: otherName})).not.toHaveAttribute("aria-disabled", "true");
    });

    // wp8-r20-1 (it replaces the hold of wp8-r10-2 and wp8-r16-5 on the invite page): the code of a link lives only in
    // this page's state, so the switch is free and carries it in the destination's fragment. The page that loads takes
    // the fragment off the bar and looks the invite up again, so an invitee reaches the other language at the same step.
    const CODE = "ABCD-EFGH-JKMN-PQRS-TVWX";
    const canonical = CODE.replaceAll("-", "");

    test("wp8-r20-1: the language can be switched on the invite info step, and the code goes with it", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      expect(new URL(page.url()).hash).toBe("");
      await openCorner(page);
      const item = page.getByRole("menuitemradio", {name: otherName});
      await expect(item).not.toHaveAttribute("aria-disabled", "true");
      await expect(item).not.toContainText(T("corner.languageHeld"));
      await item.click();
      await page.waitForURL(`**/${OTHER}/invite`);
      // Same step in the other language, with the fragment already taken off the address bar again.
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(OTHER, "invite.lookupTitle"));
      expect(new URL(page.url()).hash).toBe("");
      const lookups = callsTo(mock, "POST", "/auth/invites/lookup");
      expect(lookups).toHaveLength(2);
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toMatchObject({token: canonical});
    });

    test("wp8-r20-1: a link whose lookup failed can switch language too, and the code goes with it", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": err(503, "service_unavailable")});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(field(page, "token")).toHaveValue(CODE);
      await openCorner(page);
      const item = page.getByRole("menuitemradio", {name: otherName});
      await expect(item).not.toHaveAttribute("aria-disabled", "true");
      await item.click();
      await page.waitForURL(`**/${OTHER}/invite`);
      await expect(field(page, "token")).toHaveValue(CODE);
      expect(lastBody(mock, "POST", "/auth/invites/lookup")).toMatchObject({token: canonical});
    });

    // wp8-r21-3: only the code of a link goes into a URL. A fragment in a navigation is recorded in the browser's
    // global history, which a code the visitor typed never was. The committed URLs of the frame are collected, since
    // the destination takes its fragment off the bar again and the final URL would not show it.
    const committedUrls = (page: Page) => {
      const urls: string[] = [];
      page.on("framenavigated", (frame) => {
        if (frame === page.mainFrame()) urls.push(frame.url());
      });
      return urls;
    };

    test("wp8-r21-3: a typed code is not written into the URL by the language switch", async ({page, context}) => {
      const mock = await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      const urls = committedUrls(page);
      await gotoForm(page, `/${lang}/invite`);
      await field(page, "token").pressSequentially(canonical);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await openCorner(page);
      const item = page.getByRole("menuitemradio", {name: otherName});
      await expect(item).not.toHaveAttribute("aria-disabled", "true");
      await item.click();
      await page.waitForURL(`**/${OTHER}/invite`);
      // The code was typed, so it is not carried: the other language asks for it again, and no URL held it.
      await expect(field(page, "token")).toHaveValue("");
      expect(urls.filter((url) => url.includes("#"))).toEqual([]);
      expect(callsTo(mock, "POST", "/auth/invites/lookup")).toHaveLength(1);
    });

    test("wp8-r21-3: a link's code is still carried, and was in the destination's fragment", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}});
      const urls = committedUrls(page);
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await openCorner(page);
      await page.getByRole("menuitemradio", {name: otherName}).click();
      await page.waitForURL(`**/${OTHER}/invite`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(OTHER, "invite.lookupTitle"));
      expect(urls.some((url) => url.includes(`/${OTHER}/invite#`))).toBe(true);
    });

    test("wp8-r21-3: typing over the code of a link stops it being carried", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": err(503, "service_unavailable")});
      const urls = committedUrls(page);
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(field(page, "token")).toHaveValue(CODE);
      // One character is replaced by the visitor: the code in the field is now a typed one.
      await field(page, "token").press("Backspace");
      await field(page, "token").pressSequentially("X");
      await openCorner(page);
      await page.getByRole("menuitemradio", {name: otherName}).click();
      await page.waitForURL(`**/${OTHER}/invite`);
      await expect(field(page, "token")).toHaveValue("");
      expect(urls.filter((url) => url.includes(`/${OTHER}/invite#`))).toEqual([]);
    });

    test("wp8-r20-1: a code that is not whole is not carried, and the field starts empty in the other language", async ({page, context}) => {
      await openAnonymous(context, {});
      await gotoForm(page, `/${lang}/invite`);
      await field(page, "token").pressSequentially("ABCD");
      await openCorner(page);
      await expect(page.getByRole("menuitemradio", {name: otherName})).not.toHaveAttribute("aria-disabled", "true");
      await page.getByRole("menuitemradio", {name: otherName}).click();
      await page.waitForURL(`**/${OTHER}/invite`);
      expect(new URL(page.url()).hash).toBe("");
      await expect(field(page, "token")).toHaveValue("");
    });

    test("wp8-r20-1: the confirm step of an invite still holds the language, because its challenge cannot be carried", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/invites/lookup": {body: inviteInfoFixture()}, "POST /auth/otp/request": issued});
      await page.goto(`/${lang}/invite#${CODE}`);
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.lookupTitle"));
      await page.getByRole("button", {name: T("invite.send")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("invite.confirmTitle"));
      await openCorner(page);
      await expect(page.getByRole("menuitemradio", {name: otherName})).toHaveAttribute("aria-disabled", "true");
    });

    // wp8-r10-3: a load that is cancelled (Stop, Escape, window.stop()) leaves this document alive, and nothing
    // fires for it. Without the fix the mark stays, the sign-in is ended and its form spins for ever.
    test("wp8-r10-3: after a cancelled language switch a sign-in finishes on this page", async ({page, context, baseURL}) => {
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": sign,
        "POST /auth/logout": {status: 204},
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      let asked = 0;
      const held: (() => void)[] = [];
      await page.route(`**/${OTHER}/login**`, (route) => {
        asked += 1;
        // Held: the visitor cancels before it answers.
        held.push(() => void route.abort().catch(() => undefined));
      });
      await openCorner(page);
      await page.getByRole("menuitemradio", {name: otherName}).click({noWaitAfter: true});
      await expect.poll(() => asked).toBeGreaterThan(0);
      // The Stop button, as the browser itself does it.
      const cdp = await context.newCDPSession(page);
      await cdp.send("Page.stopLoading");
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await page.waitForURL(`**/${lang}/profiles`);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(0);
      for (const release of held) release();
    });

    test("wp8-r10-3: a switch that goes through still ends a session that answers during it (round 9 stays)", async ({page, context, baseURL}) => {
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": sign,
        "POST /auth/logout": {status: 204},
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      const box = (await field(page, "password").boundingBox())!;
      let release!: () => void;
      const opened = new Promise<void>((resolve) => (release = resolve));
      await page.route(`**/${OTHER}/login**`, async (route) => {
        await opened;
        // Let the load through at the end. Aborting it left the tab on Chrome's error page, and a test that ends in that transition raced the
        // guard's close of the tab (wp8-r11-4, wp8-r9-6: one run in four).
        await route.continue().catch(() => undefined);
      });
      await openCorner(page);
      await page.getByRole("menuitemradio", {name: otherName}).click({noWaitAfter: true});
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      await page.keyboard.press("Enter");
      await expect.poll(() => callsTo(mock, "POST", "/auth/logout").length).toBe(1);
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      release();
      await expect.poll(() => new URL(page.url()).pathname).toBe(`/${OTHER}/login`);
    });
  });
}
