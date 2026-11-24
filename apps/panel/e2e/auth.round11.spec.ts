import type {Page} from "@playwright/test";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  errorText,
  field,
  gotoForm,
  lastBody,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  STRONG_PASSWORD,
  submit,
  text,
} from "./auth-support.ts";

// Round 11 of the review of WP8: a pasted code with invisible characters (wp8-r11-1), a sign-in that moves on and
// comes back to the login route (wp8-r11-2), the way back from Forgot Password step 3 (wp8-r11-3), and a language
// load that Chrome aborts without cancelling (wp8-r11-4).

test.beforeEach(({guard}) => allowAuthErrors(guard));

const OTP_ID = otpChallengeId(3);
const PHONE = "09123456789";
const RLM = "‏";
const LRM = "‎";
const ZWSP = "​";
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};

for (const {lang, dir} of LANGS) {
  test.describe(`round 11, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);
    const OTHER = lang === "fa" ? "en" : "fa";
    const otherName = lang === "fa" ? "English" : "فارسی";

    async function toOtpCode(page: Page) {
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("tab", {name: T("login.tabOtp")}).click();
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.otpCode.title"));
      await expect(field(page, "code")).toBeFocused();
    }

    // wp8-r11-1: input-otp drops a whole paste, with no message, when the text fails the digit pattern.
    test("wp8-r11-1: a code pasted with RLM, LRM and ZWSP around it is taken and sent", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": err(401, "otp_invalid"),
      });
      await toOtpCode(page);
      await page.evaluate((pasted) => {
        const input = document.querySelector<HTMLInputElement>('input[name="code"]')!;
        const data = new DataTransfer();
        data.setData("text/plain", pasted);
        input.dispatchEvent(new ClipboardEvent("paste", {clipboardData: data, bubbles: true, cancelable: true}));
      }, `${RLM}123${LRM}456${ZWSP}`);
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/otp").length).toBe(1);
      expect(lastBody(mock, "POST", "/auth/login/otp")).toMatchObject({code: "123456"});
    });

    // gate-r28-6: page translation sends text nodes to a third party, and each typed digit is a text node of a slot. input-otp marks its own
    // container translate="no"; this pins that in a real page, with a digit typed, so a library bump that drops it fails here.
    test("gate-r28-6: the slots and the input of the code field sit inside translate=no, with a code typed in", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": err(401, "otp_invalid"),
      });
      await toOtpCode(page);
      await page.keyboard.type("12");
      const bare = await page.evaluate(() => {
        const nodes = [...document.querySelectorAll('input[name="code"], [data-slot="input-otp-slot"], .input-otp__slot')];
        return {count: nodes.length, bare: nodes.filter((n) => !n.closest('[translate="no"]')).length};
      });
      expect(bare.count).toBeGreaterThanOrEqual(7);
      expect(bare.bare).toBe(0);
    });

    test("wp8-r11-1: a code that autofill puts in the input with a mark in it is taken too", async ({page, context}) => {
      const mock = await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/login/otp": err(401, "otp_invalid"),
      });
      await toOtpCode(page);
      await page.evaluate((filled) => {
        const input = document.querySelector<HTMLInputElement>('input[name="code"]')!;
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, filled);
        input.dispatchEvent(new Event("input", {bubbles: true}));
      }, `${RLM}654321`);
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/otp").length).toBe(1);
      expect(lastBody(mock, "POST", "/auth/login/otp")).toMatchObject({code: "654321"});
    });

    // wp8-r11-2: the browser drops the session cookie, so the proxy sends /profiles back to this very route. Nothing
    // unmounts the page, and the form used to stay pending for ever.
    test("wp8-r11-2: a sign-in that ends back on the login route gives the form back, with a notice", async ({page, context, baseURL}) => {
      test.setTimeout(90_000);
      // No cookie is set, as when the browser refuses it, so the proxy sends /profiles back to the login route. The
      // proxy's own Location is relative, but the page's CSP carries upgrade-insecure-requests, so on an http origin
      // Chrome hops to https and the guard counts that as another origin (gate-r1-9). The redirect is answered here, on
      // the page's own origin, so the hop is never made.
      // The redirect keeps the `_rsc` key of the request, or the server answers it with one more redirect.
      await context.route(`**/${lang}/profiles**`, (route) => {
        const rsc = new URL(route.request().url()).searchParams.get("_rsc");
        const location = `${baseURL}/${lang}/login?next=%2Fprofiles${rsc ? `&_rsc=${rsc}` : ""}`;
        return route.fulfill({status: 307, headers: {location}});
      });
      // After the bound the page asks /me (wp8-r12-1): 401, and no refresh cookie to renew it, as the API answers.
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": {status: 200, body: {status: "authenticated"}},
        "POST /auth/refresh": err(401, "session_expired"),
      });
      await gotoForm(page, `/${lang}/login`);
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      // Pending first, as the round 5 rule says.
      await expect(field(page, "password")).toBeDisabled();
      // Then, after the bound, the form is made again with the notice and the focus on the password.
      await expect(page.getByText(errorText(lang, "session_expired"), {exact: true})).toBeVisible({timeout: 40_000});
      await expect(field(page, "password")).toBeEnabled();
      await expect(field(page, "password")).toBeFocused();
      await expect(field(page, "phone")).toHaveValue(PHONE);
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      // And it signs in again: nothing was left half done.
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(2);
    });

    // wp8-r11-3: the language item says "return to the first step", so the step must have a control that does.
    test("wp8-r11-3: Forgot Password step 3 has a way back to the first step, on both views", async ({page, context}) => {
      await openAnonymous(context, {
        "POST /auth/otp/request": issued,
        "POST /auth/password/reset/verify": (call) => ({
          body: {ticket: "reset-ticket-1", second_factor: call.pageUrl.includes("passkey=1") ? "passkey" : "none"},
        }),
      });
      for (const second of ["none", "passkey"] as const) {
        await gotoForm(page, `/${lang}/forgot-password${second === "passkey" ? "?passkey=1" : ""}`);
        await field(page, "phone").fill(PHONE);
        await submit(page).click();
        await expect(field(page, "code")).toBeFocused();
        await page.keyboard.type("123456");
        await expect(page.getByRole("heading", {level: 1})).toHaveText(T("forgot.newTitle"));
        // The language is held here, and the control the reason names is on the page.
        await page.getByRole("button", {name: T("corner.label")}).click();
        await expect(page.getByRole("menuitemradio", {name: otherName})).toHaveAttribute("aria-disabled", "true");
        await page.keyboard.press("Escape");
        await page.getByRole("button", {name: T("forgot.change")}).click();
        await expect(field(page, "phone")).toBeVisible();
        await expect(field(page, "phone")).toBeFocused();
        await page.getByRole("button", {name: T("corner.label")}).click();
        await expect(page.getByRole("menuitemradio", {name: otherName})).not.toHaveAttribute("aria-disabled", "true");
        await page.keyboard.press("Escape");
      }
    });

    // wp8-r11-4: Chrome aborts the signal of a pending load when a later navigation starts, and the load commits.
    test("wp8-r11-4: a tab change while the language load is held does not leave the session behind the new page", async ({
      page,
      context,
      baseURL,
    }) => {
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": sign,
        "POST /auth/logout": {status: 204},
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      // Chrome holds some work until its tab has the focus (see login.spec.ts).
      const cdp = await context.newCDPSession(page);
      await cdp.send("Emulation.setFocusEmulationEnabled", {enabled: true});
      await field(page, "phone").fill(PHONE);
      const smsTab = (await page.getByRole("tab", {name: T("login.tabOtp")}).boundingBox())!;
      const passwordTab = (await page.getByRole("tab", {name: T("login.tabPassword")}).boundingBox())!;
      const password = (await field(page, "password").boundingBox())!;
      const centre = (box: {x: number; y: number; width: number; height: number}) => [box.x + box.width / 2, box.y + box.height / 2] as const;
      let release!: () => void;
      const opened = new Promise<void>((resolve) => (release = resolve));
      await page.route(`**/${OTHER}/login**`, async (route) => {
        await opened;
        // Let the load through at the end. Aborting it left the tab on Chrome's error page, which probes the origin by itself and writes the
        // refusal to the console, and a test that ends there raced the guard's close of that tab (wp8-r11-4, one run in four).
        await route.continue().catch(() => undefined);
      });
      await page.getByRole("button", {name: T("corner.label")}).click();
      await page.getByRole("menuitemradio", {name: otherName}).click({noWaitAfter: true});
      // Playwright waits for a held load before a locator action, so the rest is raw input. Each tab change is a
      // history.replaceState, which aborts the load's signal in Chrome though the load still commits.
      // A page that waits for a held load only processes raw input when a frame is produced, and a window that
      // nobody looks at produces none, so each step asks for one.
      const frame = () => cdp.send("Page.captureScreenshot", {format: "jpeg", quality: 10});
      await page.mouse.click(...centre(smsTab));
      await frame();
      await page.mouse.click(...centre(passwordTab));
      await frame();
      await page.mouse.click(...centre(password));
      await frame();
      await page.keyboard.type(STRONG_PASSWORD);
      await frame();
      await page.keyboard.press("Enter");
      await frame();
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      await expect.poll(() => callsTo(mock, "POST", "/auth/logout").length).toBe(1);
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      release();
      await expect.poll(() => new URL(page.url()).pathname).toBe(`/${OTHER}/login`);
    });
  });
}
