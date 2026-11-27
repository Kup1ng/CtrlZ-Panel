import {meFixture, otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {
  allowAuthErrors,
  callsTo,
  err,
  field,
  gotoForm,
  LANGS,
  meReady,
  openAnonymous,
  signedIn,
  STRONG_PASSWORD,
  submit,
  text,
  typeWhenFocused,
} from "./auth-support.ts";

// Round 9 of the review of WP8: the hint under a field is the field's own description, so a screen reader reads it
// with the field (wp8-r9-1), and the links between the sign-in pages carry `next` (wp8-r9-5). axe does not flag a
// hint that no input points at, so the first checks the relation itself.

test.beforeEach(({guard}) => allowAuthErrors(guard));

/** The text of every element an input's aria-describedby names, in order. A dangling id gives an empty string. */
async function described(input: Locator): Promise<string[]> {
  return input.evaluate((el) =>
    (el.getAttribute("aria-describedby") ?? "")
      .split(/\s+/)
      .filter(Boolean)
      .map((id) => document.getElementById(id)?.textContent?.trim() ?? ""),
  );
}

const OTP_ID = otpChallengeId(13);
const PHONE = "09123456789";
const issued = {status: 202, body: {challenge_id: OTP_ID, expires_in_s: 300, resend_after_s: 60}};
// A page of the panel that `next` may name, and how it is written inside a query.
const NEXT = "/endpoints";
const NEXT_QUERY = "next=%2Fendpoints";
function gate() {
  let release!: () => void;
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {opened, release};
}
const endsWith = (path: string, query = "") => new RegExp(`${path}${query ? `\\?${query}` : ""}$`);

for (const {lang, dir} of LANGS) {
  test.describe(`round 9, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    test("wp8-r9-1: the SMS number's hint is read with the number field", async ({page, context}) => {
      await openAnonymous(context);
      await gotoForm(page, `/${lang}/login`);
      await page.getByRole("tab", {name: T("login.tabOtp")}).click();
      await expect(field(page, "phone")).toBeVisible();
      await expect.poll(() => described(field(page, "phone"))).toContain(T("login.otpPhone.description"));
    });

    test("wp8-r9-1: the password recommendation of Register is read with the password field", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/register`);
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(field(page, "password")).toBeVisible();
      await expect.poll(() => described(field(page, "password"))).toContain(T("register.passwordHint"));
    });

    test("wp8-r9-1: why the current password is asked for is read with that field, which has the focus", async ({page, context, baseURL}) => {
      await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
      await installApiMock(context, {
        me: meFixture({user: {must_reset: true}}),
        handlers: {"POST /account/password": () => err(403, "reauth_required")},
      });
      await gotoForm(page, `/${lang}/change-password`);
      await field(page, "new_password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await expect(field(page, "reauth_password")).toBeFocused();
      await expect.poll(() => described(field(page, "reauth_password"))).toContain(T("changePassword.reauth.text"));
    });

    test("wp8-r9-5: the links between the sign-in pages carry next", async ({page, context}) => {
      await openAnonymous(context, {}, {registration_mode: "open", sms_available: true});
      await gotoForm(page, `/${lang}/login?next=${NEXT}`);
      await expect(page.getByRole("link", {name: T("login.register")})).toHaveAttribute("href", endsWith("/register", NEXT_QUERY));
      await expect(page.getByRole("link", {name: T("login.forgot")})).toHaveAttribute("href", endsWith("/forgot-password", NEXT_QUERY));

      await page.getByRole("link", {name: T("login.register")}).click();
      await page.waitForURL(`**/${lang}/register?${NEXT_QUERY}`);
      await expect(page.getByRole("link", {name: T("register.signIn")})).toHaveAttribute("href", endsWith("/login", NEXT_QUERY));

      // The Forgot Password page links back with it too.
      await page.goto(`/${lang}/forgot-password?next=${NEXT}`);
      await expect(page.getByRole("link", {name: T("forgot.back")})).toHaveAttribute("href", endsWith("/login", NEXT_QUERY));
    });

    test("wp8-r9-5: the invite link of the login page carries next", async ({page, context}) => {
      await openAnonymous(context, {}, {registration_mode: "invite"});
      await gotoForm(page, `/${lang}/login?next=${NEXT}`);
      await expect(page.getByRole("link", {name: T("login.invite")})).toHaveAttribute("href", endsWith("/invite", NEXT_QUERY));
    });

    test("wp8-r9-5: a next the proxy refuses is not carried", async ({page, context}) => {
      await openAnonymous(context, {}, {registration_mode: "open"});
      await gotoForm(page, `/${lang}/login?next=//evil.example`);
      await expect(page.getByRole("link", {name: T("login.register")})).toHaveAttribute("href", endsWith("/register"));
    });

    test("wp8-r9-5: registering after the link ends on the page the visitor came for", async ({page, context, baseURL}) => {
      const mock = await openAnonymous(
        context,
        {"POST /auth/otp/request": issued, "POST /auth/register": signedIn(context, baseURL), "GET /me": meReady()},
        {registration_mode: "open"},
      );
      await gotoForm(page, `/${lang}/login?next=${NEXT}`);
      await page.getByRole("link", {name: T("login.register")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.title"));
      await expect(submit(page)).toBeEnabled();
      await field(page, "phone").fill(PHONE);
      await expect(field(page, "phone")).toHaveValue(PHONE);
      await submit(page).click();
      await typeWhenFocused(page, "123456");
      await field(page, "password").fill(STRONG_PASSWORD);
      await submit(page).click();
      await page.waitForURL(`**/${lang}${NEXT}`);
      expect(callsTo(mock, "POST", "/auth/register")).toHaveLength(1);
    });

    // wp8-r9-6: the language switch is a full load, and a sign-in call that answers while it is under way would open
    // a session behind a blank login page. Two layers: the switch is off while a call runs, and a page that has
    // started the load ends a session that answers late.
    const OTHER = lang === "fa" ? "en" : "fa";
    const otherName = lang === "fa" ? "English" : "فارسی";
    const openCorner = async (page: Page) => {
      await page.getByRole("button", {name: T("corner.label")}).click();
      await expect(page.getByRole("menu")).toBeVisible();
    };
    const fillSignIn = async (page: Page) => {
      await field(page, "phone").fill(PHONE);
      await field(page, "password").fill(STRONG_PASSWORD);
    };

    test("wp8-r9-6: the other language is off in the corner menu while a sign-in call runs", async ({page, context, baseURL}) => {
      const held = gate();
      const sign = signedIn(context, baseURL);
      await openAnonymous(context, {
        "POST /auth/login/password": async (c, s) => {
          await held.opened;
          return sign(c, s);
        },
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await openCorner(page);
      await expect(page.getByRole("menuitemradio", {name: otherName})).not.toHaveAttribute("aria-disabled", "true");
      await page.keyboard.press("Escape");
      await fillSignIn(page);
      await submit(page).click();
      await expect(field(page, "password")).toBeDisabled();
      await openCorner(page);
      await expect(page.getByRole("menuitemradio", {name: otherName})).toHaveAttribute("aria-disabled", "true");
      await page.getByRole("menuitemradio", {name: otherName}).click({force: true});
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      held.release();
      await page.waitForURL(`**/${lang}/profiles`);
    });

    test("wp8-r9-6: a sign-in that answers while the language switch is loading is ended, and nobody is moved", async ({page, context, baseURL}) => {
      const sign = signedIn(context, baseURL);
      const mock = await openAnonymous(context, {
        "POST /auth/login/password": sign,
        "POST /auth/logout": {status: 204},
        "GET /me": meReady(),
      });
      await gotoForm(page, `/${lang}/login`);
      await fillSignIn(page);
      // Where the password field is, taken now: once the load has started Playwright waits for it before it acts
      // through a locator or page.evaluate, and the raw mouse and keyboard below do not.
      const box = (await field(page, "password").boundingBox())!;
      // The new document is held: the old page is alive and its form still works, as on a slow network.
      const document = gate();
      let asked = 0;
      await page.route(`**/${OTHER}/login**`, async (route) => {
        asked += 1;
        await document.opened;
        // Let the load through at the end. Aborting it left the tab on Chrome's error page, and a test that ends in that transition raced the
        // guard's close of the tab (wp8-r11-4, wp8-r9-6: one run in four).
        await route.continue().catch(() => undefined);
      });
      await openCorner(page);
      await page.getByRole("menuitemradio", {name: otherName}).click({noWaitAfter: true});
      await expect.poll(() => asked).toBeGreaterThan(0);
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      await page.keyboard.press("Enter");
      await expect.poll(() => callsTo(mock, "POST", "/auth/login/password").length).toBe(1);
      // The call opened a session, so the page ends it, and it does not go on to /profiles.
      await expect.poll(() => callsTo(mock, "POST", "/auth/logout").length).toBe(1);
      await page.waitForTimeout(300);
      expect(new URL(page.url()).pathname).toBe(`/${lang}/login`);
      document.release();
      await expect.poll(() => new URL(page.url()).pathname).toBe(`/${OTHER}/login`);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(1);
    });
    // wp8-r9-4: the first InputGroup on a screen (PasswordField, with a Show button in its suffix). The shell's corner is
    // 0.4 x height, and the parts inside it must use the same radius, or the autofill cover (clipped to
    // var(--radius-field)) paints over the shell's border and focus ring at the outer corners. The autofill paint
    // itself cannot be made to happen in Chrome without a saved password, so HeroUI's own declarations for it
    // are applied by hand to the input, and what the browser then computes is read.
    for (const scheme of ["light", "dark"] as const) {
      test(`wp8-r9-4: the input group's inner parts take the shell's corner, under the autofill paint (${scheme})`, async ({page, context}) => {
        await page.emulateMedia({colorScheme: scheme});
        await openAnonymous(context);
        await gotoForm(page, `/${lang}/login`);
        const got = await page.evaluate(() => {
          const group = document.querySelector(".input-group")!;
          const input = document.querySelector<HTMLElement>(".input-group__input")!;
          const suffix = document.querySelector(".input-group__suffix")!;
          input.style.setProperty("appearance", "none");
          input.style.setProperty("clip-path", "inset(0 round var(--radius-field))");
          const corners = (el: Element) => {
            const c = getComputedStyle(el);
            return [c.borderTopLeftRadius, c.borderTopRightRadius, c.borderBottomRightRadius, c.borderBottomLeftRadius];
          };
          return {
            shell: getComputedStyle(group).borderTopLeftRadius,
            height: group.getBoundingClientRect().height,
            clip: getComputedStyle(input).clipPath,
            input: corners(input),
            suffix: corners(suffix),
          };
        });
        const shell = parseFloat(got.shell);
        // 0.4 x height, to the pixel the browser rounds a border box to.
        expect(shell).toBeCloseTo(0.4 * got.height, 0);
        expect(got.clip).toContain(`${shell}px`);
        // The one rounded corner pair of the input is the shell's, the other pair is square (the suffix touches it).
        const rounded = got.input.map(parseFloat).filter((r) => r > 0);
        expect(rounded).toHaveLength(2);
        for (const r of rounded) expect(r).toBeCloseTo(shell, 1);
        // The suffix rounds its outer pair with the shell's radius too.
        const outer = got.suffix.map(parseFloat).filter((r) => r > 0);
        expect(outer).toHaveLength(2);
        for (const r of outer) expect(r).toBeCloseTo(shell, 1);
      });
    }
  });
}
