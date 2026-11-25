import {publicConfigFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {allowAuthErrors, callsTo, field, gotoForm, LANGS, meReady, openAnonymous, signedIn, text} from "./auth-support.ts";

// Round 8 of the review of WP8: a reload at ?step=otp-phone does not show the password form while
// /auth/config loads (wp8-r8-1), and a passkey sign-in whose finish request is in flight when the visitor leaves
// is not cancelled, so the session it opens is ended (wp8-r8-3). The length hint of r8-2 is a unit test
// (passwordStrength.test.ts), and the abort of the finish request has one too (webauthn.test.ts).

test.beforeEach(({guard}) => allowAuthErrors(guard));

function gate() {
  let release!: () => void;
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {opened, release};
}

const passkeyOptions = (rpId: string) => ({
  publicKey: {challenge: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", rpId, timeout: 60000, userVerification: "preferred"},
});

/** A resident credential on Chrome's virtual authenticator, so the browser's own ceremony answers at once. */
async function virtualAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Emulation.setFocusEmulationEnabled", {enabled: true});
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true},
  });
  await page.evaluate(async () => {
    const bytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
    await navigator.credentials.create({
      publicKey: {
        challenge: bytes(32),
        rp: {id: location.hostname, name: "Ctrl Z test"},
        user: {id: bytes(16), name: "e2e", displayName: "e2e"},
        pubKeyCredParams: [{type: "public-key", alg: -7}],
        authenticatorSelection: {residentKey: "required", userVerification: "required"},
      },
    });
  });
}

for (const {lang, dir} of LANGS) {
  test.describe(`round 8, ${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});
    const T = (path: string) => text(lang, path);

    // wp8-r8-1: the URL asked for the SMS form, so the password form is never shown while the answer is awaited.
    for (const sms of [true, false]) {
      test(`wp8-r8-1: ?step=otp-phone waits for /auth/config before it picks a form (SMS ${sms ? "works" : "is down"})`, async ({page, context}) => {
        const held = gate();
        let asked = 0;
        await openAnonymous(context, {
          "GET /auth/config": async () => {
            asked += 1;
            await held.opened;
            return {body: publicConfigFixture({sms_available: sms})};
          },
        });
        await page.goto(`/${lang}/login?step=otp-phone`);
        await expect.poll(() => asked).toBeGreaterThan(0);
        await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
        // No form to type into, and the URL keeps what the visitor asked for.
        await expect(page.locator("form")).toHaveCount(0);
        await expect(field(page, "password")).toHaveCount(0);
        expect(new URL(page.url()).searchParams.get("step")).toBe("otp-phone");
        held.release();
        if (sms) {
          await expect(field(page, "phone")).toBeVisible();
          await expect(field(page, "password")).toHaveCount(0);
          expect(new URL(page.url()).searchParams.get("step")).toBe("otp-phone");
        } else {
          await expect(field(page, "password")).toBeVisible();
          await expect.poll(() => new URL(page.url()).searchParams.get("step")).toBeNull();
        }
      });
    }

    // wp8-r8-3: the finish request opens the session, so leaving while it is in flight must still end the session.
    test("wp8-r8-3: leaving the passkey step while finish is in flight does not cancel it, and its session is ended", async ({page, context, baseURL}) => {
      const held = gate();
      const sign = signedIn(context, baseURL);
      let finishAborted = false;
      const mock = await openAnonymous(
        context,
        {
          "POST /auth/passkey/login/begin": {body: {ticket: "pk-ticket", options: passkeyOptions(new URL(baseURL!).hostname)}},
          "POST /auth/passkey/login/finish": async (c, s) => {
            await held.opened;
            return sign(c, s);
          },
          "POST /auth/logout": {status: 204},
          "GET /me": meReady(),
        },
        {passkey_enabled: true, registration_mode: "open"},
      );
      page.on("requestfailed", (request) => {
        if (request.url().includes("/auth/passkey/login/finish")) finishAborted = true;
      });
      await gotoForm(page, `/${lang}/register`);
      // A client-side move, so that Back is one too and the step unmounts without a page load.
      await page.getByRole("link", {name: T("register.signIn")}).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("login.title"));
      await virtualAuthenticator(page);
      await page.getByRole("button", {name: T("login.passkey")}).click();
      await expect.poll(() => callsTo(mock, "POST", "/auth/passkey/login/finish").length).toBe(1);
      await page.goBack();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(T("register.title"));
      held.release();
      await expect.poll(() => callsTo(mock, "POST", "/auth/logout").length).toBe(1);
      expect(finishAborted).toBe(false);
      await page.waitForTimeout(300);
      expect(new URL(page.url()).pathname).toBe(`/${lang}/register`);
      expect(callsTo(mock, "POST", "/auth/logout")).toHaveLength(1);
    });
  });
}
