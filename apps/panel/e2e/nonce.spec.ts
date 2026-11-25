import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";

import {allowAuthErrors, field, gotoForm, LANGS, openAnonymous, submit, text} from "./auth-support.ts";

// Spec 15.2, gate-r1-1 and gate-r1-8. The CSP of a document is fixed when it loads, and so must be the nonce that
// run-time readers find in the csp-nonce meta tag: React Aria and OtpField put it on the <style> elements they make
// later. A refresh of the server tree renders the root layout under a new request, with a new nonce. Before the fix React
// wrote that nonce into the tag, and a style made afterwards was refused (style-src-elem). The guard fails any such
// violation at the end of the test, so the OTP step below is the proof; the assertions on the tag say why.

test.beforeEach(({guard}) => allowAuthErrors(guard));

const PHONE = "09123456789";
const issued = {status: 202, body: {challenge_id: otpChallengeId(20), expires_in_s: 300, resend_after_s: 60}};

const nonceOfDocument = () => document.querySelector<HTMLScriptElement>("script[nonce]")?.nonce ?? "";
const nonceOfMeta = () => (document.querySelector('meta[name="csp-nonce"]') as HTMLMetaElement | null)?.nonce ?? "";

for (const {lang} of LANGS) {
  test.describe(`the nonce of the document after a refresh, ${lang}`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("the csp-nonce tag keeps the nonce of the first load, and an OTP field made after the refresh gets its style", async ({page, context}) => {
      await openAnonymous(context, {"POST /auth/otp/request": issued});
      await gotoForm(page, `/${lang}/login`);
      const first = await page.evaluate(nonceOfDocument);
      expect(first, "the document has a nonce").not.toBe("");
      expect(await page.evaluate(nonceOfMeta)).toBe(first);

      // A refresh of the server tree: the request is answered under a new nonce, which is what makes this test mean something.
      const answered = page.waitForResponse((r) => r.url().includes("_rsc") && r.request().method() === "GET");
      await page.evaluate(() => (window as unknown as {next: {router: {refresh(): void}}}).next.router.refresh());
      const csp = (await answered).headers()["content-security-policy"] ?? "";
      expect(/'nonce-([^']+)'/.exec(csp)?.[1], "the refresh was served under another nonce").not.toBe(first);
      // The refreshed tree has reached the page: React has had its turn to write the tag.
      await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => setTimeout(done, 100))));

      expect(await page.evaluate(nonceOfMeta), "the tag still holds the nonce of the document's CSP").toBe(first);
      expect(await page.evaluate(nonceOfDocument)).toBe(first);

      // The first OtpField of this document is made now: input-otp appends its <style> with the nonce it reads from the tag.
      await page.getByRole("tab", {name: text(lang, "login.tabOtp")}).click();
      await field(page, "phone").fill(PHONE);
      await submit(page).click();
      await expect(page.getByRole("heading", {level: 1})).toHaveText(text(lang, "login.otpCode.title"));
      await expect(field(page, "code")).toBeFocused();
      // A style that the browser refused has no sheet. The guard's CSP check at the end of the test is the other half.
      const styles = await page.evaluate(() => [...document.querySelectorAll<HTMLStyleElement>("style[nonce]")].map((el) => ({nonce: el.nonce, sheet: el.sheet !== null})));
      for (const style of styles) expect(style).toEqual({nonce: first, sheet: true});
    });
  });
}
