import {expect, test} from "@ctrlz/ui/testing/guard.ts";
import {otpChallengeId} from "@ctrlz/api-client/testing/fixtures.ts";

import {INVITE_TOKEN, allowAuthErrors, field, gotoForm, inviteInfoFixture, openAnonymous, submit, text} from "./auth-support.ts";

// gate-r2-14. `global-error.tsx` is the fallback for every render error on the six auth pages: only (shell) has an error.tsx, and there is
// no [locale]/error.tsx. It supplies its own <html>, with inline `style` attributes and `light-dark()` colours, because the provider
// that failed may be the one that would have supplied the rest, and spec 8.7 and 15.2 promise that it loads nothing. Nothing else
// renders it, so a later edit that gave it a <style>, a font or a script would raise a CSP violation that no test would see, and a
// Retry that did nothing would go unseen as well.
//
// The crash is a lookup reply whose masked number is an object: React refuses to render it as text. The React error and the failed
// load are the two console messages the browser adds on its own, and they are named here and nowhere else.

test.beforeEach(({guard}) => allowAuthErrors(guard));
test.use({allowConsole: [/Minified React error|Objects are not valid as a React child|status of (404|500)/]});

const CODE = INVITE_TOKEN;

for (const colorScheme of ["light", "dark"] as const) {
  test.describe(`the fatal state, ${colorScheme}`, () => {
    test.use({colorScheme, viewport: {width: 375, height: 812}});

    test("shows both languages, loads nothing from outside, and Try again renders the page again", async ({page, context, guard}) => {
      let lookups = 0;
      await openAnonymous(context, {
        "POST /auth/invites/lookup": () => {
          lookups += 1;
          return {body: {...inviteInfoFixture(), phone_masked: {broken: true}}};
        },
      });
      await page.goto(`/fa/invite#${CODE}`);

      const fatal = page.locator("main", {hasText: "Something went wrong"});
      await expect(fatal).toBeVisible();
      await expect(fatal).toContainText("مشکلی پیش آمد");
      await expect(fatal.locator('section[lang="fa"]')).toHaveAttribute("dir", "rtl");
      await expect(fatal.locator('section[lang="en"]')).toHaveAttribute("dir", "ltr");
      const retry = page.getByRole("button", {name: /تلاش دوباره \/ Try again/});
      await expect(retry).toBeVisible();
      // It styles itself with inline attributes and no class. (The document keeps the stylesheets that the app's own layout added before the
      // crash, and the Dana face with them: that is Next's doing, and they would be blocked, not loaded, if they were not the app's own.)
      expect(await fatal.locator("[class]").count(), "global-error.tsx uses no class, so no stylesheet is needed for it").toBe(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "no horizontal scroll at 375").toBe(true);
      // The colours follow light-dark(), so the dark phone has a dark ground (no white flash).
      const ground = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
      expect(ground, `the ground in ${colorScheme}`).toBe(colorScheme === "dark" ? "rgb(10, 11, 12)" : "rgb(247, 247, 248)");
      expect(guard.consume("csp"), "a CSP violation while the fatal state is shown").toEqual([]);

      // Retry is a real button: it asks React to render the tree again, which for the invite page with no code in the address any more is not the crash.
      await retry.click();
      await expect(fatal).toHaveCount(0);
      await expect(page.getByRole("heading", {level: 1})).toBeVisible();
      expect(lookups).toBe(1);
    });
  });
}

// gate-r9-1. The csp-nonce tag is removed with the old document head when global-error.tsx replaces the document, and Try again mounts the layout
// again. If a router.refresh() had been answered under another request's nonce before, the layout's prop is that nonce, and a tag that took it
// would be refused by the document's CSP, which is the failure gate-r1-1 removed. The value is held outside React for that reason.
const PHONE = "09123456789";
const issued = {status: 202, body: {challenge_id: otpChallengeId(15), expires_in_s: 300, resend_after_s: 60}};
const nonceOfDocument = () => document.querySelector<HTMLScriptElement>("script[nonce]")?.nonce ?? "";
const nonceOfMeta = () => (document.querySelector('meta[name="csp-nonce"]') as HTMLMetaElement | null)?.nonce ?? "";
type Router = {next: {router: {refresh(): void; push(href: string): void}}};

test.describe("the nonce tag after a refresh, a crash and Try again (gate-r9-1)", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("the tag is the document's nonce again, and an OTP field made afterwards gets its style", async ({page, context}) => {
    await openAnonymous(context, {
      "POST /auth/invites/lookup": () => ({body: {...inviteInfoFixture(), phone_masked: {broken: true}}}),
      "POST /auth/otp/request": issued,
    });
    await gotoForm(page, "/en/login");
    const first = await page.evaluate(nonceOfDocument);
    expect(first, "the document has a nonce").not.toBe("");

    // A refresh answered under another nonce: the layout's prop in the client's payload is now not the document's.
    const answered = page.waitForResponse((r) => r.url().includes("_rsc") && r.request().method() === "GET");
    await page.evaluate(() => (window as unknown as Router).next.router.refresh());
    expect(/'nonce-([^']+)'/.exec((await answered).headers()["content-security-policy"] ?? "")?.[1], "the refresh was served under another nonce").not.toBe(first);
    await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => setTimeout(done, 100))));
    expect(await page.evaluate(nonceOfMeta)).toBe(first);

    // The crash: global-error.tsx replaces the document, and the tag goes with the old head.
    await page.evaluate((code) => (window as unknown as Router).next.router.push(`/en/invite#${code}`), CODE);
    const retry = page.getByRole("button", {name: /تلاش دوباره \/ Try again/});
    await expect(retry).toBeVisible();
    expect(await page.evaluate(nonceOfMeta), "the tag is gone while the fatal state is shown").toBe("");

    // Try again mounts the layout from the client's cached payload, whose prop is the later nonce.
    await page.evaluate(() => history.replaceState(null, "", "/en/invite"));
    await retry.click();
    await expect(page.getByRole("heading", {level: 1})).toBeVisible();
    expect(await page.evaluate(nonceOfMeta), "the tag holds the nonce of the document's CSP").toBe(first);
    expect(await page.evaluate(nonceOfDocument)).toBe(first);

    await page.evaluate(() => (window as unknown as Router).next.router.push("/en/login"));
    await page.getByRole("tab", {name: text("en", "login.tabOtp")}).click();
    await field(page, "phone").fill(PHONE);
    await submit(page).click();
    await expect(page.getByRole("heading", {level: 1})).toHaveText(text("en", "login.otpCode.title"));
    await expect(field(page, "code")).toBeFocused();
    const styles = await page.evaluate(() => [...document.querySelectorAll<HTMLStyleElement>("style[nonce]")].map((el) => ({nonce: el.nonce, sheet: el.sheet !== null})));
    for (const style of styles) expect(style).toEqual({nonce: first, sheet: true});
  });
});
