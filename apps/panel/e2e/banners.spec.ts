import {meFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock} from "@ctrlz/api-client/testing/mock.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

// Spec 17.3 `banners.spec.ts` (T-122), in mock mode: the toast sits at the bottom of the viewport. Priority, the limit of two and the
// announcement window are in `session.spec.ts`, the security banner in `notices.spec.ts` and the offline banner in `shell.spec.ts`; the
// placement is the one thing that no case asserted (`Toast.Provider placement="bottom"` is in AppProviders.tsx), and a provider that
// moved it, or a stylesheet that pushed it under the page header, would have passed every other case.
//
// The toast of the sample is the one a refused dismissal of the onboarding card raises (spec 8.12): a real toast from a real action,
// and not a component drawn for the test.

const LANGS = [
  {lang: "fa", say: /سرویس فعلاً در دسترس نیست/, hide: "پنهان کردن", confirm: "پنهان کن"},
  {lang: "en", say: /service is not available/i, hide: "Hide", confirm: "Hide it"},
] as const;

// 375 is a phone, where the toast takes the full width less the gutters; 1280 is the desktop, where it is 460 wide.
const WIDTHS = [375, 1280] as const;

for (const {lang, say, hide, confirm} of LANGS) {
  for (const width of WIDTHS) {
    test.describe(`${lang} at ${width}px`, () => {
      test.use({viewport: {width, height: 800}});

      test("a toast is at the bottom of the viewport, centred, and inside it (T-122)", async ({page, context, baseURL, guard}) => {
        guard.allowConsole(/status of 503/);
        await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
        const mock = await installApiMock(context, {me: meFixture({user: {locale: lang}})});
        mock.on("PATCH /account/preferences", {status: 503, body: {code: "service_unavailable"}});
        await page.goto(`/${lang}/profiles`);
        await page.getByRole("button", {name: hide, exact: true}).click();
        await page.getByRole("button", {name: confirm, exact: true}).click();

        const toast = page.locator(".toast", {hasText: say});
        await expect(toast).toBeVisible();
        await expect(page.locator(".toast-region")).toHaveClass(/toast-region--bottom\b/);
        // The toast rises into place from below and leaves after a few seconds, so its box is read in one step, in the frame where the
        // entrance has finished (an identity transform), and not from two reads that a moving element would make disagree.
        const box = await toast.evaluate(
          (el) =>
            new Promise<{x: number; y: number; width: number; height: number}>((resolve) => {
              const settled = () => {
                const {transform} = getComputedStyle(el);
                if (transform === "none" || transform === "matrix(1, 0, 0, 1, 0, 0)") {
                  const r = el.getBoundingClientRect();
                  resolve({x: r.x, y: r.y, width: r.width, height: r.height});
                } else requestAnimationFrame(settled);
              };
              settled();
            }),
        );
        const view = page.viewportSize()!;
        // Entirely inside the viewport, in the lower half, and nearer the bottom edge than the top one.
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(view.width);
        expect(box.y + box.height).toBeLessThanOrEqual(view.height);
        expect(box.y + box.height / 2, "the toast's centre is in the lower half").toBeGreaterThan(view.height / 2);
        expect(view.height - (box.y + box.height), "the gap under the toast").toBeLessThan(box.y);
        // Centred on the inline axis in both directions of writing.
        expect(Math.abs(box.x + box.width / 2 - view.width / 2)).toBeLessThanOrEqual(2);
        // The provider's width: 460 at most, and the screen less 32 below that.
        expect(box.width).toBeLessThanOrEqual(Math.min(460, view.width - 32) + 1);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), "the toast makes no sideways scroll").toBe(true);
      });
    });
  }
}
