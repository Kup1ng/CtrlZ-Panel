import {meFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LANGS, LAB, SCHEMES, signIn} from "./feedback-support.ts";

// Spec 17.3 `states.spec.ts` (T-121), in mock mode: the 404 inside and outside the shell,
// `SectionEmpty` (the stub pages and the lab sample with an action) and `SectionError` with its
// request id, both on the lab sample and as the session gate's error. The lab needs a server started
// with CTRLZ_LAB=1 (E2E_START_SERVER=1 sets it, see packages/ui/src/testing/config.ts).

test.beforeEach(async ({guard}, info) => {
  // The gate test and the 404 test make the browser log a failed response on purpose.
  const allowed = info.title.includes("/me fails") ? /status of 503/ : info.title.startsWith("404") ? /status of 404/ : undefined;
  if (allowed) guard.allowConsole(allowed);
});

const RETRY = {fa: "تلاش دوباره", en: "Try again"} as const;
const alertOf = (page: Page) => page.getByRole("alert").filter({has: page.locator(".empty-state")});

for (const {lang, dir} of LANGS) {
  test.describe(`${lang} (${dir})`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("SectionEmpty: a stub page has a title, a line, no action and no button", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(`/${lang}/endpoints`);
      const empty = page.locator(".empty-state");
      await expect(empty).toBeVisible();
      await expect(empty.locator(".empty-state__title")).not.toBeEmpty();
      await expect(empty.locator(".empty-state__description")).not.toBeEmpty();
      await expect(empty.locator(".empty-state__media svg")).toBeVisible();
      await expect(empty.locator(".empty-state__content")).toHaveCount(0);
      await expect(empty.getByRole("button")).toHaveCount(0);
    });

    test("SectionEmpty: the sample has its action, and the generic words come from the catalogue", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      const empty = page.getByTestId("sample-empty");
      await expect(empty.locator(".empty-state__title")).toHaveText(lang === "fa" ? "چیزی برای نمایش نیست" : "Nothing to show");
      await expect(empty.locator(".empty-state__description")).toHaveText(lang === "fa" ? "هنوز موردی اضافه نشده است." : "Nothing has been added yet.");
      await expect(empty.locator(".empty-state__content").getByRole("button")).toHaveCount(1);
    });

    test("SectionError: title, text, Retry, and the request id isolated left to right", async ({page, context, baseURL}) => {
      await signIn(context, baseURL);
      await page.goto(LAB(lang));
      const sample = page.getByTestId("sample-error");
      const alert = sample.getByRole("alert");
      await expect(alert).toBeVisible();
      await expect(alert.locator(".empty-state__title")).toHaveText(lang === "fa" ? "مشکلی پیش آمد" : "Something went wrong");
      await expect(alert.locator(".empty-state__description")).toHaveText(
        lang === "fa" ? "سرویس فعلاً در دسترس نیست. کمی بعد دوباره تلاش کنید." : "The service is not available right now. Try again shortly.",
      );
      const id = alert.locator("bdi");
      await expect(id).toHaveText("req-7f3a91c2");
      await expect(id).toHaveAttribute("dir", "ltr");
      // No stack, no URL, no raw status in the text a visitor sees.
      const text = (await alert.innerText()).toLowerCase();
      expect(text).not.toMatch(/https?:|503|stack/);
      const retries = sample;
      await expect(retries).toHaveAttribute("data-retries", "0");
      await alert.getByRole("button", {name: RETRY[lang]}).click();
      await expect(retries).toHaveAttribute("data-retries", "1");
    });

    test("SectionError is the session gate's error: a /me fails with a request id, Retry recovers", async ({page, context, baseURL}) => {
      const mock = await signIn(context, baseURL);
      mock.on("GET /me", {status: 503, body: {code: "service_unavailable", request_id: "req-gate-91", retry_after_s: 2}});
      await page.goto(`/${lang}/profiles`);
      const alert = alertOf(page);
      await expect(alert).toBeVisible({timeout: 15_000});
      await expect(alert.locator("bdi")).toHaveText("req-gate-91");
      mock.on("GET /me", {body: meFixture({user: {locale: lang}})});
      await alert.getByRole("button", {name: RETRY[lang]}).click();
      await expect(page.locator(".shell-page")).toBeVisible();
      await expect(alertOf(page)).toHaveCount(0);
    });

    test("404 inside the shell with a session, and on its own without one", async ({page, context, guard, baseURL}) => {
      guard.allowConsole(/status of 404/);
      await signIn(context, baseURL);
      const inside = await page.goto(`/${lang}/no/such/page`);
      expect(inside?.status()).toBe(404);
      await expect(page.locator("aside.sidebar")).toBeVisible();
      await expect(page.locator(".empty-state__title")).toBeVisible();

      const bare = await guard.newContext();
      const other = await bare.newPage();
      const outside = await other.goto(`/${lang}/no/such/page`);
      expect(outside?.status()).toBe(404);
      await expect(other.locator("aside.sidebar")).toHaveCount(0);
      await expect(other.locator(".empty-state__title")).toBeVisible();
      await bare.close();
    });
  });

  for (const width of [375, 768]) {
    test.describe(`${lang} at ${width}px`, () => {
      test.use({viewport: {width, height: 800}});

      test("the states fit the screen and do not scroll the page sideways", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await expect(page.getByTestId("sample-error")).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        for (const id of ["sample-empty", "sample-error"]) {
          const box = (await page.getByTestId(id).boundingBox())!;
          expect(box.x).toBeGreaterThanOrEqual(0);
          expect(box.x + box.width).toBeLessThanOrEqual(width);
        }
      });
    });
  }

  for (const scheme of SCHEMES) {
    test.describe(`${lang} ${scheme}`, () => {
      test.use({viewport: {width: 1280, height: 800}, colorScheme: scheme});

      test("axe finds nothing serious in the states", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await expect(page.getByTestId("sample-error")).toBeVisible();
        await page.waitForTimeout(500);
        await expectAccessible(page, {screen: "states"});
      });
    });
  }
}
