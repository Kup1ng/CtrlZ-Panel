import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LANGS, LAB, SCHEMES, signIn} from "./feedback-support.ts";

// Spec 17.3 `dialogs.spec.ts` (T-117, T-486), in mock mode: the cases of spec 9 for `UrlModal` and
// `useUrlDialog`, on the feedback lab (`ruleDialog`, a body tall enough to scroll, a footer) and on
// the shell's own two parameters (`helpPane`, `notificationsDialog`). Needs a server started with
// CTRLZ_LAB=1 (E2E_START_SERVER=1 sets it, see packages/ui/src/testing/config.ts).

// The shared guard (spec 17.2) already fails on an external request, a CSP violation and a console error.
test.beforeEach(async ({context, baseURL}) => {
  await signIn(context, baseURL);
});

const OPEN = {fa: "باز کردن پنجره بلند", en: "Open a tall dialog"} as const;
const SWITCH = {fa: "تغییر مقدار", en: "Change the value"} as const;
const CLOSE = {fa: "بستن", en: "Close"} as const;
const DONE = {fa: "بستن پنجره", en: "Close the dialog"} as const;

const OPEN_LOCKED = {fa: "باز کردن پنجره قفل‌شده", en: "Open a locked dialog"} as const;

const dialog = (page: Page) => page.getByRole("dialog");
const opener = (page: Page, lang: "fa" | "en") => page.getByRole("button", {name: OPEN[lang]});
// Hydration attaches the click handlers after the server HTML is painted.
const ready = (page: Page) => page.waitForLoadState("networkidle");

for (const {lang} of LANGS) {
  test.describe(`${lang}: the cases of spec 9`, () => {
    test.use({viewport: {width: 1280, height: 800}});

    test("a direct link opens it, and a reload keeps it", async ({page}) => {
      await page.goto(LAB(lang, "?ruleDialog=tall"));
      await expect(dialog(page)).toBeVisible();
      await expect(page.getByTestId("dialog-value")).toHaveAttribute("data-value", "tall");
      await page.reload();
      await expect(dialog(page)).toBeVisible();
      await expect(page).toHaveURL(/ruleDialog=tall/);
    });

    test("an empty value opens nothing", async ({page}) => {
      await page.goto(LAB(lang, "?ruleDialog="));
      await ready(page);
      await expect(dialog(page)).toHaveCount(0);
    });

    test("opening pushes an entry and Back closes it", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      await opener(page, lang).click();
      await expect(dialog(page)).toBeVisible();
      await expect(page).toHaveURL(/ruleDialog=tall/);
      await page.goBack();
      await expect(dialog(page)).toBeHidden();
      await expect(page).not.toHaveURL(/ruleDialog/);
    });

    test("Escape closes it, the URL changes, and focus returns to the opener", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const button = opener(page, lang);
      await button.click();
      await expect(dialog(page)).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(dialog(page)).toBeHidden();
      await expect(page).not.toHaveURL(/ruleDialog/);
      await expect(button).toBeFocused();
    });

    test("focus returns to the opener after Back, the close button and the footer button too (wp7-r1-5)", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const button = opener(page, lang);
      const closers: Array<() => Promise<unknown>> = [
        () => page.goBack(),
        () => dialog(page).getByRole("button", {name: CLOSE[lang], exact: true}).click(),
        () => dialog(page).getByRole("button", {name: DONE[lang]}).click(),
      ];
      for (const close of closers) {
        await button.click();
        await expect(dialog(page)).toBeVisible();
        await close();
        await expect(dialog(page)).toBeHidden();
        await expect(button).toBeFocused();
      }
    });

    test("Tab and Shift+Tab stay inside the open dialog (wp7-r1-5)", async ({page}) => {
      await page.goto(LAB(lang, "?ruleDialog=tall"));
      await expect(dialog(page)).toBeVisible();
      const inside = () => dialog(page).evaluate((el) => el.contains(document.activeElement));
      // More presses than the dialog has controls (close, the switch of the value, the footer), so the trap has to wrap.
      for (let i = 0; i < 7; i++) {
        await page.keyboard.press("Tab");
        expect(await inside(), `Tab ${i + 1}`).toBe(true);
      }
      for (let i = 0; i < 7; i++) {
        await page.keyboard.press("Shift+Tab");
        expect(await inside(), `Shift+Tab ${i + 1}`).toBe(true);
      }
    });

    test("a frame that is not dismissable ignores Escape and a click outside, and its own button closes it (wp7-r1-5)", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const button = page.getByRole("button", {name: OPEN_LOCKED[lang]});
      await button.click();
      await expect(dialog(page)).toBeVisible();
      await page.keyboard.press("Escape");
      await page.mouse.click(4, 4);
      await page.waitForTimeout(300);
      await expect(dialog(page)).toBeVisible();
      // State only: nothing of it is in the address bar.
      expect(new URL(page.url()).search).toBe("");
      await dialog(page).getByRole("button", {name: DONE[lang]}).click();
      await expect(dialog(page)).toBeHidden();
      await expect(button).toBeFocused();
    });

    test("the close button and the footer button close it the same way", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      await opener(page, lang).click();
      await dialog(page).getByRole("button", {name: CLOSE[lang], exact: true}).click();
      await expect(dialog(page)).toBeHidden();
      await expect(page).not.toHaveURL(/ruleDialog/);
      await opener(page, lang).click();
      await dialog(page).getByRole("button", {name: DONE[lang]}).click();
      await expect(dialog(page)).toBeHidden();
      await expect(page).not.toHaveURL(/ruleDialog/);
    });

    test("closing a dialog reached by a direct link keeps the visitor in the app", async ({page}) => {
      await page.goto(LAB(lang, "?ruleDialog=tall"));
      await expect(dialog(page)).toBeVisible();
      await dialog(page).getByRole("button", {name: DONE[lang]}).click();
      await expect(dialog(page)).toBeHidden();
      // back() here would have left for about:blank: the entry before is the app's own and there is none.
      await expect(page).toHaveURL(new RegExp(`/${lang}/feedback-lab$`));
    });

    test("opening one that is open changes its value and adds no history entry", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      await opener(page, lang).click();
      await dialog(page).getByRole("button", {name: SWITCH[lang]}).click();
      await expect(page).toHaveURL(/ruleDialog=second/);
      await expect(page.getByTestId("dialog-value")).toHaveAttribute("data-value", "second");
      // One Back leaves the dialog, and does not land on it again with the first value.
      await page.goBack();
      await expect(dialog(page)).toBeHidden();
      await expect(page).not.toHaveURL(/ruleDialog/);
    });

    test("other parameters and the fragment survive an open and a close", async ({page}) => {
      await page.goto(LAB(lang, "?a=1#x"));
      await ready(page);
      await opener(page, lang).click();
      await expect(dialog(page)).toBeVisible();
      await expect(page).toHaveURL(/\?a=1&ruleDialog=tall#x$/);
      await page.keyboard.press("Escape");
      await expect(page).toHaveURL(/\?a=1#x$/);
    });

    test("the shell's help pane and bell are the same frame, and an unknown help key opens nothing", async ({page}) => {
      await page.goto(`/${lang}/profiles?helpPane=nonsense`);
      await ready(page);
      await expect(dialog(page)).toHaveCount(0);
      await page.goto(`/${lang}/profiles?helpPane=profiles`);
      await expect(dialog(page)).toBeVisible();
      await expect.poll(async () => Math.round((await dialog(page).boundingBox())!.width)).toBe(440);
      await page.keyboard.press("Escape");
      await expect(dialog(page)).toBeHidden();
      await page.goto(`/${lang}/profiles?notificationsDialog=1`);
      await expect(dialog(page)).toBeVisible();
    });

    test("the dialog is about 440px wide at 1280 and dims the page behind it", async ({page}) => {
      await page.goto(LAB(lang, "?ruleDialog=tall"));
      await expect(dialog(page)).toBeVisible();
      await expect.poll(async () => Math.round((await dialog(page).boundingBox())!.width)).toBe(440);
      const box = (await dialog(page).boundingBox())!;
      const centre = box.x + box.width / 2;
      // Centred in the viewport, not in the content column next to the sidebar.
      expect(Math.abs(centre - 640)).toBeLessThanOrEqual(2);
      const backdrop = await page.locator(".modal__backdrop").evaluate((el) => getComputedStyle(el).backgroundColor);
      expect(backdrop).not.toBe("rgba(0, 0, 0, 0)");
      expect(backdrop).not.toBe("transparent");
    });

    test("the body scrolls inside while the header and the footer stay", async ({page}) => {
      await page.setViewportSize({width: 1280, height: 420});
      await page.goto(LAB(lang, "?ruleDialog=tall"));
      await expect(dialog(page)).toBeVisible();
      // The dialog slides in; measure only once it has stopped moving, or "the footer stays" compares a frame of the animation.
      let last = -1;
      await expect
        .poll(async () => {
          const y = (await dialog(page).boundingBox())!.y;
          const still = y === last;
          last = y;
          return still;
        })
        .toBe(true);
      const body = page.locator(".modal__body");
      const footer = dialog(page).getByRole("button", {name: DONE[lang]});
      const metrics = await body.evaluate((el) => ({scroll: el.scrollHeight, client: el.clientHeight}));
      expect(metrics.scroll).toBeGreaterThan(metrics.client + 100);
      const dialogBox = (await dialog(page).boundingBox())!;
      expect(dialogBox.y).toBeGreaterThanOrEqual(0);
      expect(dialogBox.y + dialogBox.height).toBeLessThanOrEqual(420);
      const before = (await footer.boundingBox())!;
      expect(before.y + before.height).toBeLessThanOrEqual(420);
      await body.evaluate((el) => (el.scrollTop = el.scrollHeight));
      expect(await body.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
      const after = (await footer.boundingBox())!;
      expect(Math.round(after.y)).toBe(Math.round(before.y));
      await expect(page.getByRole("heading", {name: lang === "fa" ? "پنجره نمونه" : "Sample dialog"})).toBeInViewport();
    });
  });

  test.describe(`${lang}: widths`, () => {
    for (const width of [375, 768]) {
      test(`the dialog fits a ${width}px screen with the footer in view`, async ({page}) => {
        await page.setViewportSize({width, height: 700});
        await page.goto(LAB(lang, "?ruleDialog=tall"));
        await expect(dialog(page)).toBeVisible();
        await page.waitForTimeout(400);
        const box = (await dialog(page).boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(width);
        expect(box.width).toBeLessThanOrEqual(440);
        const footer = (await dialog(page).getByRole("button", {name: DONE[lang]}).boundingBox())!;
        expect(footer.y + footer.height).toBeLessThanOrEqual(700);
        // The page behind does not scroll sideways because of it.
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      });
    }
  });
}

for (const {lang} of LANGS) {
  for (const scheme of SCHEMES) {
    test.describe(`${lang} ${scheme}`, () => {
      test.use({viewport: {width: 1280, height: 800}, colorScheme: scheme});

      test("axe finds nothing serious with the dialog open", async ({page}) => {
        await page.goto(LAB(lang, "?ruleDialog=tall"));
        await expect(dialog(page)).toBeVisible();
        await page.waitForTimeout(500);
        await expectAccessible(page, {screen: "dialogs"});
      });
    });
  }
}
