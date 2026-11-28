import type {Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LAB, signIn} from "./feedback-support.ts";
import {shell} from "./notices-support.ts";

// Spec 17.3 `motion.spec.ts` (T-465, D15, 8.11), in mock mode. Two things guard motion: the lint rule `ctrlz/reduced-motion` (tools/web-lint/src/rules/
// reducedMotion.ts) and `check-css.mjs`, which read OUR classes and our CSS, and this case, which reads what the browser computes for the
// parts that are not ours: the stock HeroUI dialog, sheet, sidebar and the row hover. A lint rule cannot see a transition that a library's own
// stylesheet adds, so the one place that says "with reduced motion nothing moves" has to be a browser.
//
// Under `reducedMotion: "reduce"` the computed `transition-duration` and `animation-duration` of every element of the shell, the open dialog,
// the open sheet and a row are at the floor of base.css (0.01ms), apart from a spinner and a skeleton, which are the loops that the spec allows (8.11, 16.1). A control run
// with motion allowed shows that the check can fail: the same places do have a duration then.

const LANGS = ["fa", "en"] as const;

type Moving = {element: string; property: "transition-duration" | "animation-duration"; value: string};

// The loops that 8.11 allows: a spinner and a skeleton (HeroUI's own classes), and what sits inside them.
// base.css gives every element 0.01ms under reduced motion, not 0 (see the rule there for why); a millisecond is the line between that and motion.
const FLOOR_S = 0.001;
const ALLOWED = ".spinner, .spinner *, .skeleton, .skeleton *";

/** Every element under `root` (and `root`) whose computed duration is above the floor, apart from the loops that are allowed. */
async function moving(root: Locator): Promise<Moving[]> {
  return root.evaluate((el, {allowed, floor}) => {
    const out: {element: string; property: "transition-duration" | "animation-duration"; value: string}[] = [];
    const describe = (n: Element) => `${n.tagName.toLowerCase()}${n.className && typeof n.className === "string" ? "." + n.className.trim().split(/\s+/).slice(0, 3).join(".") : ""}`;
    for (const node of [el, ...el.querySelectorAll("*")]) {
      if (node.matches(allowed)) continue;
      const style = getComputedStyle(node);
      for (const property of ["transition-duration", "animation-duration"] as const) {
        const value = style.getPropertyValue(property);
        if (value.split(",").some((part) => parseFloat(part) > floor)) out.push({element: describe(node), property, value});
      }
    }
    return out;
  }, {allowed: ALLOWED, floor: FLOOR_S});
}

const unique = (list: Moving[]) => [...new Set(list.map((m) => `${m.element} ${m.property} ${m.value}`))].sort();

async function openDialog(page: Page, lang: (typeof LANGS)[number]) {
  const label = lang === "fa" ? "باز کردن پنجره بلند" : "Open a tall dialog";
  await page.getByRole("button", {name: label, exact: true}).click();
  await expect(page.getByRole("dialog")).toBeVisible();
}

for (const lang of LANGS) {
  test.describe(`${lang}`, () => {
    test.describe("reduced motion", () => {
      test.use({reducedMotion: "reduce", viewport: {width: 1280, height: 800}});

      test("nothing in the shell, a row, or an open dialog has a transition or an animation (T-465)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await expect(page.locator(".shell-page")).toBeVisible();
        expect(await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(true);
        // Settled: a toast or an entrance that ran before the emulation took hold would have a duration of its own.
        await page.waitForTimeout(400);
        expect(unique(await moving(page.locator(".shell"))), "the shell, the page header, the lists and the cards").toEqual([]);

        // A hovered row: the hover state is where a fill and a lift are usually animated.
        await page.locator(".shell-page [data-testid='sample-error']").hover();
        await page.getByRole("row").first().hover().catch(() => undefined);
        expect(unique(await moving(page.locator(".shell"))), "the shell under the pointer").toEqual([]);

        await openDialog(page, lang);
        await page.waitForTimeout(400);
        expect(unique(await moving(page.getByRole("dialog"))), "the open dialog").toEqual([]);
        // Its backdrop is a sibling of the dialog, not inside it.
        expect(unique(await moving(page.locator("body"))), "everything on the page with the dialog open").toEqual([]);
        // A floor of 0.01ms and not 0 is what lets React Aria see the end of the exit and take the dialog out of the page.
        await page.keyboard.press("Escape");
        await expect(page.getByRole("dialog")).toHaveCount(0);
      });
    });

    test.describe("reduced motion on a phone", () => {
      test.use({reducedMotion: "reduce", viewport: {width: 375, height: 812}});

      test("the full-screen sidebar panel (the sheet) has no transition or animation (T-465)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await page.getByRole("button", {name: shell(lang, "sidebar.openMenu")}).click();
        const panel = page.getByRole("dialog");
        await expect(panel).toBeVisible();
        await page.waitForTimeout(400);
        expect(unique(await moving(panel)), "the open sheet").toEqual([]);
        expect(unique(await moving(page.locator("body"))), "everything on the page with the sheet open").toEqual([]);
        await page.keyboard.press("Escape");
        await expect(page.getByRole("dialog")).toHaveCount(0);
      });
    });

    test.describe("motion allowed (the control)", () => {
      test.use({reducedMotion: "no-preference", viewport: {width: 1280, height: 800}});

      // Without this, an emulation that never took hold, or a selector that matched nothing, would pass the cases above.
      test("the same places do move when motion is allowed, so the check above can fail (T-465)", async ({page, context, baseURL}) => {
        await signIn(context, baseURL);
        await page.goto(LAB(lang));
        await expect(page.locator(".shell-page")).toBeVisible();
        expect(await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(false);
        await openDialog(page, lang);
        await page.waitForTimeout(400);
        const found = unique(await moving(page.locator("body")));
        expect(found.length, `elements with a duration: ${found.slice(0, 5).join("; ")}`).toBeGreaterThan(0);
      });
    });
  });
}
