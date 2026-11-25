import type {Locator, Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LANGS, LAB, SCHEMES, signIn} from "./feedback-support.ts";

// Spec 8.10 (T-487), in mock mode: `ListRow` with `RowCounters` and the dense row, on the feedback
// lab. Heights and corners in the design scale, the two-line layout below md, the stretched action
// with its separate controls above it, the hover swap that never changes the row's size, and
// selection. Needs a server started with CTRLZ_LAB=1 (E2E_START_SERVER=1 sets it, see packages/ui/src/testing/config.ts).

// The shared guard (spec 17.2) already fails on an external request, a CSP violation and a console error.
test.beforeEach(async ({context, baseURL}) => {
  await signIn(context, baseURL);
});

const NAMES = {
  fa: {profile: "خانه", fresh: "پروفایل تازه", plain: "دفتر کار", rules: "قانون‌ها", ads: "ads.example.org", select: "انتخاب ردیف", enabled: "فعال", copy: "کپی"},
  en: {profile: "Home", fresh: "New profile", plain: "Office", rules: "Rules", ads: "ads.example.org", select: "Select row", enabled: "Enabled", copy: "Copy"},
} as const;

// Exact text of the title: a sub-line such as "Endpoint: home router" must not make two rows match one name.
const row = (page: Page, text: string) => page.getByRole("listitem").filter({has: page.getByText(text, {exact: true})}).first();
const css = (loc: Locator, prop: string) => loc.evaluate((el, p) => getComputedStyle(el).getPropertyValue(p), prop);
// The wrapper of the hover actions: opacity is not inherited, so it is the one that carries the swap.
const actionsOf = (r: Locator, name: string) => r.getByRole("button", {name}).locator("..");
const ready = (page: Page) => page.waitForLoadState("networkidle");

for (const {lang, dir} of LANGS) {
  const n = NAMES[lang];

  test.describe(`${lang} (${dir}) desktop`, () => {
    test.use({viewport: {width: 1280, height: 900}});

    test("a list row is 75px high with the 30px corner, and the counters sit at the inline end on the same line", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.profile);
      const box = (await r.boundingBox())!;
      expect(Math.round(box.height)).toBe(75);
      expect(await css(r, "border-radius")).toBe("30px");
      const title = (await r.locator("[data-row-main]").boundingBox())!;
      const counters = (await r.locator("ul").boundingBox())!;
      // One line: the counters are centred on the row, not under the title.
      expect(Math.abs(counters.y + counters.height / 2 - (box.y + box.height / 2))).toBeLessThan(4);
      if (dir === "rtl") expect(counters.x + counters.width).toBeLessThanOrEqual(title.x);
      else expect(counters.x).toBeGreaterThanOrEqual(title.x + title.width);
    });

    test("a click anywhere on the row opens it, and a counter opens its own tab instead", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.profile);
      const box = (await r.boundingBox())!;
      // The empty middle of the row, away from the title text and the counters.
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles$`));
      await page.goBack();
      await ready(page);
      await row(page, n.profile).getByRole("link", {name: new RegExp(n.rules)}).click();
      await expect(page).toHaveURL(/\/profiles\?tab=rules$/);
    });

    test("the counters write digits as the language does", async ({page}) => {
      await page.goto(LAB(lang));
      const text = await row(page, n.profile).locator("ul").innerText();
      if (lang === "fa") {
        expect(text).toMatch(/[۰-۹]/);
        expect(text).not.toMatch(/[0-9]/);
      } else {
        expect(text).toMatch(/1,204/);
        expect(text).not.toMatch(/[۰-۹]/);
      }
    });

    test("the keyboard reaches the row's action, shows a focus ring on the row, and Enter opens it", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const link = row(page, n.profile).locator("[data-row-main]");
      await link.focus();
      await page.keyboard.press("Shift+Tab");
      await page.keyboard.press("Tab");
      await expect(link).toBeFocused();
      const r = row(page, n.profile);
      expect(Number.parseFloat(await css(r, "outline-width"))).toBeGreaterThanOrEqual(2);
      await page.keyboard.press("Enter");
      await expect(page).toHaveURL(new RegExp(`/${lang}/profiles$`));
    });

    test("a row with no action is information only: no link, no pointer, no hover change", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const plain = row(page, n.plain);
      await expect(plain.locator("[data-row-main]")).toHaveCount(0);
      const before = await css(plain, "background-color");
      await plain.hover();
      expect(await css(plain, "background-color")).toBe(before);
      expect(await css(plain, "cursor")).not.toBe("pointer");
    });

    test("the new row is marked with a different surface, and an acting row reacts to the pointer", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const fresh = row(page, n.fresh);
      await expect(fresh).toHaveAttribute("data-highlighted", "true");
      const ordinary = row(page, n.profile);
      expect(await css(fresh, "background-color")).not.toBe(await css(ordinary, "background-color"));
      const before = await css(ordinary, "background-color");
      await ordinary.hover();
      await expect.poll(() => css(ordinary, "background-color")).not.toBe(before);
    });

    test("a dense row is 50px high with the 20px corner", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.ads);
      expect(Math.round((await r.boundingBox())!.height)).toBe(50);
      expect(await css(r, "border-radius")).toBe("20px");
    });

    test("hover swaps the tags for the actions without changing the row's size", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.ads);
      // Transparent, not display:none or visibility:hidden, so a screen reader's browse mode still finds it (wp7-r1-3).
      const actions = actionsOf(r, n.copy);
      const before = (await r.boundingBox())!;
      expect(await css(actions, "opacity")).toBe("0");
      await r.hover();
      await expect.poll(() => css(actions, "opacity")).toBe("1");
      const after = (await r.boundingBox())!;
      expect(Math.round(after.width)).toBe(Math.round(before.width));
      expect(Math.round(after.height)).toBe(Math.round(before.height));
      await page.mouse.move(2, 2);
      await expect.poll(() => css(actions, "opacity")).toBe("0");
    });

    test("a click leaves no trace: the tags are back when the pointer leaves, though the row kept focus (wp7-r1-2)", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.ads);
      const actions = actionsOf(r, n.copy);
      const tag = r.getByText(lang === "fa" ? "مسدود" : "Blocked", {exact: true});
      await r.locator("[data-row-main]").click();
      await expect(r).toHaveAttribute("data-selected", "true");
      await page.mouse.move(2, 2);
      await expect.poll(() => css(actions, "opacity")).toBe("0");
      expect(await css(tag, "visibility")).toBe("visible");
      // The mouse click focused the row's button, and that alone must not count as keyboard focus.
      await expect(r.locator("[data-row-main]")).toBeFocused();
    });

    test("the actions are in the accessibility tree while hidden, and the pointer cannot reach them (wp7-r1-3)", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.ads);
      await r.scrollIntoViewIfNeeded();
      await expect(r.getByRole("button", {name: n.copy})).toHaveCount(1);
      expect(await css(actionsOf(r, n.copy), "pointer-events")).toBe("none");
      // The row's stretched action still gets a click where the hidden actions are.
      const box = (await r.getByRole("button", {name: n.copy}).boundingBox())!;
      await page.mouse.move(2, 2);
      expect(await page.evaluate(([x, y]) => (document.elementFromPoint(x!, y!) as HTMLElement).closest("[data-row-main]") !== null, [box.x + box.width / 2, box.y + box.height / 2])).toBe(true);
    });

    test("keyboard focus on the row reveals the actions too, and they take the next Tab", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.ads);
      // Keyboard focus: Tab into the row's button from the checkbox before it, so the browser treats it as :focus-visible.
      await r.getByRole("checkbox", {name: n.select}).focus();
      await page.keyboard.press("Tab");
      await expect(r.locator("[data-row-main]")).toBeFocused();
      await expect.poll(() => css(actionsOf(r, n.copy), "opacity")).toBe("1");
      await page.keyboard.press("Tab");
      await expect(r.getByRole("button", {name: n.copy})).toBeFocused();
    });

    test("pressing a dense row selects it; the checkbox and the switch are their own controls", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.ads);
      const box = r.getByRole("checkbox", {name: n.select});
      await expect(box).not.toBeChecked();
      await r.locator("[data-row-main]").click();
      await expect(box).toBeChecked();
      await expect(r).toHaveAttribute("data-selected", "true");
      // The checkbox toggles once, not twice through the row's action behind it.
      await box.click({force: true});
      await expect(box).not.toBeChecked();
      // The switch changes itself and leaves the selection alone.
      const sw = r.getByRole("switch", {name: n.enabled});
      await expect(sw).toBeChecked();
      await sw.click({force: true});
      await expect(sw).not.toBeChecked();
      await expect(box).not.toBeChecked();
    });
  });

  test.describe(`${lang} (${dir}) touch`, () => {
    test.use({viewport: {width: 375, height: 812}, hasTouch: true, isMobile: true});

    test("on a coarse pointer, tapping a dense row selects it and shows its actions in place of the tags (wp7-r1-3)", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      expect(await page.evaluate(() => matchMedia("(pointer: coarse)").matches)).toBe(true);
      const r = row(page, n.ads);
      const actions = actionsOf(r, n.copy);
      expect(await css(actions, "opacity")).toBe("0");
      await r.locator("[data-row-main]").tap();
      await expect(r).toHaveAttribute("data-selected", "true");
      await expect.poll(() => css(actions, "opacity")).toBe("1");
      await actions.tap();
    });
  });

  test.describe(`${lang} (${dir}) tablet`, () => {
    test.use({viewport: {width: 768, height: 900}});

    test("at 768 the row is still one line of 75px", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.profile);
      expect(Math.round((await r.boundingBox())!.height)).toBe(75);
    });
  });

  test.describe(`${lang} (${dir}) phone`, () => {
    test.use({viewport: {width: 375, height: 812}});

    test("below md a list row is two lines: the counters go under the title and the row grows", async ({page}) => {
      await page.goto(LAB(lang));
      await ready(page);
      const r = row(page, n.profile);
      const box = (await r.boundingBox())!;
      expect(box.height).toBeGreaterThan(75);
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(375);
      const title = (await r.locator("[data-row-main]").boundingBox())!;
      const counters = (await r.locator("ul").boundingBox())!;
      expect(counters.y).toBeGreaterThanOrEqual(title.y + title.height);
      expect(counters.x).toBeGreaterThanOrEqual(box.x);
      expect(counters.x + counters.width).toBeLessThanOrEqual(box.x + box.width + 0.5);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      // The corner stays the capped one, so a taller row does not become a different shape.
      expect(await css(r, "border-radius")).toBe("30px");
    });
  });
}

for (const {lang} of LANGS) {
  for (const scheme of SCHEMES) {
    test.describe(`${lang} ${scheme}`, () => {
      test.use({viewport: {width: 1280, height: 900}, colorScheme: scheme});

      test("axe finds nothing serious in the rows", async ({page}) => {
        await page.goto(LAB(lang));
        await ready(page);
        await page.getByRole("listitem").first().scrollIntoViewIfNeeded();
        await page.waitForTimeout(500);
        await expectAccessible(page, {screen: "rows"});
      });
    });
  }
}
