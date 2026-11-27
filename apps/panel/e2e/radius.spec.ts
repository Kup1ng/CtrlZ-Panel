import type {Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {COMPONENT_SELECTORS} from "../../../packages/ui/src/lab/samples.ts";
import {rows, type Row} from "../../../packages/ui/tokens/radius.table.ts";
import {signIn} from "./feedback-support.ts";

// Spec 6.3 (T-474). The radius table is one file, tokens/radius.table.ts, and this spec reads that same file:
// it opens the token lab, which draws one sample of every row, and checks each row against what the browser
// computed. The numbers are never typed here.
//
//   control row   the rendered height is the table's height (0.5px), and the corner is min(0.4 x height, 30px)
//                 (0.1px). A row with an `exception` (D47: the switch track and thumb) is fully round instead:
//                 every corner is at least half the height.
//   box row       the corner is exactly 20px on the corners the row names.
//   a box        is measured at two heights where it is bare markup (`h-8` and `h-40`),
//                 and every box element has to be rendered (height above 0), so that a corner is never read from an
//                 element that draws nothing.
//   the split    a row is a real component exactly when samples.ts lists it. A selector that the table renamed
//                 would fall back to bare markup and still pass the radius check, so the split is asserted.
//   .control-50   is 50px high with a 20px corner, and .control-75 is 75px with 30px (D16's own examples).
//
// It runs in Flat, light and dark, in fa and en, at 375, 768 and 1280: 12 cases, each a load of the lab. The
// server must run with CTRLZ_LAB=1 (the lab is closed otherwise), after `next build`:
//
//   CTRLZ_LAB=1 pnpm exec next start -p 3410
//   E2E_BASE_URL=http://localhost:3410 pnpm exec playwright test e2e/radius.spec.ts
//
// The table's heights are CSS expressions (`calc(var(--spacing) * 9)`, `var(--size-50)`), so the page resolves
// them itself: a probe element gets the expression as its height and is measured, with the same --spacing, the
// same rem and the same custom properties as the sample.

const WIDTHS = [375, 768, 1280] as const;
const HEIGHTS = {375: 812, 768: 1024, 1280: 800} as const;
const LANGS = ["fa", "en"] as const;
const MODES = ["light", "dark"] as const;

// What the page reports for one row. Plain data, so it crosses from the browser.
type Measured = {
  index: number;
  selector: string;
  sample: string | null;
  expectedHeight: number;
  items: {height: number; corners: [number, number, number, number]}[];
};

// The table, as the browser function receives it: only what it needs.
type RowInput = Pick<Row, "kind" | "selector"> & {index: number; height?: {base: string; sm?: string; md?: string}};

async function openTokenLab(page: Page, baseURL: string, lang: (typeof LANGS)[number], mode: (typeof MODES)[number]) {
  await page.context().addCookies([{name: "ctrlz_theme", value: mode, url: baseURL}]);
  // The mocked /me says the user's theme is "system", and the server's value wins over the cookie once /me has
  // answered (spec 5.1), so "system" has to resolve to the mode under test. Reduced motion stops the tab
  // indicator and the sheet's entrance from being measured half way.
  await page.emulateMedia({colorScheme: mode, reducedMotion: "reduce"});
  await page.goto(`/${lang}/token-lab`);
  await page.evaluate(() => document.fonts.ready);
  const html = page.locator("html");
  await expect(html).toHaveAttribute("lang", lang);
  await expect(html).toHaveAttribute("dir", lang === "fa" ? "rtl" : "ltr");
  await expect(html).toHaveAttribute("data-theme", mode, {timeout: 30_000});
  await expect(html).toHaveClass(new RegExp(`\\bflat-${mode}\\b`));
  // The page sits behind the session gate, so its content appears once /me has answered.
  await page.locator("[data-radius-row]").first().waitFor();
}

async function measure(page: Page, input: RowInput[]): Promise<Measured[]> {
  // Written inside the page function: the page's CSP forbids eval, so a helper cannot be passed in.
  return page.evaluate((rowsArg) => {
    const width = window.innerWidth;
    // 40rem and 48rem are the table's `sm` and `md` (gen-radius.mjs), and rem is 16px unless the page says
    // otherwise, so the media queries and the probe agree.
    const rem = parseFloat(getComputedStyle(document.documentElement).fontSize);
    const pick = (h: {base: string; sm?: string; md?: string}) => {
      let expr = h.base;
      if (h.sm !== undefined && width >= 40 * rem) expr = h.sm;
      if (h.md !== undefined && width >= 48 * rem) expr = h.md;
      return expr;
    };
    const probeHeight = (host: Element, expr: string) => {
      const probe = document.createElement("div");
      probe.style.position = "absolute";
      probe.style.visibility = "hidden";
      probe.style.width = "1px";
      probe.style.height = expr;
      host.appendChild(probe);
      const h = probe.getBoundingClientRect().height;
      probe.remove();
      return h;
    };
    return rowsArg.map(({index, selector, height}) => {
      const cell = document.querySelector(`[data-radius-row="${index}"]`);
      if (!cell) return {index, selector, sample: null, expectedHeight: NaN, items: []};
      const items = [...cell.querySelectorAll(selector)].map((el) => {
        const cs = getComputedStyle(el);
        const corners = [cs.borderTopLeftRadius, cs.borderTopRightRadius, cs.borderBottomRightRadius, cs.borderBottomLeftRadius].map(parseFloat);
        return {height: el.getBoundingClientRect().height, corners: corners as [number, number, number, number]};
      });
      return {
        index,
        selector,
        sample: cell.getAttribute("data-sample"),
        expectedHeight: height ? probeHeight(cell, pick(height)) : NaN,
        items,
      };
    });
  }, input);
}

const components = new Set<string>(COMPONENT_SELECTORS);
const live = rows.map((row, index) => ({row, index}));
const input: RowInput[] = live.map(({row, index}) => ({
  index,
  kind: row.kind,
  selector: row.selector,
  height: row.kind === "control" ? row.height : undefined,
}));

// Which corners a box row rounds, by index in [top-left, top-right, bottom-right, bottom-left].
const CORNER_INDEXES = {all: [0, 1, 2, 3], top: [0, 1], bottom: [2, 3], left: [0, 3], right: [1, 2]} as const;

test.beforeEach(async ({context, baseURL}) => {
  await signIn(context, baseURL);
});

for (const width of WIDTHS) {
  for (const lang of LANGS) {
    for (const mode of MODES) {
      test(`radius table, ${mode}, ${lang}, ${width}px: every row measures what the table says`, async ({page, baseURL}) => {
        await page.setViewportSize({width, height: HEIGHTS[width]});
        await openTokenLab(page, baseURL!, lang, mode);
        const measured = await measure(page, input);
        const byIndex = new Map(measured.map((m) => [m.index, m]));

        // The lab draws every row the generator emits, and every sample holds the element its selector names.
        expect(measured.length, "rows measured").toBe(live.length);
        const missing = measured.filter((m) => m.items.length === 0).map((m) => m.selector);
        expect(missing, "rows whose sample holds no element for the selector").toEqual([]);

        // Every row is checked, and a failure names the row, so the report shows all of them and not the first.
        const failures: string[] = [];
        const check = (ok: boolean, message: string) => {
          if (!ok) failures.push(message);
        };

        for (const {row, index} of live) {
          const m = byIndex.get(index)!;
          const label = `${row.selector} [${m.sample}]`;
          check(m.sample === (components.has(row.selector) ? "component" : "markup"), `${label} is drawn as the wrong kind of sample`);
          if (row.kind === "box") {
            m.items.forEach((item, k) => check(item.height > 0, `${label} #${k} is not rendered (height ${item.height}px)`));
            if (m.sample === "markup") {
              const heights = m.items.map((item) => item.height);
              check(Math.max(...heights) - Math.min(...heights) >= 20, `${label} is measured at one height only (${heights.join(", ")}px)`);
            }
            const want = CORNER_INDEXES[row.corners ?? "all"];
            m.items.forEach((item, k) => {
              for (const c of want) check(Math.abs(item.corners[c]! - 20) <= 0.01, `${label} #${k} corner ${c} is ${item.corners[c]}px, a box is 20px`);
            });
            continue;
          }
          m.items.forEach((item, k) => {
            const where = `${label} #${k} (${item.height}px)`;
            check(Math.abs(item.height - m.expectedHeight) <= 0.5, `${where} is not the table's ${m.expectedHeight}px`);
            if (row.exception) {
              // D47: a pill. The computed corner is a huge number, so "at least half the height" is the test.
              for (const c of item.corners) check(c >= item.height / 2, `${where} corner ${c}px is not a pill`);
            } else {
              // 0.4 of the rendered height. For a textarea the row keeps the one-line field's radius (spec 6.1),
              // which is 0.4 of the table's height, so its rendered height is measured too, and the sample is a
              // single row for that reason.
              const want = Math.min(0.4 * item.height, 30);
              check(Math.abs(item.corners[0]! - want) <= 0.1, `${where} corner ${item.corners[0]}px, the rule gives ${want}px`);
            }
          });
        }

        // D16's examples, from the rendered pixels and not through the formula.
        for (const [selector, h, r] of [[".control-50", 50, 20], [".control-75", 75, 30]] as const) {
          const m = measured.find((x) => x.selector === selector);
          check(m !== undefined && m.items.length > 0, `${selector} is on the lab`);
          for (const item of m?.items ?? []) {
            check(Math.abs(item.height - h) <= 0.5, `${selector} is ${item.height}px, not ${h}px`);
            check(Math.abs(item.corners[0]! - r) <= 0.1, `${selector} corner is ${item.corners[0]}px, not ${r}px`);
          }
        }

        // RADIUS_REPORT=1 prints one line per row, to read what was measured and not only that it passed.
        if (process.env.RADIUS_REPORT === "1") {
          for (const m of measured) {
            const first = m.items[0];
            console.log(`${m.sample === "component" ? "C" : "M"} ${m.items.length}x ${m.selector}  h=${first?.height.toFixed(2)} want=${Number.isNaN(m.expectedHeight) ? "box" : m.expectedHeight.toFixed(2)} r=${first?.corners.map((c) => (c > 1e6 ? "pill" : c.toFixed(2))).join("/")}`);
          }
        }

        expect(failures, "rows that differ from the table").toEqual([]);

        // The lab has to fit the screen too: the page, its main region and the lists inside it do not scroll sideways.
        const overflow = await page.evaluate(() => {
          const over = (el: Element | null) => (el ? el.scrollWidth - el.clientWidth : 0);
          return {document: over(document.documentElement), main: over(document.querySelector("main"))};
        });
        expect(overflow.document, "document overflow in px").toBeLessThanOrEqual(0);
        expect(overflow.main, "main overflow in px").toBeLessThanOrEqual(0);

        test.info().annotations.push({
          type: "samples",
          description: `${measured.filter((m) => m.sample === "component").length} components, ${measured.filter((m) => m.sample === "markup").length} bare markup`,
        });
      });
    }
  }
}
