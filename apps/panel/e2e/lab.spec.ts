import type {Page} from "@playwright/test";
import {expectAccessible} from "@ctrlz/ui/testing/axe.ts";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {signIn} from "./feedback-support.ts";

// Spec 8.10 and 5.3, 6.3. What the lab pages prove, now that the theme lab is gone (D17, T-485):
// the 5,000-row virtual lists, an accessibility pass over them, and the colour and radius tokens
// that a page of ours has to show (the chart palette, the off switch in dark, the tile radii).
//
// The server must run with CTRLZ_LAB=1, E2E_MODE=lab picks the lab project (one worker), and the numbers
// mean something only against a production build (`next build`, `next start`): a dev server compiles on
// the first hit and is slower. The token-lab of spec 6.3 holds the rest of the radius rows (radius.spec.ts); the strip on the virtual-lab
// (packages/ui/src/lab/TokenStrip.tsx) holds the few that moved here.

const MODES = ["light", "dark"] as const;
// The button that builds the virtualised grid in the browser (it stays off the server render).
const BUILD_BUTTON = {fa: "ساخت جدول", en: "Build the grid"} as const;

// External requests, CSP violations and console errors fail every test through the shared guard (spec 17.2).

// The lab pages sit in the tenant shell, whose session gate asks /me (WP4). Without an answer it logged
// a 404 and the page never reached its content, so this file fails in any mode since WP4 added the gate.
// The mock answers it as a signed-in tenant.
test.beforeEach(async ({context, baseURL}) => {
  await signIn(context, baseURL);
});

async function openLab(page: Page, baseURL: string, lang: "fa" | "en", mode: "light" | "dark", query = "") {
  // The cookie is what the server renders the theme from, so the first byte already has the class.
  await page.context().addCookies([{name: "ctrlz_theme", value: mode, url: baseURL}]);
  // The mocked /me says the user's theme is "system", and the server's value wins over the cookie once
  // /me has answered (spec 5.1). "System" must then resolve to the mode under test.
  await page.emulateMedia({colorScheme: mode});
  await page.goto(`/${lang}/virtual-lab${query}`);
  await page.evaluate(() => document.fonts.ready);
  const html = page.locator("html");
  await expect(html).toHaveAttribute("lang", lang);
  await expect(html).toHaveAttribute("dir", lang === "fa" ? "rtl" : "ltr");
  // The names on <html> are the Flat names of spec 5.2: the stock class, the set class, data-theme.
  await expect(html).toHaveAttribute("data-theme", mode, {timeout: 30_000});
  await expect(html).toHaveClass(new RegExp(`\\b${mode}\\b`));
  await expect(html).toHaveClass(new RegExp(`\\bflat-${mode}\\b`));
  // The page sits behind the session gate, which shows its content only once /me has answered. The
  // checks that follow read the DOM at once, so they wait for the token strip first.
  await page.locator('[data-shapes="switch"]').waitFor();
}

// ---- Tokens ---------------------------------------------------------------------------------

for (const mode of MODES) {
  test(`tokens, ${mode}: one chart identity, no sparkline fill, off switch cue, token radii`, async ({page, baseURL}) => {
    await page.setViewportSize({width: 1280, height: 900});
    await openLab(page, baseURL!, "fa", mode);
    // The sparkline draws over about 1.5 seconds.
    await page.waitForTimeout(2200);

    // DESIGN Q7: chart-3 is the accent in light and in dark.
    const chart3 = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--chart-3").trim().toLowerCase());
    expect(chart3).toBe("#04b5fb");
    const stroke = await page.locator(".kpi__chart .recharts-area-curve").first().evaluate((el) => getComputedStyle(el).stroke);
    expect(stroke).toBe("rgb(4, 181, 251)");

    // DESIGN.md allows no gradient at all (Flat has no page wash): the area under the line is off.
    const fills = await page.locator(".kpi__chart .recharts-area-area").evaluateAll((els) => els.map((el) => getComputedStyle(el).fill));
    expect(fills.length).toBeGreaterThan(0);
    for (const f of fills) expect(f).toBe("none");

    // The off switch is not the loudest thing in the row: in dark its thumb is no longer white.
    const thumbs = await page.locator('.switch:not([data-selected="true"]):not([data-disabled="true"]) .switch__thumb').evaluateAll((els) => els.map((el) => getComputedStyle(el).backgroundColor));
    expect(thumbs.length).toBeGreaterThan(0);
    if (mode === "dark") for (const c of thumbs) expect(c).not.toBe("rgb(255, 255, 255)");

    // The tiles take their radius from the table: min(0.4 x height, 30px), not from a typed number.
    const tiles = await page.locator(".tile-11, .tile-6").evaluateAll((els) =>
      els.map((el) => ({h: el.getBoundingClientRect().height, r: parseFloat(getComputedStyle(el).borderTopLeftRadius)})),
    );
    expect(tiles.length).toBe(2);
    for (const t of tiles) expect(Math.abs(t.r - Math.min(0.4 * t.h, 30))).toBeLessThan(0.6);
  });
}

// D47 (owner, 2026-11-07): the switch track and thumb are pills, like stock HeroUI. Avatars, the
// checkbox and the header buttons keep the 0.4 rule of D16, and so do the tiles. Both halves are
// asserted from computed styles, in both modes, on every size the strip draws.
for (const mode of MODES) {
  test(`switch radius, ${mode}: track and thumb are pills at every size, the cell switch follows, the rest keep 0.4 x height`, async ({page, baseURL}) => {
    await page.setViewportSize({width: 1280, height: 900});
    await openLab(page, baseURL!, "fa", mode);

    const rule = (h: number) => Math.min(0.4 * h, 30);

    // Rows of the strip are sm, md, lg. Each holds four switches: off, on, and both disabled.
    // The reader is written inside the page function: the page's CSP forbids eval, so it cannot be passed in.
    const sizes = await page.locator('[data-shapes="switch"] > div').evaluateAll((rowEls) => {
      const read = (el: Element) => {
        const cs = getComputedStyle(el);
        const r = el.getBoundingClientRect();
        const corners = [cs.borderTopLeftRadius, cs.borderTopRightRadius, cs.borderBottomRightRadius, cs.borderBottomLeftRadius].map(parseFloat);
        return {w: r.width, h: r.height, corners};
      };
      return rowEls.map((row) => ({
        controls: [...row.querySelectorAll(".switch__control")].map(read),
        thumbs: [...row.querySelectorAll(".switch__thumb")].map(read),
      }));
    });
    expect(sizes.length, "switch sizes on the strip").toBe(3);
    for (const [i, name] of ["sm", "md", "lg"].entries()) {
      const {controls, thumbs} = sizes[i]!;
      expect(controls.length, `${name} controls`).toBe(4);
      expect(thumbs.length, `${name} thumbs`).toBe(4);
      // Fully round: every corner is at least half the rendered height. A 0.4 rule track would be 0.4 x height.
      for (const c of controls) for (const r of c.corners) expect(r, `${name} track corner`).toBeGreaterThanOrEqual(c.h / 2);
      for (const t of thumbs) for (const r of t.corners) expect(r, `${name} thumb corner`).toBeGreaterThanOrEqual(t.h / 2);
      // Not a 0.4 x height rectangle by accident of the numbers: the rule would give less than half.
      for (const c of controls) expect(c.corners[0]!, `${name} track is above the rule`).toBeGreaterThan(rule(c.h) + 0.5);
    }
    // The three rows really are three different sizes.
    const heights = sizes.map((s) => s.controls[0]!.h);
    expect(heights[0]!).toBeLessThan(heights[1]!);
    expect(heights[1]!).toBeLessThan(heights[2]!);

    // CellSwitch: its row follows the rule (it is a field), the track inside is the stock switch and is a pill.
    const cell = await page.evaluate(() => {
      const trigger = document.querySelector(".cell-switch__trigger")!;
      const track = document.querySelector(".cell-switch__control")!;
      const thumb = track.querySelector(".switch__thumb")!;
      const px = (el: Element) => parseFloat(getComputedStyle(el).borderTopLeftRadius);
      return {
        isStockTrack: track.classList.contains("switch__control"),
        trigger: {h: trigger.getBoundingClientRect().height, r: px(trigger)},
        track: {h: track.getBoundingClientRect().height, r: px(track)},
        thumb: {h: thumb.getBoundingClientRect().height, r: px(thumb)},
      };
    });
    expect(cell.isStockTrack, "CellSwitch.Control is a .switch__control").toBe(true);
    expect(Math.abs(cell.trigger.r - rule(cell.trigger.h)), "cell switch row follows 0.4 x height").toBeLessThan(0.6);
    expect(cell.track.r, "cell switch track").toBeGreaterThanOrEqual(cell.track.h / 2);
    expect(cell.thumb.r, "cell switch thumb").toBeGreaterThanOrEqual(cell.thumb.h / 2);

    // Avatars (three sizes) and the checkbox are not exceptions: 0.4 x height, capped at 30.
    const others = await page.evaluate(() => {
      const px = (el: Element) => parseFloat(getComputedStyle(el).borderTopLeftRadius);
      const pick = (sel: string) => [...document.querySelectorAll(sel)].map((el) => ({h: el.getBoundingClientRect().height, r: px(el)}));
      return {avatars: pick('[data-shapes="avatar-checkbox"] .avatar'), checkboxes: pick('[data-shapes="avatar-checkbox"] .checkbox__control')};
    });
    expect(others.avatars.length, "avatars on the strip").toBe(3);
    expect(others.checkboxes.length, "checkboxes on the strip").toBe(2);
    for (const a of [...others.avatars, ...others.checkboxes]) expect(Math.abs(a.r - rule(a.h)), `radius ${a.r} of a ${a.h}px control`).toBeLessThan(0.6);
  });
}

// ---- Rules carried over from the Glass theme (glass-carryover.css, spec 5.4) --------------------

// The same markup HeroUI renders is put on the page and the computed values are read, because the
// lab has no toggle button, badge, tooltip or pinned column of its own. The expected values are
// written as CSS and resolved by the browser, so they follow the tokens in both modes.
//
// What each assertion catches was measured, not assumed: the carried-over import was commented out,
// the panel rebuilt, and the same probe run. These values changed (stock on the right):
//   toggle-button selected   accent fill, dark text      -> accent at 15% alpha, accent text
//   toggle-button hover      accent-hover                -> accent at 16 to 20% alpha
//   badge, number-field btn  border none                 -> 1px solid
//   .table__header           surface-secondary at 1%     -> opaque surface-secondary
//   secondary table pinned   surface                     -> a different off-white (surface-secondary mix)
//   .chart-tooltip           background-secondary, no border -> surface fill, 1px border
//   .item-card-group         overflow hidden             -> visible
//   .widget__content         no shadow                   -> two-layer shadow
//   carousel buttons         mix-blend-mode difference   -> normal
//   .emoji-picker__footer    z-index 10, relative        -> auto, absolute
// The pinned header, the pinned cell and its hover and selected mixes did NOT change: in Flat the
// stock rules already give the same colours, so those rules are inert today. Their assertions below
// guard the variables (`--pinned-surface*` read with no fallback, so an undefined one turns the
// cell transparent), not the deletion of the rules; the unit test of glass-carryover.css holds
// their selectors.
for (const mode of MODES) {
  test(`carried-over rules, ${mode}: every rule with an effect in Flat still computes, and the pinned variables resolve`, async ({page, baseURL}) => {
    await page.setViewportSize({width: 1280, height: 900});
    await openLab(page, baseURL!, "fa", mode);

    const r = await page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const colourOf = (css: string) => {
        const probe = document.createElement("div");
        probe.style.backgroundColor = css;
        document.body.append(probe);
        const value = getComputedStyle(probe).backgroundColor;
        probe.remove();
        return value;
      };
      const host = document.createElement("div");
      host.dataset.slot = "data-grid";
      host.innerHTML =
        '<div class="number-field"><button id="nf" class="number-field__increment-button" type="button">+</button></div>' +
        '<button id="tg" class="toggle-button" data-selected="true" type="button">t</button>' +
        '<button id="tgh" class="toggle-button" data-selected="true" data-hovered="true" type="button">t</button>' +
        '<span id="badge" class="badge">b</span>' +
        '<table><thead id="th" class="table__header"><tr><th id="col" class="table__column" data-pinned="true">h</th></tr></thead>' +
        '<tbody><tr class="table__row"><td id="cell" class="table__cell" data-pinned="true">c</td></tr>' +
        '<tr class="table__row" data-hovered="true"><td id="cellhover" class="table__cell" data-pinned="true">c</td></tr>' +
        '<tr class="table__row" data-selected="true"><td id="cellsel" class="table__cell" data-pinned="true">c</td></tr></tbody></table>' +
        '<div class="table-root--secondary"><table><tbody><tr class="table__row"><td id="cellsec" class="table__cell" data-pinned="true">c</td></tr></tbody></table></div>' +
        '<div id="tip" class="chart-tooltip">x</div>' +
        '<div id="icg" class="item-card-group--default">x</div>' +
        '<div id="wid" class="widget__content">x</div>' +
        '<div class="carousel"><button id="car" class="carousel__previous" type="button">x</button></div>' +
        '<div id="emoji" class="emoji-picker__footer">x</div>';
      document.body.append(host);
      const cs = (id: string) => getComputedStyle(host.querySelector("#" + id)!);
      const out = {
        pinnedSurface: root.getPropertyValue("--pinned-surface").trim(),
        pinnedSurfaceSecondary: root.getPropertyValue("--pinned-surface-secondary").trim(),
        expected: {
          surface: colourOf("var(--surface)"),
          surfaceSecondary: colourOf("var(--surface-secondary)"),
          accent: colourOf("var(--accent)"),
          accentHover: colourOf("var(--accent-hover)"),
          accentForeground: colourOf("var(--accent-foreground)"),
          backgroundSecondary: colourOf("var(--background-secondary)"),
          header: colourOf("color-mix(in oklab, var(--surface-secondary) 1%, transparent)"),
          pinnedHover: colourOf("color-mix(in oklch, var(--pinned-surface) 40%, var(--pinned-surface-secondary))"),
          pinnedSelected: colourOf("color-mix(in oklch, var(--pinned-surface) 10%, var(--pinned-surface-secondary))"),
        },
        toggle: {bg: cs("tg").backgroundColor, fg: cs("tg").color, hoverBg: cs("tgh").backgroundColor},
        numberFieldBorder: cs("nf").borderTopStyle,
        badgeBorder: cs("badge").borderTopStyle,
        header: cs("th").backgroundColor,
        pinnedColumn: cs("col").backgroundColor,
        pinnedCell: cs("cell").backgroundColor,
        pinnedHover: cs("cellhover").backgroundColor,
        pinnedSelected: cs("cellsel").backgroundColor,
        pinnedSecondary: cs("cellsec").backgroundColor,
        tooltip: {bg: cs("tip").backgroundColor, border: cs("tip").borderTopStyle},
        itemCardGroupOverflow: cs("icg").overflow,
        widgetShadow: cs("wid").boxShadow,
        carouselBlend: cs("car").mixBlendMode,
        emoji: {zIndex: cs("emoji").zIndex, position: cs("emoji").position},
      };
      host.remove();
      return out;
    });

    // The variables the DataGrid rules read with no fallback.
    expect(r.pinnedSurface, "--pinned-surface on the Flat class").not.toBe("");
    expect(r.pinnedSurfaceSecondary, "--pinned-surface-secondary on the Flat class").not.toBe("");
    expect(r.pinnedColumn, "pinned column header").toBe(r.expected.surfaceSecondary);
    expect(r.pinnedCell, "pinned cell").toBe(r.expected.surface);
    expect(r.pinnedHover, "pinned cell in a hovered row").toBe(r.expected.pinnedHover);
    expect(r.pinnedSelected, "pinned cell in a selected row").toBe(r.expected.pinnedSelected);

    // Rules whose deletion changes the computed value (see the table above).
    expect(r.pinnedSecondary, "pinned cell of the secondary table").toBe(r.expected.surface);
    expect(r.toggle.bg, "selected toggle button").toBe(r.expected.accent);
    expect(r.toggle.fg, "selected toggle button text").toBe(r.expected.accentForeground);
    expect(r.toggle.hoverBg, "selected toggle button, hovered").toBe(r.expected.accentHover);
    expect(r.numberFieldBorder, "number field button border").toBe("none");
    expect(r.badgeBorder, "badge border").toBe("none");
    expect(r.header, "table header, 1% of surface-secondary").toBe(r.expected.header);
    expect(r.tooltip.bg, "chart tooltip fill").toBe(r.expected.backgroundSecondary);
    expect(r.tooltip.border, "chart tooltip border").toBe("none");
    expect(r.itemCardGroupOverflow, "item card group clips").toBe("hidden");
    expect(r.widgetShadow, "widget content shadow").toBe("none");
    expect(r.carouselBlend, "carousel button blend").toBe("difference");
    expect(r.emoji, "emoji picker footer").toEqual({zIndex: "10", position: "relative"});
  });
}

// ---- Number format of the token strip -----------------------------------------------------------

// What the reader sees is asserted, not the prop: dropping `locale` from TokenStrip does not change the text today
// (the app's I18nProvider already gives NumberValue the language), and this fails if that stops being so.
for (const [lang, text] of [["fa", "۱۲۸٬۴۵۰"], ["en", "128,450"]] as const) {
  test(`token strip number, ${lang}: written in the language's own digits`, async ({page, baseURL}) => {
    await page.setViewportSize({width: 1280, height: 900});
    await openLab(page, baseURL!, lang, "light", "?rows=100");
    await expect(page.locator(".kpi__value").first()).toHaveText(text);
  });
}

// ---- No sideways scroll (spec 5.3, 8.1) ----------------------------------------------------------

// The old theme lab checked this at 375, 768 and 1280; nothing else did after it went. At 768 the
// open sidebar leaves the content about 488px (spec 5.4), so this is where a row built for a window
// breakpoint would overflow. The page, its content column and the token strip must fit, before and
// after the grid is built. The grid's own scroller is allowed to be wider (min-w-[34rem]), but it
// must scroll inside itself, so the check is on its ancestors, not on the grid.
for (const lang of ["fa", "en"] as const) {
  for (const width of [375, 768, 1280]) {
    test(`virtual-lab fits the window with no sideways scroll, ${lang} ${width}px`, async ({page, baseURL}) => {
      await page.setViewportSize({width, height: 900});
      await openLab(page, baseURL!, lang, "light", "?rows=100");
      await expect(page.getByRole("listbox")).toBeVisible({timeout: 30_000});

      const overflow = () =>
        page.evaluate(() => {
          const over = (el: Element | null) => (el ? el.scrollWidth - el.clientWidth : 0);
          return {
            document: over(document.documentElement),
            body: over(document.body),
            main: over(document.querySelector("main")),
            strip: over(document.querySelector('section[aria-labelledby="token-strip"]')),
          };
        });
      const fits = {document: 0, body: 0, main: 0, strip: 0};
      expect(await overflow(), "overflow in px before the grid").toEqual(fits);

      await page.getByRole("button", {name: BUILD_BUTTON[lang]}).click();
      await expect(page.locator('.data-grid [role="gridcell"]').first()).toBeVisible({timeout: 60_000});
      await page.waitForTimeout(500);
      expect(await overflow(), "overflow in px after the grid").toEqual(fits);
    });
  }
}

// ---- Long lists (spec 8.10, T-487) ------------------------------------------------------------

test("5,000 rows in fa: ListBox with a Virtualizer and a virtualised DataGrid keep the DOM small and settle fast", async ({page, baseURL}) => {
  // The grid is built in the browser after a button press. Rendered on the server, 5,000 rows make
  // the page take close to a minute (see VirtualLab.tsx), so the lab keeps it out of the server render.
  test.setTimeout(300_000);
  await page.setViewportSize({width: 1280, height: 1000});
  await openLab(page, baseURL!, "fa", "light");

  const list = page.getByRole("listbox");
  await expect(list).toBeVisible({timeout: 30_000});
  // The count is written in Persian digits.
  await expect(page.getByText("۵٬۰۰۰ ردیف").first()).toBeVisible();
  await expect.poll(() => page.locator('[role="listbox"] [role="option"]').count(), {timeout: 30_000}).toBeGreaterThan(0);
  const built = Date.now();
  await page.getByRole("button", {name: "ساخت جدول"}).click();
  const grid = page.locator(".data-grid");
  await expect(grid).toBeVisible({timeout: 240_000});
  await expect.poll(() => page.locator('.data-grid [role="gridcell"]').count(), {timeout: 240_000}).toBeGreaterThan(0);
  console.log("virtualised grid with 5,000 rows: first cells " + (Date.now() - built) + "ms after the button, built in the browser");

  const listRows = () => page.locator('[role="listbox"] [role="option"]').count();
  const gridRows = () => page.locator('.data-grid [role="row"]').count();
  expect(await listRows()).toBeGreaterThan(0);
  expect(await listRows(), "list rows in the DOM").toBeLessThan(100);
  expect(await gridRows(), "grid rows in the DOM").toBeGreaterThan(0);
  expect(await gridRows(), "grid rows in the DOM").toBeLessThan(100);

  // A 2,000px wheel on each, then the DOM must have caught up within 100ms of the last scroll event.
  // The clock starts at the last scroll event, not at the wheel event: the browser animates a wheel
  // scroll for a few hundred milliseconds by itself (smooth scrolling), before any component code
  // runs, so the wheel event is the wrong zero. The scroll events end when the position is final.
  // Only rows coming and going count (childList), not attributes: the pointer rests over the list, and
  // the hover state of the rows that slide under it changes after the scroll, which is not rendering.
  const settles: Record<string, number> = {};
  for (const [name, target] of [["list", list], ["grid", grid.locator('[role="grid"], table').first()]] as const) {
    await target.scrollIntoViewIfNeeded();
    const box = (await target.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + Math.min(box.height, 400) / 2);
    await page.evaluate(() => {
      const w = window as unknown as {__lastScroll: number; __lastMutation: number; __wired?: boolean};
      w.__lastScroll = 0;
      w.__lastMutation = 0;
      if (w.__wired) return;
      w.__wired = true;
      document.addEventListener("scroll", () => (w.__lastScroll = performance.now()), {capture: true, passive: true});
      new MutationObserver(() => (w.__lastMutation = performance.now())).observe(document.body, {childList: true, subtree: true});
    });
    await page.mouse.wheel(0, 2000);
    await page.waitForTimeout(1000);
    const settle = await page.evaluate(() => {
      const w = window as unknown as {__lastScroll: number; __lastMutation: number};
      return {scrolled: w.__lastScroll > 0, gap: w.__lastMutation - w.__lastScroll};
    });
    expect(settle.scrolled, name + " scrolled").toBe(true);
    settles[name] = Math.round(settle.gap);
    expect(settle.gap, name + ": ms from the last scroll event to the last DOM change").toBeLessThanOrEqual(100);
    expect(await listRows()).toBeLessThan(100);
    expect(await gridRows()).toBeLessThan(100);
  }
  console.log("settle after a 2,000px wheel, ms from the last scroll event: " + JSON.stringify(settles));

  // The first visible domain moved a long way down: the lists render by scroll position.
  const first = await list.locator('[role="option"]').first().textContent();
  const n = parseInt((first ?? "").split("host-")[1] ?? "0", 10);
  expect(n).toBeGreaterThan(20);
});

// ---- Accessibility of the page itself (spec 17.5, until WP12 runs it on every screen) -------------

// Both languages and both modes: Flat dark and English have no other machine check on a page of ours
// until WP12 runs axe on every screen. The grid is built in each, because its cells are what axe checks.

for (const lang of ["fa", "en"] as const) {
  for (const mode of MODES) {
    test(`axe finds nothing serious on the long lists and the token strip, ${lang} ${mode}`, async ({page, baseURL}) => {
      await page.setViewportSize({width: 1280, height: 900});
      await openLab(page, baseURL!, lang, mode, "?rows=500");
      await expect(page.getByRole("listbox")).toBeVisible({timeout: 30_000});
      await page.getByRole("button", {name: BUILD_BUTTON[lang]}).click();
      await expect(page.locator(".data-grid [role=\"gridcell\"]").first()).toBeVisible({timeout: 60_000});
      await page.waitForTimeout(1000);
      await expectAccessible(page, {screen: "lab"});
    });
  }
}
