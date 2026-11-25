import type {BrowserContext, Page, Response} from "@playwright/test";

import {THEME_COOKIE} from "../theme/config.ts";
import {expectAccentPair} from "./axe.ts";
import {expect} from "./guard.ts";
import {DIRECTION, HEIGHTS, type Matrix} from "./matrix.ts";

// What a matrix project promises (spec 17.1), asserted once for both apps' harness specs (wp12-r1-8).
// Each line is one thing that can break on its own, and none of them can be satisfied by another:
//
//   - the cookie is what makes the theme, and the mocked /me says "system", which resolves to the
//     emulated colour scheme, which equals the project's theme: the attribute alone would pass with
//     no cookie at all, so the cookie and the server-rendered HTML are read directly;
//   - the first byte of the response already holds the mode (spec 5.2), so the raw HTML is read,
//     not the DOM after the scripts ran;
//   - the locale, the width and the height of the context are what the project names.
// `status` is the answer the screen is meant to give: 200 for a page, 404 for a Not found screen (T-468), which is a screen with the same
// document promises as any other.
export async function expectMatrixPage({
  page,
  context,
  response,
  baseURL,
  matrix,
  status = 200,
}: {
  page: Page;
  context: BrowserContext;
  response: Response | null;
  baseURL: string | undefined;
  matrix: Matrix;
  status?: number;
}) {
  const {width, lang, theme} = matrix;
  expect(response?.status()).toBe(status);

  const cookies = await context.cookies(baseURL);
  expect(cookies.find((c) => c.name === THEME_COOKIE)?.value, "the guard sets the theme cookie for a matrix project").toBe(theme);

  const raw = await response!.text();
  // The one exception of spec 5.2: the first response of a 404 is Next's own error shell, which has no lang, dir, theme or nonce tag, and client
  // recovery renders the page after it. That is accepted for the 404 alone, so the raw HTML is held to its promises only when it is not that shell
  // (a later Next that renders the document on the server then has to keep them), and the document after recovery is held to them in every case below.
  const errorShell = status === 404 && /<html\b[^>]*\bid="__next_error__"/.test(raw);
  if (!errorShell) {
    const tag = /<html\b[^>]*>/.exec(raw)?.[0] ?? "";
    expect(tag, "the <html> tag of the raw response").toContain(`lang="${lang}"`);
    expect(tag).toContain(`dir="${DIRECTION[lang]}"`);
    expect(tag, "data-theme in the raw response, before any script").toContain(`data-theme="${theme}"`);
    const classes = (/\bclass="([^"]*)"/.exec(tag)?.[1] ?? "").split(/\s+/);
    expect(classes.includes("dark"), "the dark class in the raw response").toBe(theme === "dark");
    expect(classes.includes("light"), "the light class in the raw response").toBe(theme === "light");
  }

  const html = page.locator("html");
  await expect(html).toHaveAttribute("lang", lang);
  await expect(html).toHaveAttribute("dir", DIRECTION[lang]);
  await expect(html).toHaveAttribute("data-theme", theme);
  await expect(html).toHaveClass(new RegExp(`\\bflat-${theme}\\b`));

  expect(await page.evaluate(() => [window.innerWidth, window.innerHeight])).toEqual([width, HEIGHTS[width]]);
  expect(await page.evaluate(() => navigator.language)).toBe(lang === "fa" ? "fa-IR" : "en-US");
  expect(await page.evaluate(() => matchMedia("(prefers-color-scheme: dark)").matches)).toBe(theme === "dark");
  // Dark text on the accent, in this project's theme (17.5).
  await expectAccentPair(page);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, "horizontal page overflow in px").toBeLessThanOrEqual(0);
}
