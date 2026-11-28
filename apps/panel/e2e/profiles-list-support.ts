import type {Page} from "@playwright/test";

import enShell from "../../../packages/i18n/messages/en/shell.json";
import faShell from "../../../packages/i18n/messages/fa/shell.json";

import {text, type Lang} from "./profiles-support.ts";

// What the specs of the profile list and its dialogs (package S1 of P2) share, over `profiles-support.ts`: the rows of the list by the
// name of the profile, the header's own buttons, and the digits and region names the way the language writes them.

const SHELL = {fa: faShell, en: enShell} as const;

/** `shell.header.<key>`: "Search", "More options", "Create". */
export const header = (lang: Lang, key: "search" | "more" | "create") => SHELL[lang].header[key];

/** The sidebar link to Profiles, for a case that leaves a profile's page by a client-side move (a reload would clear the page's state). */
export const sidebarProfilesLink = (page: Page, lang: Lang) => page.locator("aside.sidebar .sidebar__menu-item").filter({hasText: SHELL[lang].nav.profiles}).first();

/** The reads of one job (`GET /jobs/<id>`), which `GET /jobs/active` is not. */
export const jobReads = (calls: {method: string; path: string}[]) => calls.filter((c) => c.method === "GET" && /^\/jobs\/[^/]+$/.test(c.path) && c.path !== "/jobs/active").length;

/** A number written as the language writes it (Persian digits in `fa`), the way `useAppFormat().number` does. */
export const digits = (lang: Lang, value: number) => new Intl.NumberFormat(lang).format(value);

export const regionName = (lang: Lang, code: string) => new Intl.DisplayNames(lang, {type: "region"}).of(code) ?? code;

/** The list of profiles. */
export const profileList = (page: Page, lang: Lang) => page.getByRole("list", {name: text(lang, "profiles", "list.label")});

/** The rows of the list: its own items, not the counters' `li` inside them. */
export const profileRows = (page: Page, lang: Lang) => profileList(page, lang).locator(":scope > [role=listitem]");

/** One row of the list, found by the profile's name in its main link (the Endpoint line and the counters do not match it). */
export const profileRow = (page: Page, lang: Lang, name: string) =>
  profileRows(page, lang).filter({has: page.locator("[data-row-main]", {hasText: name})});

/** The names of the rows, in order. */
export async function rowNames(page: Page, lang: Lang): Promise<string[]> {
  const links = await profileList(page, lang).locator("[data-row-main]").allInnerTexts();
  // The main link carries the redirect sentence for a reader after the name, in a visually hidden span.
  return links.map((s) => s.replace(/\s*\(.*\)\s*$/, "").trim());
}

/** The three-dot menu of the header, opened. */
export async function openMenu(page: Page, lang: Lang) {
  await page.getByRole("button", {name: header(lang, "more")}).click();
  return page.getByRole("menu", {name: header(lang, "more")});
}

/** The search field of the header: at desktop widths it opens from its button, below `md` it is always there. */
export async function searchField(page: Page, lang: Lang) {
  const field = page.getByRole("searchbox", {name: header(lang, "search")});
  if (!(await field.first().isVisible())) await page.getByRole("button", {name: header(lang, "search"), exact: true}).click();
  return field.first();
}

/** A small JSON profile file for the import dialog. */
export const profileFile = (name = "Imported", extra: Record<string, unknown> = {}) => ({
  name: "profile.json",
  mimeType: "application/json",
  buffer: Buffer.from(JSON.stringify({format: "ctrlz-profile", version: 1, name, kind: "custom", ...extra})),
});
