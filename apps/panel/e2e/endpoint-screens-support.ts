import type {Locator, Page} from "@playwright/test";
import {expect} from "@ctrlz/ui/testing/guard.ts";
import type {MockCall} from "@ctrlz/api-client/testing/mock.ts";

import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";
import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import enShell from "../../../packages/i18n/messages/en/shell.json";
import faShell from "../../../packages/i18n/messages/fa/shell.json";

import enEndpoints from "../../../packages/i18n/messages/en/endpoints.json";
import faEndpoints from "../../../packages/i18n/messages/fa/endpoints.json";
import {openEndpoints} from "./endpoints-support.ts";
import type {Lang} from "./profiles-support.ts";

// What the specs of the Endpoint list and its dialogs (package S5) share beyond endpoints-support.ts: numbers as the page writes them, the
// words of the shell and the errors, the header menu, and the row of one Endpoint.

const MESSAGES = {fa: {shell: faShell, errors: faErrors, common: faCommon}, en: {shell: enShell, errors: enErrors, common: enCommon}} as const;

/** A number as the page writes it: Persian digits in `fa`. */
export const nf = (lang: Lang, n: number) => new Intl.NumberFormat(lang === "fa" ? "fa-IR" : "en-US").format(n);

export function message(lang: Lang, namespace: "shell" | "errors" | "common", path: string): string {
  let node: unknown = MESSAGES[lang][namespace];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`${namespace}.${path} is not a message in ${lang}`);
  return node;
}

/** The header's three-dot menu, opened, and one of its items. */
export async function menuItem(page: Page, lang: Lang, name: string | RegExp): Promise<Locator> {
  await page.getByRole("button", {name: message(lang, "shell", "header.more")}).click();
  return page.getByRole("menuitem", {name});
}

/** The row of the Endpoint with this name: the list item whose main link is the name. */
export const endpointRow = (page: Page, name: string) => page.getByRole("listitem").filter({has: page.getByRole("link", {name, exact: true})});

/** The header's + (Add Endpoint). */
export const addButton = (page: Page, lang: Lang, addTitle: string) => page.getByRole("button", {name: addTitle, exact: true}).first();

/** The calls the mock saw, newest last, by method and path. */
export function callsTo(calls: MockCall[], method: string, path: RegExp | string) {
  return calls.filter((c) => c.method === method && (typeof path === "string" ? c.path === path : path.test(c.path)));
}

/**
 * Sets a HeroUI switch by its label, as a person does: the input is under the drawn track, so a click on it is intercepted, and a forced click
 * can land on a neighbour. The label toggles it, and the new state is asserted.
 */
export async function flip(scope: Locator, name: string, on: boolean) {
  const input = scope.getByRole("switch", {name});
  if ((await input.isChecked()) !== on) await scope.getByText(name, {exact: true}).click();
  await expect(input).toBeChecked({checked: on});
}

/**
 * Ticks a HeroUI checkbox. Its real input sits under the drawn box, so a plain `check()` finds the box in the way and waits for ever; a forced
 * check clicks at the input's place, which lands on the box and its label as a person's click does, and still asserts the new state.
 */
export const tick = (box: Locator) => box.check({force: true});
export const untick = (box: Locator) => box.uncheck({force: true});

/** The button of a Select by its label: a button that merely has the word in its name (`Add a second profile`) is not it. */
export const selectOf = (scope: Locator, label: string) => scope.getByRole("button", {name: label}).and(scope.locator("[data-slot=select-trigger]"));

/**
 * `openEndpoints` with the groups copied. The mock builds its state from `[...GROUPS]`, a copy of the list whose objects are the fixture's own, and a
 * rename writes `g.name` on one of them: every later test of the same worker would then find the group called "Family" (the foundation's
 * mock, packages/api-client/src/testing/screenMock.ts, to be fixed there with `GROUPS.map((g) => ({...g}))`).
 */
export async function openList(...args: Parameters<typeof openEndpoints>) {
  const mock = await openEndpoints(...args);
  mock.screens.groups = mock.screens.groups.map((g) => ({...g}));
  return mock;
}

/**
 * The text of `endpoints.<path>` with ICU plurals and `{count, number}` filled in. `endpointsText` of endpoints-support.ts reads messages with no plural; the
 * English titles of the batch dialogs have one ("Move 1 Endpoint", "Move 2 Endpoints"), so this reads `{n, plural, one {..} other {..}}` as well.
 */
export function endpointsMessage(lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = lang === "fa" ? faEndpoints : enEndpoints;
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`endpoints.${path} is not a message in ${lang}`);
  const plain = (n: string | number | undefined) => String(n ?? "");
  return node
    .replace(/\{(\w+), plural, one \{([^}]*)\} other \{([^}]*)\}\}/g, (_, key: string, one: string, other: string) => {
      const n = values[key];
      const count = typeof n === "number" ? n : Number(String(n).replace(/[^0-9]/g, ""));
      return (Number(count) === 1 ? one : other).replace("#", plain(n));
    })
    .replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => plain(values[key]));
}
