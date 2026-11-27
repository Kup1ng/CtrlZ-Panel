import type {Locator, Page} from "@playwright/test";
import {errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect} from "@ctrlz/ui/testing/guard.ts";

import {endpointsMessage, nf} from "./endpoint-screens-support.ts";
import type {Lang} from "./profiles-support.ts";

// What the specs of the Schedule, Clients and IPs pages (package S6) share: the messages with ICU plurals filled in, the cell of the
// schedule grid by its place in the week, and the answers of a locked profile.

export {nf};
export const text = (lang: Lang, path: string, values: Record<string, string | number> = {}) => endpointsMessage(lang, path, values);

/** The cell of the grid: `day` counts from Sunday (0), `row` is the half hour of that day (0 to 47). */
export const gridCell = (page: Page, day: number, row: number): Locator => page.locator(`[role=gridcell][data-cell="${day * 48 + row}"]`);

/** The middle of a locator, after it has been scrolled to the middle of the screen (the bar of the page sticks to the bottom and covers what is under it). */
export async function centerOf(locator: Locator): Promise<{x: number; y: number}> {
  await locator.evaluate((el) => el.scrollIntoView({block: "center"}));
  const box = await locator.boundingBox();
  expect(box, "the element has no box on the page").not.toBeNull();
  return {x: box!.x + box!.width / 2, y: box!.y + box!.height / 2};
}

/** A drag with a mouse from one cell to another of the same day. */
export async function dragCells(page: Page, day: number, from: number, to: number) {
  const a = await centerOf(gridCell(page, day, from));
  await page.mouse.move(a.x, a.y);
  await page.mouse.down();
  const b = await centerOf(gridCell(page, day, to));
  await page.mouse.move(b.x, b.y, {steps: 4});
  await page.mouse.up();
}

/** A tap on a cell with a finger: `touchscreen.tap` sends touch pointer events and a click. */
export async function tapCell(page: Page, day: number, row: number) {
  const c = await centerOf(gridCell(page, day, row));
  await page.touchscreen.tap(c.x, c.y);
}

/** The 423 that asks for the lock password of `profileId` until a body carries it, and 401 for a wrong one. */
export function lockedUntilPassword(profileId: string, password: string, then: (body: unknown) => {status: number; body?: unknown}) {
  return (call: {body: unknown}) => {
    const sent = (call.body as {lock_passwords?: {profile_id: string; password: string}[]}).lock_passwords;
    if (!sent || sent.length === 0) return {status: 423, body: errorBody("profile_locked", {fields: [{name: "/lock_passwords", code: "required"}]})};
    const mine = sent.find((p) => p.profile_id === profileId);
    if (!mine || mine.password !== password) return {status: 401, body: errorBody("invalid_credentials", {fields: [{name: "/lock_passwords/0/password", code: "invalid"}]})};
    return then(call.body);
  };
}
