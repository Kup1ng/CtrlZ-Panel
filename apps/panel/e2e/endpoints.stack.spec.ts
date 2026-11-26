import {readFileSync} from "node:fs";

import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enEndpoints from "../../../packages/i18n/messages/en/endpoints.json";

// Stack mode (spec p3 11.6, T-220 and T-239), the Endpoint screens against the real API behind Caddy at https://panel.localhost: create an Endpoint
// from the Add dialog, see its Resolvers dialog open by itself with the stamps the server built, and delete the Endpoint again.
//
// WRITTEN, NOT RUN (Plan.md D69): the Compose stack is not started on the build machine. It runs with the rest of the stack specs
// (CTRLZ_WEB_STACK=1, after the seed of scripts/e2e-seed.mjs) and skips itself unless E2E_MODE=stack. The seeded user needs one profile; the
// first real run may show a selector to fix.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test e2e/endpoints.stack.spec.ts
//
// The test leaves the seeded user as it found it: the Endpoint it makes is deleted in a `finally` block by the API, which is the same call the
// Delete dialog makes, so a failed step of the page cannot leave an Endpoint behind for the next stack file.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 where the mock fulfils quietly (the anonymous /me probe of the login page); only 401 is allowed.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

type Seed = {user: {phone: string; password: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  return {user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""}};
})();

const t = enEndpoints.dialogs;
const NAME = "CTRLZ-STACK-ENDPOINT";

async function signIn(page: Page) {
  await page.goto("/en/login");
  const submit = page.locator('form button[type="submit"]');
  await expect(submit.first()).toBeEnabled();
  await page.locator('input[name="phone"]').fill(seed.user.phone);
  await page.locator('input[name="password"]').fill(seed.user.password);
  await submit.first().click();
  await page.waitForURL("**/en/profiles");
}

/** Deletes every Endpoint of this spec by the API, whatever state the page was left in. */
async function removeEndpoints(context: BrowserContext) {
  const list = await context.request.get(`/api/v1/endpoints?q=${encodeURIComponent(NAME)}`);
  if (list.status() !== 200) return;
  const body = (await list.json()) as {items: {id: string; name: string}[]};
  for (const e of body.items.filter((x) => x.name === NAME)) {
    expect([200, 204], "delete the Endpoint of the spec").toContain((await context.request.post(`/api/v1/endpoints/${e.id}:delete`, {data: {}})).status());
  }
}

test.describe("Endpoints against the real API", () => {
  test("T-220, T-239: Add makes an Endpoint, its Resolvers dialog opens by itself, and the Endpoint is in the list", async ({page, context}) => {
    test.setTimeout(120_000);
    try {
      await signIn(page);
      await page.goto("/en/endpoints?deviceDialog=add");
      const add = page.getByRole("dialog", {name: t.add.title});
      await expect(add).toBeVisible();
      await add.getByRole("textbox", {name: t.fields.name}).fill(NAME);
      await add.getByRole("button", {name: t.add.submit, exact: true}).click();

      // The Add flow opens the first Endpoint's Resolvers address at once (T-218). The Resolvers dialog itself is the next package's, so this
      // asserts the address only. The dialog's own part (visible, names the Endpoint, closes with Escape) comes back with that package.
      await expect(page).toHaveURL(/deviceDialog=resolvers&deviceId=[0-9a-f-]{36}/);
      await page.goto("/en/endpoints");
      await expect(page.getByRole("listitem").filter({has: page.getByRole("link", {name: NAME, exact: true})})).toBeVisible();
    } finally {
      await removeEndpoints(context);
    }
  });
});
