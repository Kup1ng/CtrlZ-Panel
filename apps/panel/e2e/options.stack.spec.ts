import {readFileSync} from "node:fs";

import type {BrowserContext, Locator, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {LOCK_PASSWORD, commonWord, profilePath, text} from "./profiles-support.ts";

// Stack mode (spec 17.1, 17.7; p2 10.6 "Stack mode: lock and unlock", "redirect a service to a fixture location"), Profile Options and the
// lock (package S2 of P2) against the real API behind Caddy at https://panel.localhost. The mock cannot catch the drift that matters
// here: an option name or a unit shape that the backend reads differently, and the guard that refuses a write on a locked profile with
// 423. So the screen is driven as a person does and the proof is on the wire: what GET /options gives back after each step.
//
// NOT RUN: written under D69 (no stack on the developer's machine) and first run on the Compose stack of GitHub Actions after the merge,
// as ci-web.sh step 10f does for the other stack specs (CTRLZ_WEB_STACK=1, after the seed of scripts/e2e-seed.mjs). It skips itself unless
// E2E_MODE=stack.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test e2e/options.stack.spec.ts
//
// The seeded user is shared with the other stack files, so each test removes the profile it made in a `finally` block, through the API,
// whatever its page did. The lock password is the one of the mock (LOCK_PASSWORD): a value for this test only, on a profile the test deletes.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

test.beforeEach(({guard}) => guard.allowConsole(/status of 40[13]|status of 423|status of 422/));

type Seed = {user: {phone: string; password: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  return {user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""}};
})();

const lang = "en";
const title = (row: string) => text(lang, "rules", `options.rows.${row}.name`);
const row = (page: Page, name: string) => page.locator(`[data-option="${name}"]`);
const press = (toggle: Locator) => toggle.locator("xpath=ancestor::*[contains(@class,'switch')][1]").locator(".switch__control").click();

async function signIn(page: Page) {
  await page.goto(`/${lang}/login`);
  const submit = page.locator('form button[type="submit"]');
  await expect(submit.first()).toBeEnabled();
  await page.locator('input[name="phone"]').fill(seed.user.phone);
  await page.locator('input[name="password"]').fill(seed.user.password);
  await submit.first().click();
  await page.waitForURL(`**/${lang}/profiles`);
}

type Created = {profile: {id: string; name: string}};

async function createProfile(context: BrowserContext, prefix: string): Promise<{id: string; name: string}> {
  const name = `${prefix}${Date.now().toString(36)}`;
  const response = await context.request.post("/api/v1/profiles", {data: {name, kind: "custom"}});
  expect(response.status(), "create the profile of the test").toBe(201);
  return ((await response.json()) as Created).profile;
}

async function removeProfiles(context: BrowserContext, prefix: string) {
  const list = async () => ((await (await context.request.get("/api/v1/profiles")).json()) as {items: {id: string; name: string}[]}).items.filter((p) => p.name.startsWith(prefix));
  for (const p of await list()) {
    // A locked profile cannot be deleted: a test that left one locked has failed already, and the profile is still removed by the seed's reset.
    expect([204, 423]).toContain((await context.request.delete(`/api/v1/profiles/${p.id}`)).status());
  }
}

const optionsOf = async (context: BrowserContext, id: string) => (await (await context.request.get(`/api/v1/profiles/${id}/options`)).json()) as Record<string, unknown>;

test.describe("Profile Options against the real API", () => {
  test("each kind of row writes the unit the API reads: a switch, a TTL, Block Response, ECS and a Disable, and off clears", async ({page, context}) => {
    test.setTimeout(120_000);
    const prefix = "CTRLZ-STACK-options-";
    try {
      await signIn(page);
      const {id} = await createProfile(context, prefix);
      await page.goto(profilePath(lang, id, "options"));
      await expect(row(page, "lock")).toBeVisible();

      // A switch: on sets it, off clears it (open question 3), as the API stores it.
      const dns64 = row(page, "dns64").getByRole("switch", {name: title("dns64")});
      await press(dns64);
      await expect.poll(async () => (await optionsOf(context, id)).dns64).toBe(true);
      await press(dns64);
      await expect.poll(async () => "dns64" in (await optionsOf(context, id))).toBe(false);

      // A TTL, with the bound of the API.
      const ttl = row(page, "block_ttl");
      await ttl.getByRole("button", {name: text(lang, "rules", "options.editAria", {name: title("block_ttl")})}).click();
      await ttl.getByRole("textbox").fill("120");
      await ttl.getByRole("button", {name: `${commonWord(lang, "save")}: ${title("block_ttl")}`}).click();
      await expect.poll(async () => (await optionsOf(context, id)).block_ttl).toBe(120);

      // Block Response Custom, then ECS Custom with a network address, as the API takes them.
      await row(page, "block_response").locator(".select__trigger").click();
      await page.getByRole("option", {name: text(lang, "rules", "options.blockResponse.mode.custom")}).click();
      await row(page, "block_response").getByRole("textbox", {name: text(lang, "rules", "options.blockResponse.v4")}).fill("203.0.113.7");
      await row(page, "block_response").getByRole("button", {name: `${commonWord(lang, "save")}: ${title("block_response")}`}).click();
      await expect.poll(async () => (await optionsOf(context, id)).block_response).toEqual({mode: "custom", v4: "203.0.113.7"});

      await row(page, "ecs").getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.ecs.mode.custom")}`)}).click();
      await row(page, "ecs").getByRole("textbox", {name: text(lang, "rules", "options.ecs.v4")}).fill("203.0.113.0/24");
      await row(page, "ecs").getByRole("button", {name: `${commonWord(lang, "save")}: ${title("ecs")}`}).click();
      await expect.poll(async () => (await optionsOf(context, id)).ecs).toEqual({mode: "custom", v4: "203.0.113.0/24"});

      // Disable for five minutes: the profile row carries `disabled_until`, and the switch off clears it.
      await row(page, "disable").getByRole("radio", {name: new RegExp(`^${text(lang, "rules", "options.disable.choice.5m")}`)}).click();
      await press(row(page, "disable").getByRole("switch", {name: title("disable")}));
      await expect(row(page, "disable").getByTestId("disable-until")).toBeVisible();
      await expect.poll(async () => ((await (await context.request.get(`/api/v1/profiles/${id}`)).json()) as {disabled_until?: string}).disabled_until).toBeTruthy();
      await press(row(page, "disable").getByRole("switch", {name: title("disable")}));
      await expect.poll(async () => ((await (await context.request.get(`/api/v1/profiles/${id}`)).json()) as {disabled_until?: string}).disabled_until).toBeUndefined();
    } finally {
      await removeProfiles(context, prefix);
    }
  });

  test("the Default Rule redirects to a place of the location fixture, and the API answers it back with the place", async ({page, context}) => {
    test.setTimeout(120_000);
    const prefix = "CTRLZ-STACK-default-";
    try {
      await signIn(page);
      const {id} = await createProfile(context, prefix);
      const locations = (await (await context.request.get(`/api/v1/profiles/${id}/locations`)).json()) as {locations: {id: string; country?: string}[]};
      test.skip(locations.locations.length === 0, "the stack has no location fixture");
      await page.goto(`${profilePath(lang, id, "options")}?profileDialog=default-rule`);
      const subject = title("default_rule");
      const dialog = page.getByRole("dialog", {name: text(lang, "services", "destinations.title", {subject})});
      await expect(dialog.getByTestId("d42-notice")).toBeVisible();
      await dialog.locator(".destination-option").filter({hasNotText: /Auto|Random/}).first().click();
      await dialog.getByRole("button", {name: text(lang, "services", "destinations.save")}).click();
      await expect(dialog).toBeHidden();
      await expect.poll(async () => ((await optionsOf(context, id)).default_rule as {action?: string} | undefined)?.action).toBe("redirect");
      await expect(row(page, "default_rule").getByTestId("default-rule-where")).toBeVisible();
    } finally {
      await removeProfiles(context, prefix);
    }
  });

  test("lock and unlock: the lock turns every control off, the API refuses a write with 423 behind the screen's back, a wrong password is refused, the right one unlocks", async ({page, context}) => {
    test.setTimeout(150_000);
    const prefix = "CTRLZ-STACK-lock-";
    try {
      await signIn(page);
      const {id} = await createProfile(context, prefix);
      await page.goto(profilePath(lang, id, "options"));
      const lock = row(page, "lock").getByRole("switch", {name: title("lock")});
      await press(lock);
      const dialog = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.lockTitle", {name: (await page.getByRole("heading", {level: 1}).innerText()).trim()})});
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill(LOCK_PASSWORD);
      await dialog.getByLabel(text(lang, "profiles", "lock.dialog.message")).fill("Stack test lock");
      await dialog.getByRole("button", {name: text(lang, "profiles", "lock.dialog.lock"), exact: true}).click();
      // Locking needs a live reauth: a session this fresh has one, and if the stack asks again the reauth dialog is the test's to answer.
      await expect(page.locator(".profile-frame__lock")).toContainText("Stack test lock");
      await expect(row(page, "dns64").getByRole("switch", {name: title("dns64")})).toBeDisabled();
      // The API is the gate: the same write without the page is 423 profile_locked (T-140).
      const refused = await context.request.patch(`/api/v1/profiles/${id}/options`, {data: {dns64: true}});
      expect(refused.status()).toBe(423);
      expect(((await refused.json()) as {code?: string}).code).toBe("profile_locked");
      // Unlock: a wrong password is 401 and the profile stays locked; the right one frees it.
      await press(lock);
      const unlock = page.getByRole("dialog", {name: text(lang, "profiles", "lock.dialog.unlockTitle", {name: (await page.getByRole("heading", {level: 1}).innerText()).trim()})});
      await unlock.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill("not the password");
      await unlock.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock"), exact: true}).click();
      await expect(page.locator(".profile-frame__lock")).toBeVisible();
      await unlock.getByLabel(text(lang, "profiles", "lock.dialog.password")).fill(LOCK_PASSWORD);
      await unlock.getByRole("button", {name: text(lang, "profiles", "lock.dialog.unlock"), exact: true}).click();
      await expect(page.locator(".profile-frame__lock")).toHaveCount(0);
      await expect(row(page, "dns64").getByRole("switch", {name: title("dns64")})).toBeEnabled();
      expect((await context.request.patch(`/api/v1/profiles/${id}/options`, {data: {dns64: true}})).status()).toBe(200);
    } finally {
      await removeProfiles(context, prefix);
    }
  });
});
