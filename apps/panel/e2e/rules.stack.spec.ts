import {randomBytes} from "node:crypto";

import type {APIRequestContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import enCommon from "../../../packages/i18n/messages/en/common.json";
import {text} from "./profiles-support.ts";

// Stack mode (spec 17.1, 17.7; spec p2 10.6 "Stack mode"), the Rules and folders screens (S4) against the real API behind Caddy at
// https://panel.localhost: add a rule, make a folder and upload a rules file into it, and see a locked profile refuse writes. The profile
// itself is made and removed through the API (create from a type is the profiles spec's case), so every test owns a profile with a name of its
// own and takes it away in a `finally` block, the way the other stack specs leave the seeded user as they found it.
//
// Written under D69 and NOT run: the stack runs only on GitHub Actions after the merge, where `scripts/ci-web.sh` step 10f starts it with
// CTRLZ_WEB_STACK=1 after the seed of `scripts/e2e-seed.mjs`.
//
//   E2E_MODE=stack E2E_PHONE=... E2E_PASSWORD=... pnpm exec playwright test e2e/rules.stack.spec.ts
//
// The credentials come from the environment and are never printed. The lock password is made up for each run and lives in this process only.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// A write the real API refuses with 423 is made from the page in no case below (the writes are disabled), but the API checks are made with
// `context.request`, which Chrome does not log.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

const R = (path: string, values: Record<string, string | number> = {}) => text("en", "rules", path, values);
const base = (id: string) => `/en/profiles/${id}/custom-rules`;

async function signIn(request: APIRequestContext) {
  const response = await request.post("/api/v1/auth/login/password", {data: {phone: process.env.E2E_PHONE, password: process.env.E2E_PASSWORD, remember_me: false}});
  expect(response.status(), "sign in").toBe(200);
}

type Made = {id: string; name: string};

/** A custom profile with a name no other run has. */
async function makeProfile(request: APIRequestContext): Promise<Made> {
  const name = `E2E rules ${randomBytes(4).toString("hex")}`;
  const response = await request.post("/api/v1/profiles", {data: {name, kind: "custom"}});
  expect(response.status(), "create the profile").toBe(201);
  const body = (await response.json()) as {profile: {id: string}};
  return {id: body.profile.id, name};
}

/** Takes the profile away, unlocking it first if a test left it locked. Never fails the test by itself: a missing profile is already gone. */
async function removeProfile(request: APIRequestContext, made: Made | undefined, lockPassword?: string) {
  if (!made) return;
  if (lockPassword) await request.post(`/api/v1/profiles/${made.id}/unlock`, {data: {password: lockPassword}});
  const response = await request.delete(`/api/v1/profiles/${made.id}`);
  expect([204, 404]).toContain(response.status());
}

const rulesList = (page: Page, name: string) => page.getByRole("list", {name: R("list.listLabel", {name})});
const dialogOf = (page: Page, title: string) => page.getByRole("dialog", {name: title});

async function open(page: Page, path: string) {
  await page.goto(path);
  await expect(page.locator(".shell-page")).toBeVisible();
}

test("add a rule: the dialog writes it, and it is still there after a reload", async ({page, context}) => {
  test.setTimeout(90_000);
  await signIn(context.request);
  let made: Made | undefined;
  try {
    made = await makeProfile(context.request);
    await open(page, base(made.id));
    await expect(page.getByText(R("list.emptyTitle"))).toBeVisible();
    await page.getByRole("button", {name: R("list.addAria", {name: made.name})}).first().click();
    const dialog = dialogOf(page, R("dialog.add"));
    const box = dialog.getByRole("textbox", {name: R("dialog.domains")});
    await box.fill("stack-one.test");
    await box.press("Enter");
    await dialog.getByRole("button", {name: /^Add /}).last().click();
    await expect(dialog).toBeHidden();
    const row = rulesList(page, made.name).getByRole("listitem").filter({hasText: "stack-one.test"});
    await expect(row).toBeVisible();
    await page.reload();
    await expect(rulesList(page, made.name).getByRole("listitem").filter({hasText: "stack-one.test"})).toBeVisible();
    // The switch writes the rule at once and the server keeps it.
    const toggle = rulesList(page, made.name).getByRole("switch", {name: R("row.switch", {pattern: "stack-one.test"})});
    await toggle.click({force: true});
    await expect(toggle).not.toBeChecked();
    await page.reload();
    await expect(rulesList(page, made.name).getByRole("switch", {name: R("row.switch", {pattern: "stack-one.test"})})).not.toBeChecked();
  } finally {
    await removeProfile(context.request, made);
  }
});

test("make a folder and upload a rules file into it", async ({page, context}) => {
  test.setTimeout(90_000);
  await signIn(context.request);
  let made: Made | undefined;
  try {
    made = await makeProfile(context.request);
    await open(page, `${base(made.id)}?ruleDialog=folder`);
    const make = dialogOf(page, R("folderDialog.add"));
    await make.getByRole("textbox", {name: R("folderDialog.name")}).fill("Stack folder");
    await make.getByRole("button", {name: enCommon.create}).click();
    await expect(make).toBeHidden();
    const folders = page.getByRole("list", {name: R("folder.listLabel")});
    await expect(folders.getByRole("listitem").filter({hasText: "Stack folder"})).toBeVisible();
    await folders.getByRole("listitem").filter({hasText: "Stack folder"}).getByRole("link").first().click();
    await page.waitForURL(/custom-rules\/[0-9a-f-]{36}$/);
    await page.getByRole("button", {name: R("folderPage.uploadAria", {name: "Stack folder"})}).click();
    const upload = dialogOf(page, R("upload.title", {name: "Stack folder"}));
    const document = {format: "ctrlz-rules", version: 1, rules: [{pattern: "up-one.test", action: "block"}, {pattern: "up-two.test", action: "bypass", comment: "from file"}]};
    await upload.locator("input[type=file]").setInputFiles({name: "rules.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(document))});
    await upload.getByRole("button", {name: R("upload.do"), exact: true}).click();
    await expect(upload.getByText(R("upload.done"))).toBeVisible();
    await upload.getByRole("button", {name: enCommon.done}).click();
    await expect(upload).toBeHidden();
    const inside = rulesList(page, "Stack folder");
    await expect(inside.getByRole("listitem")).toHaveCount(2);
    await expect(inside.getByRole("listitem").filter({hasText: "up-two.test"})).toContainText("from file");
    // Export Rules gives the folder's document back.
    const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", {name: R("folderPage.exportAria", {name: "Stack folder"})}).click()]);
    expect(download.suggestedFilename()).toMatch(/\.json$/);
  } finally {
    await removeProfile(context.request, made);
  }
});

test("a locked profile shows its rules, disables every write, and the API refuses one with 423; unlocked, it works again", async ({page, context}) => {
  test.setTimeout(90_000);
  await signIn(context.request);
  const lockPassword = randomBytes(9).toString("base64url");
  let made: Made | undefined;
  let locked = false;
  try {
    made = await makeProfile(context.request);
    const created = await context.request.post(`/api/v1/profiles/${made.id}/rules`, {data: {patterns: ["kept.test"], action: "block"}});
    expect(created.status(), "a rule to look at").toBe(201);
    // A lock needs a live reauth, and a fresh sign-in does not open the window: without it the API answers 403 (measured on the stack run of 2026-11-27).
    expect((await context.request.post("/api/v1/auth/reauth", {data: {password: process.env.E2E_PASSWORD}})).status(), "reauth").toBe(204);
    const lock = await context.request.post(`/api/v1/profiles/${made.id}/lock`, {data: {password: lockPassword, message: "stack"}});
    expect(lock.status(), "lock").toBeLessThan(300);
    locked = true;
    await open(page, base(made.id));
    await expect(page.locator(".profile-frame__lock")).toBeVisible();
    await expect(rulesList(page, made.name).getByRole("listitem").filter({hasText: "kept.test"})).toBeVisible();
    await expect(page.getByRole("button", {name: R("list.addAria", {name: made.name})}).first()).toBeDisabled();
    await expect(rulesList(page, made.name).getByRole("switch").first()).toBeDisabled();
    const refused = await context.request.post(`/api/v1/profiles/${made.id}/rules`, {data: {patterns: ["refused.test"], action: "block"}});
    expect(refused.status(), "a write to a locked profile").toBe(423);

    const unlock = await context.request.post(`/api/v1/profiles/${made.id}/unlock`, {data: {password: lockPassword}});
    expect(unlock.status(), "unlock").toBeLessThan(300);
    locked = false;
    await page.reload();
    await expect(page.locator(".profile-frame__lock")).toHaveCount(0);
    await expect(page.getByRole("button", {name: R("list.addAria", {name: made.name})}).first()).toBeEnabled();
    await expect(rulesList(page, made.name).getByRole("switch").first()).toBeEnabled();
  } finally {
    await removeProfile(context.request, made, locked ? lockPassword : undefined);
  }
});
