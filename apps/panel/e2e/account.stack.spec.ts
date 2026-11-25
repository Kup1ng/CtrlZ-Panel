import {createHmac} from "node:crypto";
import {readFileSync} from "node:fs";

import type {BrowserContext, Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

import {acc} from "./account-support.ts";

// Stack mode (spec 17.1, 17.7), the Account page of WP9 against the real API behind Caddy at
// https://panel.localhost: the two-step wizard with a real secret and a computed code, a passkey added and
// deleted on Chrome's virtual authenticator, and Log out all ending the session on the server.
//
// First run through Caddy on the Compose stack: 2026-11-23, P1 web merge. ci-web.sh step 10f runs it (CTRLZ_WEB_STACK=1), after the seed of scripts/e2e-seed.mjs. It needs deploy/compose/e2e-stack.yml and skips itself unless E2E_MODE=stack.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test e2e/account.stack.spec.ts
//
// Every test leaves the seeded user as it found it (no authenticator, no passkey, the seeded password), because
// the tests share one user: what a test adds is removed in a `finally` block by the API, which does not wait for
// a TOTP window and so cannot run into the 60 s timeout of stack mode (wp8-r4-4, wp8-r5-8, wp9-r5-1). The
// static check of these rules is packages/ui/src/testing/stackSpec.test.ts. The phone change is not here: it would move the seeded number, and the SMS gateway's
// file would have to be read for two numbers; it stays a manual check after the merge (see the WP9 notes).

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 where the mock of the same flow fulfils it quietly: the anonymous /me probe of a login page, a wrong password, a session
// cookie that is gone before a refresh. Chrome logs each as "Failed to load resource", and the first real run (merge item, step 10f) showed
// them. Only 401 is allowed: a 403, 5xx or network failure in these flows is still a failure.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

type Seed = {user: {phone: string; password: string}};
const seed = ((): Seed => {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  return {user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""}};
})();

/** RFC 6238, SHA-1, 6 digits, 30 seconds: what the authenticator app does. */
function totp(secretBase32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretBase32.replace(/=+$/, "").replace(/\s/g, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function signIn(page: Page, lang: "fa" | "en") {
  await page.goto(`/${lang}/login`);
  const submit = page.locator('form button[type="submit"]');
  await expect(submit.first()).toBeEnabled();
  await page.locator('input[name="phone"]').fill(seed.user.phone);
  await page.locator('input[name="password"]').fill(seed.user.password);
  await submit.first().click();
  await page.waitForURL(`**/${lang}/profiles`);
  await page.goto(`/${lang}/preferences/account`);
  await expect(page.locator('[data-row-id="phone"]')).toBeVisible();
}

const dialog = (page: Page) => page.getByRole("dialog");

/**
 * Turns TOTP off for a user who has it, so the seeded user is a plain password user again. It spends two of the
 * recovery codes the page showed and no TOTP code: a code is good for one 30 second step and a second one waits
 * for the next window, which is what made a cleanup of this kind outlive the test's timeout (wp8-r4-4).
 * Fewer than two codes means TOTP was never confirmed, and a password answer without a ticket means it is
 * already off: both leave the user alone.
 */
async function removeTotp(context: BrowserContext, recovery: () => string[]) {
  await context.clearCookies();
  const first = await context.request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: seed.user.password}});
  expect(first.status(), "sign in for the cleanup").toBe(200);
  const body = (await first.json()) as {ticket?: string};
  if (!body.ticket) return;
  // TOTP is on, so the cleanup needs two codes. The codes arrive in an async handler of the confirm response, so wait for them; a user left with TOTP
  // would turn the next stack file's sign-in into a surprise prompt that points at the wrong cause (merge-r3-11).
  await expect.poll(() => recovery().length, {message: "TOTP is on and the recovery codes were not captured: the seeded user is left with TOTP", timeout: 10_000}).toBeGreaterThanOrEqual(2);
  const codes = recovery();
  expect((await context.request.post("/api/v1/auth/login/totp", {data: {ticket: body.ticket, recovery_code: codes[0]}})).status()).toBe(200);
  expect((await context.request.post("/api/v1/auth/reauth", {data: {password: seed.user.password, recovery_code: codes[1]}})).status()).toBe(204);
  expect((await context.request.post("/api/v1/account/totp/disable", {data: {}})).status()).toBe(200);
}

/** Removes every passkey of the seeded user; each delete must answer 204 and the list must be empty after. */
async function removePasskeys(context: BrowserContext) {
  await context.clearCookies();
  const request = context.request;
  expect((await request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: seed.user.password}})).status(), "sign in for the cleanup").toBe(200);
  expect((await request.post("/api/v1/auth/reauth", {data: {password: seed.user.password}})).status(), "reauth").toBe(204);
  const list = (await (await request.get("/api/v1/account/passkeys")).json()) as {passkeys: {id: string}[]};
  for (const p of list.passkeys) expect((await request.delete(`/api/v1/account/passkeys/${p.id}`)).status(), "delete passkey").toBe(204);
  const after = (await (await request.get("/api/v1/account/passkeys")).json()) as {passkeys: unknown[]};
  expect(after.passkeys, "no passkey is left on the seeded user").toEqual([]);
}

test.describe("account against the real API", () => {
  const lang = "en";
  const A = (path: string) => acc(lang, path);

  test("two-step verification: enable with a real secret and see the codes once; the cleanup turns it off", async ({page, context}) => {
    // Roomy on purpose: a first real run is slow, and the cleanup in `finally` must still get its turn.
    test.setTimeout(120_000);
    // The codes come from the confirm response, not from the page, so the cleanup has them even when a later
    // step of the page fails.
    let recovery: string[] = [];
    page.on("response", (response) => {
      if (!response.url().endsWith("/api/v1/account/totp/confirm") || response.status() !== 200) return;
      void response.json().then((body: {recovery_codes?: string[]}) => {
        recovery = body.recovery_codes ?? [];
      });
    });
    try {
      await signIn(page, lang);
      await page.locator('[data-row-id="totp"]').getByRole("button", {name: A("totp.enable")}).click();
      await dialog(page).locator('input[name="password"]').fill(seed.user.password);
      await dialog(page).getByRole("button", {name: A("reauth.submit")}).click();
      const secret = (await dialog(page).getByTestId("totp-secret").innerText()).replace(/\s/g, "");
      expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
      await dialog(page).getByRole("button", {name: "Continue"}).click();
      await dialog(page).getByRole("checkbox", {name: A("totp.saved")}).check({force: true});
      await dialog(page).locator('input[name="totp_code"]').focus();
      await page.keyboard.type(totp(secret));
      await expect(dialog(page).getByTestId("recovery-codes").getByRole("listitem")).toHaveCount(10);
      await dialog(page).getByRole("button", {name: A("totp.saveDone")}).click();
      await expect(page.locator('[data-row-id="totp"]')).toContainText(A("totp.on"));
    } finally {
      await removeTotp(context, () => recovery);
    }
  });

  test("a passkey on the virtual authenticator: add, name, rename, and delete it again", async ({page, context}) => {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true},
    });
    try {
      await signIn(page, lang);
      const add = page.locator('[data-row-id="passkey-add"]');
      await add.getByRole("button", {name: A("passkeys.addAria")}).click();
      await add.locator('input[name="password"]').fill(seed.user.password);
      await add.getByRole("button", {name: A("reauth.submit")}).click();
      await add.getByRole("button", {name: A("passkeys.create")}).click();
      await add.locator('input[name="passkey_name"]').fill("E2E key");
      await add.getByRole("button", {name: A("passkeys.saveName")}).click();
      const created = page.locator('[data-row-id^="passkey-"]', {hasText: "E2E key"});
      await expect(created).toBeVisible();

      // merge-r1-8: the real API removes the half-space from a name before it stores it (RenamePasskey, D64), and the client sends the name the
      // same way, so what the list shows is what the visitor typed minus the half-space and the direction marks.
      await created.getByRole("button", {name: A("passkeys.renameAria").replace("{name}", "E2E key")}).click();
      await created.locator('input[name="passkey_name"]').fill("‎E2E‌key‏");
      await created.getByRole("button", {name: A("passkeys.saveName")}).click();
      const renamed = page.locator('[data-row-id^="passkey-"]', {hasText: "E2Ekey"});
      await expect(renamed).toBeVisible();

      await renamed.getByRole("button", {name: /^Delete passkey/}).click();
      await page.getByRole("alertdialog").getByRole("button", {name: A("passkeys.deleteConfirm")}).click();
      await expect(renamed).toHaveCount(0);
    } finally {
      await removePasskeys(context);
    }
  });

  test("Log out all ends the session on the server: the next /me is 401 and the login page shows", async ({page}) => {
    await signIn(page, lang);
    await page.locator('[data-row-id="sessions"]').getByRole("button", {name: A("sessions.manageAria")}).click();
    await page.locator('[data-row-id="sessions"]').getByRole("button", {name: /Log out/}).click();
    await page.getByRole("alertdialog").getByRole("button", {name: A("sessions.logoutAllConfirm")}).click();
    await page.waitForURL(`**/${lang}/login`);
    const status = await page.evaluate(async () => (await fetch("/api/v1/me", {credentials: "same-origin"})).status);
    expect(status).toBe(401);
  });
});
