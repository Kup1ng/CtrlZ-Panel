import {createHmac} from "node:crypto";
import {existsSync, readFileSync} from "node:fs";
import {resolve} from "node:path";

import {request as playwrightRequest, type APIRequestContext, type BrowserContext, type Page} from "@playwright/test";
import {expect, test} from "@ctrlz/ui/testing/guard.ts";

// Stack mode (spec 17.1, 17.7), the user auth flows of WP8: login by password, by SMS code through the `noop`
// gateway, with TOTP and a recovery code, Forgot Password, an invite, and a passkey on Chrome's virtual
// authenticator, all against the real API behind Caddy at https://panel.localhost.
//
// First run through Caddy on the Compose stack: 2026-11-23, P1 web merge. ci-web.sh step 10f runs it (CTRLZ_WEB_STACK=1), after the seed of scripts/e2e-seed.mjs. It needs deploy/compose/e2e-stack.yml and skips itself unless E2E_MODE=stack.
//
//   E2E_MODE=stack E2E_SEED_FILE=<private dir>/seed.json pnpm exec playwright test -c playwright.config.ts
//
// The seed file holds the generated user and admin (never printed, never put in a URL). Codes of the SMS
// gateway are read from deploy/compose/e2e-out/noop.jsonl, one JSON object per message, or from the folder
// named by E2E_NOOP_DIR. Every test leaves the account as it found it (no TOTP, no passkey, the seeded
// password), because the tests share one user.

test.skip(process.env.E2E_MODE !== "stack", "needs the Compose stack and a seeded user");

// The real API answers 401 where the mock of the same flow fulfils it quietly: the anonymous /me probe of a login page, a wrong password, a session
// cookie that is gone before a refresh. Chrome logs each as "Failed to load resource", and the first real run (merge item, step 10f) showed
// them. Only 401 is allowed: a 403, 5xx or network failure in these flows is still a failure.
test.beforeEach(({guard}) => guard.allowConsole(/status of 401/));

type Seed = {
  admin: {username: string; password: string; totp_secret: string};
  user: {phone: string; password: string};
};

function readSeed(): Seed {
  const file = process.env.E2E_SEED_FILE;
  if (file) return JSON.parse(readFileSync(file, "utf8")) as Seed;
  // The older form of session.stack.spec.ts: the user only.
  return {
    admin: {username: "", password: "", totp_secret: ""},
    user: {phone: process.env.E2E_PHONE ?? "", password: process.env.E2E_PASSWORD ?? ""},
  };
}

const seed = readSeed();
const NOOP = resolve(process.env.E2E_NOOP_DIR ?? "../../deploy/compose/e2e-out", "noop.jsonl");

/** RFC 6238, SHA-1, 6 digits, 30 seconds: what the authenticator app does. */
function totp(secretBase32: string, at = Date.now()): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of secretBase32.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const mac = createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0xf;
  const value = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

/** A spent TOTP step is refused, so a second code waits for the next window. */
async function nextStep() {
  await new Promise((r) => setTimeout(r, 30_000 - (Date.now() % 30_000) + 500));
}

/** The newest 6-digit code the gateway recorded for a number, waiting up to ten seconds for it. */
async function smsCode(phone: string, since: number): Promise<string> {
  const tail = phone.replace(/\D/g, "").slice(-10);
  for (let i = 0; i < 40; i++) {
    if (existsSync(NOOP)) {
      const lines = readFileSync(NOOP, "utf8").trim().split("\n").filter(Boolean);
      for (const line of lines.reverse()) {
        const rec = JSON.parse(line) as {to?: string; values?: Record<string, string>};
        if (!rec.to?.replace(/\D/g, "").endsWith(tail)) continue;
        const code = Object.values(rec.values ?? {}).find((v) => /^\d{6}$/.test(v));
        if (code && lines.length > since) return code;
      }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error("no SMS code arrived in the noop file");
}

/** How many messages are in the noop file now, so `smsCode` can tell a new one from an old one. */
const smsMark = () => (existsSync(NOOP) ? readFileSync(NOOP, "utf8").trim().split("\n").filter(Boolean).length : 0);

const passwordOf = (page: Page) => page.locator('input[name="password"]');
const phoneOf = (page: Page) => page.locator('input[name="phone"]');
const submit = (page: Page) => page.locator('form button[type="submit"]');

async function ready(page: Page, path: string) {
  await page.goto(path);
  await expect(submit(page).first()).toBeEnabled();
}

async function signInByApi(request: APIRequestContext, remember = false) {
  const response = await request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: seed.user.password, remember_me: remember}});
  expect(response.status()).toBe(200);
}

/** Opens the ten minute reauth window with the user's password, which is the seeded one unless a test has changed it. */
async function reauth(request: APIRequestContext, password = seed.user.password) {
  expect((await request.post("/api/v1/auth/reauth", {data: {password}})).status(), "reauth").toBe(204);
}

/** Turns TOTP on for the signed-in user and returns the secret and every recovery code. */
async function enableTotp(request: APIRequestContext) {
  await reauth(request);
  const setup = (await (await request.post("/api/v1/account/totp/setup", {data: {}})).json()) as {secret: string};
  const confirmed = await request.post("/api/v1/account/totp/confirm", {data: {code: totp(setup.secret), saved: true}});
  expect(confirmed.status()).toBe(200);
  const {recovery_codes} = (await confirmed.json()) as {recovery_codes: string[]};
  return {secret: setup.secret, recovery: recovery_codes};
}

/**
 * Signs in as a user who has TOTP, re-proves with it, and turns TOTP off, so the seeded user is a plain
 * password user again for the other tests. It spends two recovery codes and no TOTP code: a code is good
 * for one 30 second step and a second one waits for the next window, so a cleanup built on them took up to a
 * minute and could run past the test's timeout, which is the moment it matters (wp8-r4-4). Recovery codes
 * do not depend on the clock.
 */
async function removeTotp(context: BrowserContext, spare: [string, string]) {
  await context.clearCookies();
  const first = await context.request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: seed.user.password}});
  const {ticket} = (await first.json()) as {ticket: string};
  expect((await context.request.post("/api/v1/auth/login/totp", {data: {ticket, recovery_code: spare[0]}})).status()).toBe(200);
  expect((await context.request.post("/api/v1/auth/reauth", {data: {password: seed.user.password, recovery_code: spare[1]}})).status()).toBe(204);
  expect((await context.request.post("/api/v1/account/totp/disable", {data: {}})).status()).toBe(200);
}

/**
 * Signs in again by the API, which a test that ended half way needs, and removes every passkey of the seeded
 * user: each delete must answer 204 and the list must be empty after, so a passkey left behind (a row moves the
 * account's credential_gen and makes Enforce Passkey possible) fails here and not in a later test (wp8-r5-8).
 */
async function removePasskeys(context: BrowserContext) {
  await context.clearCookies();
  await signInByApi(context.request);
  await reauth(context.request);
  const list = (await (await context.request.get("/api/v1/account/passkeys")).json()) as {passkeys: {id: string}[]};
  for (const p of list.passkeys) expect((await context.request.delete(`/api/v1/account/passkeys/${p.id}`)).status(), "delete passkey").toBe(204);
  const after = (await (await context.request.get("/api/v1/account/passkeys")).json()) as {passkeys: unknown[]};
  expect(after.passkeys, "no passkey is left on the seeded user").toEqual([]);
}

test.describe("login", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("password: signs in through the real API and lands in the shell", async ({page}) => {
    await ready(page, "/en/login");
    await phoneOf(page).fill(seed.user.phone);
    await passwordOf(page).fill(seed.user.password);
    await submit(page).click();
    await page.waitForURL("**/en/profiles");
    await expect(page.locator(".shell-page")).toBeVisible();
  });

  // merge-r1-7: the server removes U+200C from a password at verify (password.Normalize, D64), so a Persian user whose keyboard added the half-space
  // (Shift+B) still signs in, and the page must send it instead of refusing it. Any other invisible character is still refused, with no request.
  test("password: a half-space typed into the password is sent, and the user signs in", async ({page}) => {
    await ready(page, "/en/login");
    await phoneOf(page).fill(seed.user.phone);
    const half = Math.max(1, Math.floor(seed.user.password.length / 2));
    await passwordOf(page).fill(`${seed.user.password.slice(0, half)}‌${seed.user.password.slice(half)}`);
    await submit(page).click();
    await page.waitForURL("**/en/profiles");
    await expect(page.locator(".shell-page")).toBeVisible();
  });

  test("password: a wrong password is the one neutral message", async ({page}) => {
    await ready(page, "/en/login");
    await phoneOf(page).fill(seed.user.phone);
    await passwordOf(page).fill("not the password at all");
    await submit(page).click();
    await expect(page.locator(".alert")).toBeVisible();
    await expect(passwordOf(page)).toHaveValue("");
  });

  test("SMS code through noop: request, read the code from the file, sign in", async ({page}) => {
    await ready(page, "/en/login?step=otp-phone");
    await phoneOf(page).fill(seed.user.phone);
    const mark = smsMark();
    await submit(page).click();
    const code = await smsCode(seed.user.phone, mark);
    await page.locator('input[name="code"]').pressSequentially(code);
    await page.waitForURL("**/en/profiles");
  });

  test("TOTP: the code after the password, then a recovery code on a second sign-in", async ({page, context}) => {
    // One wait for the next TOTP window (up to 30.5 s) sits in the middle, on top of three page flows: the
    // 60 s default of stack mode is not enough, and the cleanup below must still get its turn (wp8-r4-4).
    test.setTimeout(180_000);
    await signInByApi(context.request);
    const {secret, recovery} = await enableTotp(context.request);
    // The page uses the first; the cleanup uses the next two.
    const [forPage, ...spare] = recovery as [string, string, string, ...string[]];
    await context.clearCookies();
    try {
      await ready(page, "/en/login");
      await phoneOf(page).fill(seed.user.phone);
      await passwordOf(page).fill(seed.user.password);
      await submit(page).click();
      await expect(page.locator('input[name="totp_code"]')).toBeVisible();
      // The step that enabled it is spent: wait for the next one.
      await nextStep();
      await page.locator('input[name="totp_code"]').pressSequentially(totp(secret));
      await page.waitForURL("**/en/profiles");

      await context.clearCookies();
      await ready(page, "/en/login");
      await phoneOf(page).fill(seed.user.phone);
      await passwordOf(page).fill(seed.user.password);
      await submit(page).click();
      await page.getByRole("button", {name: "Use a recovery code", exact: true}).click();
      await page.locator('input[name="recovery_code"]').fill(forPage);
      await submit(page).click();
      await page.waitForURL("**/en/profiles");
    } finally {
      await removeTotp(context, [spare[0], spare[1]]);
    }
  });
});

test.describe("forgot password", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("number, SMS code, new password, then the new password signs in; the old one is put back", async ({page, context}) => {
    const next = "Reset-Orchid-Lantern-2026";
    await ready(page, "/en/forgot-password");
    await phoneOf(page).fill(seed.user.phone);
    const mark = smsMark();
    await submit(page).click();
    await page.locator('input[name="code"]').pressSequentially(await smsCode(seed.user.phone, mark));
    await page.locator('input[name="new_password"]').fill(next);
    await submit(page).click();
    // The done title, not "a level 1 heading": every step of the flow has one, so that held on any page.
    await expect(page.getByRole("heading", {level: 1, name: "Password changed"})).toBeVisible();
    await page.getByRole("link", {name: "Go to sign in", exact: true}).click();
    await page.waitForURL("**/en/login");

    // The new password works, and the old one does not.
    expect((await context.request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: seed.user.password}})).status()).toBe(401);
    expect((await context.request.post("/api/v1/auth/login/password", {data: {phone: seed.user.phone, password: next}})).status()).toBe(200);

    // Put the seeded password back, so the other tests keep working. The password is `next` now, so the
    // reauth proves `next`, and a restore that fails fails this test: a seeded user who kept `next` would
    // break every test after it, in this file and in session.stack.spec.ts, with a 401 that points nowhere.
    await reauth(context.request, next);
    expect((await context.request.post("/api/v1/account/password", {data: {new_password: seed.user.password}})).status(), "the seeded password is restored").toBe(204);
  });
});

test.describe("invite", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("an admin's invite code opens the page, the fragment disappears, and the account is created", async ({page}) => {
    test.skip(!seed.admin.username, "needs E2E_SEED_FILE with the admin");
    // The admin proves a second TOTP code after the one that signed in, which waits for the next window.
    test.setTimeout(120_000);
    const phone = `09${String(Math.floor(Math.random() * 1e9)).padStart(9, "0")}`;
    const admin = await playwrightRequest.newContext({baseURL: "https://admin.localhost", ignoreHTTPSErrors: true});
    try {
      expect(
        (await admin.post("/api/v1/auth/login", {data: {username: seed.admin.username, password: seed.admin.password, totp_code: totp(seed.admin.totp_secret)}})).status(),
      ).toBe(200);
      await nextStep();
      expect((await admin.post("/api/v1/auth/totp/fresh", {data: {code: totp(seed.admin.totp_secret)}})).status()).toBe(200);
      const created = await admin.post("/api/v1/invites", {data: {phone, locale: "en", send_sms: false, ttl_hours: 1}});
      expect(created.status()).toBe(201);
      const {code} = (await created.json()) as {code: string};

      await page.goto(`/en/invite#${code}`);
      await expect(page.locator("bdi").first()).toBeVisible();
      expect(new URL(page.url()).hash).toBe("");
      const mark = smsMark();
      await submit(page).click();
      await page.locator('input[name="code"]').pressSequentially(await smsCode(phone, mark));
      await page.locator('input[name="password"]').fill("Invite-Orchid-Lantern-2026");
      await submit(page).click();
      await page.waitForURL("**/en/profiles");
    } finally {
      await admin.dispose();
    }
  });
});

test.describe("passkey, on Chrome's virtual authenticator (AUTH 7.5)", () => {
  test.use({viewport: {width: 1280, height: 800}});

  test("add a passkey through the API, then sign in with it from the login page", async ({page, context}) => {
    // The cleanup runs whatever happens below: a step that fails must not leave a passkey on the shared user.
    try {
      await signInByApi(context.request);
      await ready(page, "/en/login");
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true},
      });
      await reauth(context.request);
      // Registration: the page runs the browser half with the options the API gave, and sends the result back.
      const added = await page.evaluate(async () => {
        const begin = await (await fetch("/api/v1/account/passkeys/begin", {method: "POST", headers: {"content-type": "application/json"}, body: "{}"})).json();
        const options = (PublicKeyCredential as unknown as {parseCreationOptionsFromJSON(j: unknown): PublicKeyCredentialCreationOptions}).parseCreationOptionsFromJSON(
          begin.options.publicKey,
        );
        const credential = (await navigator.credentials.create({publicKey: options})) as PublicKeyCredential;
        const finish = await fetch("/api/v1/account/passkeys/finish", {
          method: "POST",
          headers: {"content-type": "application/json", "X-Ctrlz-Ticket": begin.ticket},
          body: JSON.stringify((credential as unknown as {toJSON(): unknown}).toJSON()),
        });
        return finish.status;
      });
      expect(added).toBe(201);

      await context.clearCookies();
      await ready(page, "/en/login");
      await page.getByRole("button", {name: /passkey/i}).click();
      await page.waitForURL("**/en/profiles");
      await expect(page.locator(".shell-page")).toBeVisible();
    } finally {
      await removePasskeys(context);
    }
  });
});
