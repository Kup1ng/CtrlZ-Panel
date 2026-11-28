import {errorBody, meFixture, passkeyRowFixture, publicConfigFixture, sessionRowFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock, type ApiMock, type MockHandler, type MockKey, type MockReply} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expect} from "@ctrlz/ui/testing/guard.ts";

import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";
import enAccount from "../../../packages/i18n/messages/en/account.json";
import faAccount from "../../../packages/i18n/messages/fa/account.json";

// Shared by account.spec.ts and account.matrix.spec.ts (WP9). Mock mode of spec 17.1: the page is tested
// with `context.route` answering `/api/v1` from typed fixtures. The stack-mode flows are in
// account.stack.spec.ts and run only after the merge.

export const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;
export type Lang = (typeof LANGS)[number]["lang"];

const MESSAGES = {fa: faAccount, en: enAccount} as const;

/** The text of `account.<path>` in one language, for messages without ICU plurals; `{name}` arguments are filled in. */
export function acc(lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = MESSAGES[lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`account.${path} is not a message in ${lang}`);
  return node.replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

/** The text of `errors.fields.<code>`, the line under a field the server found fault with. */
export function fieldText(lang: Lang, code: keyof typeof enErrors.fields): string {
  return (lang === "fa" ? faErrors : enErrors).fields[code];
}

export type Handlers = Partial<Record<MockKey, MockHandler | MockReply>>;
type MeOver = Parameters<typeof meFixture>[0];

export const SESSION_CURRENT = "10000000-0000-4000-8000-000000000001";
export const SESSION_OLDER = "10000000-0000-4000-8000-000000000002";
export const SESSION_NEWER = "10000000-0000-4000-8000-000000000003";

export const sessionsFixture = () => [
  sessionRowFixture({id: SESSION_CURRENT, current: true, created_at: "2026-11-10T09:00:00Z", last_seen_at: "2026-11-17T09:00:00Z", ip: "203.0.113.9"}),
  sessionRowFixture({id: SESSION_OLDER, created_at: "2026-11-01T09:00:00Z", auth_method: "otp", ip: "198.51.100.4"}),
  sessionRowFixture({id: SESSION_NEWER, created_at: "2026-11-12T09:00:00Z", auth_method: "passkey", ip: "192.0.2.77"}),
];

export const PK_A = "20000000-0000-4000-8000-00000000000a";
export const PK_B = "20000000-0000-4000-8000-00000000000b";
export const PK_STALE = "20000000-0000-4000-8000-00000000000c";
export const PK_NEW = "20000000-0000-4000-8000-00000000000d";

/** Two live passkeys, one synced and one not, and a third that has gone stale. */
export const passkeysFixture = () => [
  passkeyRowFixture({id: PK_A, name: "Work laptop", backup_eligible: true, last_used_at: "2026-11-15T10:00:00Z"}),
  passkeyRowFixture({id: PK_B, name: "Security key", backup_eligible: false}),
];

export const err = (status: number, code: string, extra: Record<string, unknown> = {}): MockReply => ({
  status,
  body: errorBody(code, extra as never),
});

/**
 * The browser logs every failed response as a console error, and the guard of 17.2 fails a test on one.
 * These specs make the API answer with errors on purpose, so the statuses an Account row shows are
 * allowed. A 404 is not among them: the mock answers 404 for a route nobody mocked, which is a bug.
 */
export function allowAccountErrors(guard: {allowConsole(pattern: RegExp): void}) {
  guard.allowConsole(/status of (401|403|409|422|429|500|503)/);
}

/** A signed-in tenant on the Account page. `me` overrides the fixture; `handlers` add or replace routes. */
export async function open(
  context: BrowserContext,
  baseURL: string | undefined,
  options: {me?: MeOver; passkeyEnabled?: boolean; handlers?: Handlers} = {},
): Promise<ApiMock> {
  await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
  return installApiMock(context, {
    me: meFixture(options.me),
    handlers: {
      "GET /auth/config": {body: publicConfigFixture({passkey_enabled: options.passkeyEnabled ?? true})},
      "GET /account/sessions": {body: {sessions: sessionsFixture()}},
      "GET /account/passkeys": {body: {passkeys: []}},
      "POST /auth/reauth": {status: 204},
      ...options.handlers,
    },
  });
}

export async function gotoAccount(page: Page, lang: Lang) {
  await page.goto(`/${lang}/preferences/account`);
  // The rows are drawn from `/me` in the browser, so a visible row means React owns the page.
  await expect(page.locator('[data-row-id="phone"]')).toBeVisible();
}

export const row = (page: Page, id: string) => page.locator(`[data-row-id="${id}"]`);

/** The bodies sent to a route, in order. */
export function bodies(mock: ApiMock, method: string, path: string): unknown[] {
  return mock.calls.filter((c) => c.method === method && c.path === path).map((c) => c.body);
}

/** Types a six-digit code into the OTP field with this name. */
export async function typeCode(page: Page, name: string, code: string) {
  const input = page.locator(`input[name="${name}"]`);
  await input.focus();
  await page.keyboard.type(code);
}

/**
 * Posts on the session channel (`login` or `logout`) from a tab that runs none of our code: an image document of the same origin. A page of
 * the app hears the message too, from its own channel, and leaves for the login page at once, so an `evaluate` that posted from it lost its
 * execution context whenever that navigation won the race against the reply (a failure of the full run under load, gate-r3). A sender that
 * cannot react is the same message with nothing to race.
 */
export async function broadcastFromBareTab(context: BrowserContext, guard: CspSink, message: "login" | "logout") {
  const bare = await openBareTab(context, guard);
  await bare.evaluate((m) => new BroadcastChannel("ctrlz-session").postMessage(m), message);
  await closeBareTab(bare, guard);
}

type CspSink = {consume(kind: "csp"): string[]; allowConsole(pattern: RegExp): void};

/**
 * An image document of the same origin, as a tab that runs none of our code. Through Caddy /logo.png carries the default policy
 * (`default-src 'none'`, merge item A3), and Chrome's own image viewer styles its <img> with an inline style attribute, which that policy
 * refuses: one `style-src-attr` violation for each such document. It is the browser's page and not ours, and `next start`, which sends no
 * policy on a file of public/, never showed it (found by the first run through Caddy). The guard stays whole for everything else: what was
 * recorded before the tab opened must be empty, and after it closes only that one directive may have come from it.
 */
export async function openBareTab(context: BrowserContext, guard: CspSink): Promise<Page> {
  expect(guard.consume("csp"), "a CSP violation was recorded before the bare tab opened").toEqual([]);
  // Chrome also writes each refusal to the console as an error. The text names the policy of an answer that skipped the proxy, which no page of ours has.
  guard.allowConsole(/^Applying inline style violates the following Content Security Policy directive 'default-src 'none''/);
  const bare = await context.newPage();
  await bare.goto("/logo.png");
  return bare;
}

export async function closeBareTab(bare: Page, guard: CspSink) {
  await bare.close();
  expect(guard.consume("csp").filter((directive) => directive !== "style-src-attr"), "a CSP violation other than the image viewer's inline style").toEqual([]);
}

export const NEW_PHONE = "09351234567";
export const TOTP_URI = "otpauth://totp/Ctrl%20Z:0912***4567?secret=JBSWY3DPEHPK3PXP&issuer=Ctrl%20Z&period=30&digits=6&algorithm=SHA1";
