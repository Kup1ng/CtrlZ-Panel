import {adminMeFixture, errorBody} from "@ctrlz/api-client/testing/fixtures.ts";
import {alertFixture, type AlertRow} from "@ctrlz/api-client/testing/adminFixtures.ts";
import {installApiMock, type ApiMock, type MockHandler, type MockKey, type MockReply} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";
import {expect} from "@ctrlz/ui/testing/guard.ts";

import enAdmin from "../../../packages/i18n/messages/en/admin.json";
import faAdmin from "../../../packages/i18n/messages/fa/admin.json";
import enAuth from "../../../packages/i18n/messages/en/auth.json";
import faAuth from "../../../packages/i18n/messages/fa/auth.json";
import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";
import enShell from "../../../packages/i18n/messages/en/shell.json";
import faShell from "../../../packages/i18n/messages/fa/shell.json";
import enNodes from "../../../packages/i18n/messages/en/nodes.json";
import faNodes from "../../../packages/i18n/messages/fa/nodes.json";
import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";

// Shared by the admin specs (WP10). Mock mode of spec 17.1: `context.route` answers `/api/v1` from typed fixtures. The
// panel's mock (`installApiMock`) serves both apps, since the two APIs share the `/api/v1` prefix; the admin's `/me`
// and every list are handlers here. The flows that need the real API (the TOTP of a real authenticator, a real session
// cookie over HTTPS, the cookie rotation of a password change) are in `admin.stack.spec.ts` and run after the merge.

export const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;
export type Lang = (typeof LANGS)[number]["lang"];

const FILES = {
  admin: {fa: faAdmin, en: enAdmin},
  auth: {fa: faAuth, en: enAuth},
  errors: {fa: faErrors, en: enErrors},
  common: {fa: faCommon, en: enCommon},
  nodes: {fa: faNodes, en: enNodes},
  shell: {fa: faShell, en: enShell},
} as const;

/** The text of `<ns>.<path>` in one language, for messages without plurals; `{name}` and `{name, number}` are filled in. */
function message(ns: keyof typeof FILES, lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = FILES[ns][lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`${ns}.${path} is not a message in ${lang}`);
  // `<cmd>{command}</cmd>` is a rich tag: only the argument is text.
  return node.replace(/<\/?\w+>/g, "").replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

/** `admin.<path>` */
export const adm = (lang: Lang, path: string, values?: Record<string, string | number>) => message("admin", lang, path, values);
/** `nodes.<path>`, the P4 pages. Plurals are not filled in: a spec that needs one reads the number from the page. */
export const nodesText = (lang: Lang, path: string, values?: Record<string, string | number>) => message("nodes", lang, path, values);
export const authText = (lang: Lang, path: string, values?: Record<string, string | number>) => message("auth", lang, path, values);
export const errText = (lang: Lang, code: string, values?: Record<string, string | number>) => message("errors", lang, code, values);
export const shellText = (lang: Lang, path: string, values?: Record<string, string | number>) => message("shell", lang, path, values);
export const commonText = (lang: Lang, path: string) => message("common", lang, path);

export type Handlers = Partial<Record<MockKey, MockHandler | MockReply>>;
type AdminMe = ReturnType<typeof adminMeFixture>;

export const err = (status: number, code: string, extra: Record<string, unknown> = {}): MockReply => ({status, body: errorBody(code, extra as never)});

/** A login that works: the body, and the session cookie the real API sets, which is what lets the proxy through afterwards. */
export const loginOk = (state: "ready" | "setup_required"): MockReply => ({
  body: {state},
  headers: {"set-cookie": "__Host-ctrlz_admin=e2e; Path=/; Secure; HttpOnly; SameSite=Strict"},
});

// What POST /invites answers (D67): the id and the link, once. The token is made up from a seed (140 characters of the token
// alphabet, so that a secret scanner does not take it for a signed one) and signs nothing.
export const INVITE_TOKEN = (`${"Admin-invite-fixture"}_Aa-09`).repeat(6).slice(0, 140);
export const INVITE_LINK = `https://panel.example.ir/invite#${INVITE_TOKEN}`;
export const INVITE_CREATED = {id: "10000000-0000-4000-8000-0000000000a9", link: INVITE_LINK};

export const STRONG_PASSWORD = "k7#Vq2!mZp9@Lw4$Xt";
export const TOTP_URI = "otpauth://totp/Ctrl%20Z:admin?secret=JBSWY3DPEHPK3PXP&issuer=Ctrl%20Z&period=30&digits=6&algorithm=SHA1";

/**
 * The browser logs every failed response as a console error, and the guard of 17.2 fails a test on one. These specs make
 * the API answer with errors on purpose, so the statuses a screen shows are allowed. A 404 is not among them: the mock
 * answers 404 for a route nobody mocked, which is a bug.
 */
export function allowAdminErrors(guard: {allowConsole(pattern: RegExp): void}) {
  guard.allowConsole(/status of (400|401|403|409|422|429|500|503)/);
}

export type AdminMock = ApiMock & {
  /** The admin the API says is signed in. A test changes it to move the account through setup. */
  me: {current: AdminMe};
  alerts: {current: AlertRow[]};
};

/** An empty page of the lists every shell route asks for, so a screen that is not under test never meets a 404 from the mock. */
const EMPTY_LISTS: Handlers = {
  "GET /users": {body: {items: []}},
  "GET /invites": {body: {items: []}},
  "GET /audit": {body: {items: []}},
  "GET /sms/gateways": {body: {items: []}},
  "GET /sms/templates": {body: {items: []}},
  // P4: the pages every shell route can land on, so the root of the admin (Overview) never meets a 404 from the mock.
  "GET /overview": {body: {nodes: [], config_head: 0, free_dns: {enabled: true, qps: 1000, version: 1}}},
  "GET /free-dns/counters": {body: {items: []}},
  "GET /nodes": {body: {items: []}},
  "GET /nodes/addresses-given-up": {body: {items: []}},
  "GET /pairs": {body: {items: []}},
  "GET /node-enrollments": {body: {items: []}},
  "GET /settings/free-dns": {body: {enabled: true, qps: 1000, version: 1}},
};

/**
 * A signed-in admin: the session cookie that lets the proxy through (the API decides what it is worth) and the mock.
 * `me` overrides the fixture; `handlers` add or replace routes. The mock serves `/me` and `/alerts` from `mock.me` and
 * `mock.alerts`, so a test can change them and reload.
 */
export async function openAdmin(
  context: BrowserContext,
  baseURL: string | undefined,
  options: {me?: Partial<AdminMe>; alerts?: AlertRow[]; handlers?: Handlers; cookie?: boolean} = {},
): Promise<AdminMock> {
  if (options.cookie !== false) {
    await context.addCookies([{name: "__Host-ctrlz_admin", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true, sameSite: "Strict"}]);
  }
  const me = {current: adminMeFixture(options.me)};
  const alerts = {current: options.alerts ?? []};
  const mock = await installApiMock(context, {
    handlers: {
      ...EMPTY_LISTS,
      "GET /me": () => ({body: me.current}),
      "GET /alerts": () => ({body: {items: alerts.current}}),
      "POST /auth/logout": {status: 204},
      "POST /me/notices/ack": {status: 204},
      ...options.handlers,
    },
  });
  return Object.assign(mock, {me, alerts});
}

export const bodies = (mock: ApiMock, method: string, path: string): unknown[] => mock.calls.filter((c) => c.method === method && c.path === path).map((c) => c.body);

/** Types a six-digit code into the OTP field with this name. */
export async function typeCode(page: Page, name: string, code: string) {
  const input = page.locator(`input[name="${name}"]`);
  await input.focus();
  await page.keyboard.type(code);
}

/** A page's heading, the one `h1` of the content. */
export const heading = (page: Page) => page.getByRole("heading", {level: 1});

/** Waits for the shell: the sidebar's main navigation and the page's own heading. */
export async function gotoShell(page: Page, lang: Lang, path: string, title: string) {
  await page.goto(`/${lang}${path}`);
  await expect(page.getByRole("heading", {level: 1, name: title})).toBeVisible();
}

export const alertOf = (over: Partial<AlertRow> = {}) => alertFixture(over);
