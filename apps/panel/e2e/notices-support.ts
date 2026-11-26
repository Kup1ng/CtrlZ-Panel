import {announcementFixture, meFixture, publicConfigFixture, sessionRowFixture, type Notification} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock, type ApiMock, type MockHandler, type MockKey, type MockReply} from "@ctrlz/api-client/testing/mock.ts";
import type {BrowserContext, Page} from "@playwright/test";

import enShell from "../../../packages/i18n/messages/en/shell.json";
import faShell from "../../../packages/i18n/messages/fa/shell.json";

// Shared by notices.spec.ts and notices.matrix.spec.ts: the security notices of Question 19 (spec 8.5, 8.8) in mock mode.

export const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;
export type Lang = (typeof LANGS)[number]["lang"];

const MESSAGES = {fa: faShell, en: enShell} as const;

/** The text of `shell.<path>` in one language, for messages with no ICU plural; `{name}` arguments are filled in. */
export function shell(lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = MESSAGES[lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`shell.${path} is not a message in ${lang}`);
  return node.replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

export type Handlers = Partial<Record<MockKey, MockHandler | MockReply>>;

/** A signed-in tenant with these notices. The routes the account page asks for are answered too, so a link can be followed. */
export async function openWith(
  context: BrowserContext,
  baseURL: string | undefined,
  options: {notifications?: Notification[]; announcements?: boolean; theme?: "light" | "dark"; handlers?: Handlers} = {},
): Promise<ApiMock> {
  await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
  return installApiMock(context, {
    me: meFixture(options.theme ? {user: {theme: options.theme}} : undefined),
    notifications: options.notifications ?? [],
    announcements: options.announcements ? [announcementFixture()] : [],
    handlers: {
      "GET /auth/config": {body: publicConfigFixture({passkey_enabled: true})},
      "GET /account/sessions": {body: {sessions: [sessionRowFixture({current: true})]}},
      "GET /account/passkeys": {body: {passkeys: []}},
      ...options.handlers,
    },
  });
}

// The sidebar has one bell and the mobile bar another; the one that is on screen is the one a person presses.
export const bell = (page: Page) => page.locator(".shell-bell:visible").first();
export const badge = (page: Page) => bell(page).locator(".badge");
export const securityBlock = (page: Page) => page.getByRole("dialog").getByTestId("security-notices");
export const banners = (page: Page) => page.locator(".banner-stack .banner-stack__item");

export async function openBell(page: Page) {
  await bell(page).getByRole("button").click();
  await page.getByRole("dialog").waitFor();
}

/** The reads that were posted, as notification ids. */
export const reads = (mock: ApiMock) => mock.calls.filter((c) => c.method === "POST" && /^\/notifications\/[^/]+\/read$/.test(c.path)).map((c) => c.path.split("/")[2]);
