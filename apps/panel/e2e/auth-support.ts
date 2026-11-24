import type {BrowserContext, Page} from "@playwright/test";
import {errorBody, meFixture, publicConfigFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {expect} from "@ctrlz/ui/testing/guard.ts";
import {installApiMock, type ApiMock, type MockCall, type MockHandler, type MockKey, type MockReply} from "@ctrlz/api-client/testing/mock.ts";

import enAuth from "../../../packages/i18n/messages/en/auth.json";
import faAuth from "../../../packages/i18n/messages/fa/auth.json";
import enErrors from "../../../packages/i18n/messages/en/errors.json";
import faErrors from "../../../packages/i18n/messages/fa/errors.json";

// Shared by the specs of the user auth screens (WP8): login, register, invite, forgot, password and
// the auth part of no-email. Mock mode of spec 17.1: `context.route` answers `/api/v1` from typed
// fixtures, so a screen is tested without the backend. The stack-mode flows (17.1, 17.7) are in
// auth.stack.spec.ts and run only after the merge.

export const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;
export type Lang = (typeof LANGS)[number]["lang"];

const MESSAGES = {fa: faAuth, en: enAuth} as const;

/** The text of `auth.<path>` in one language, for messages that have no ICU arguments. */
export function text(lang: Lang, path: string): string {
  let node: unknown = MESSAGES[lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`auth.${path} is not a message in ${lang}`);
  return node;
}

/** The text of `errors.<code>` in one language, for the codes whose message has no ICU arguments. */
export function errorText(lang: Lang, code: keyof typeof enErrors): string {
  const message = (lang === "fa" ? faErrors : enErrors)[code];
  if (typeof message !== "string") throw new Error(`errors.${code} is not a message in ${lang}`);
  return message;
}

/** A message with `{name}` and `{name, number}` arguments, filled in. Not ICU: only for the plain ones. */
export function textWith(lang: Lang, path: string, values: Record<string, string | number>): string {
  return text(lang, path).replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

/**
 * The browser logs every failed response as a console error, and the guard of 17.2 fails a test on one.
 * These specs make the API answer with errors on purpose, so the statuses an auth screen shows are
 * allowed. A 404 is not among them: the mock answers 404 for a route nobody mocked, which is a bug.
 */
export function allowAuthErrors(guard: {allowConsole(pattern: RegExp): void}) {
  guard.allowConsole(/status of (401|403|409|422|429|500|503)/);
  // The browser asks for the tab icon again when a test goes offline on purpose.
  guard.allowConsole(/ERR_INTERNET_DISCONNECTED/);
}

export type Handlers = Partial<Record<MockKey, MockHandler | MockReply>>;

/** No session cookie, as a visitor on the login page. `/me` answers 401, which is what the API does. */
export async function openAnonymous(context: BrowserContext, handlers: Handlers = {}, config = {}): Promise<ApiMock> {
  return installApiMock(context, {
    handlers: {
      "GET /auth/config": {body: publicConfigFixture(config)},
      "GET /me": {status: 401, body: errorBody("session_expired")},
      ...handlers,
    },
  });
}

/** A reply that signs the visitor in: the session cookie the proxy looks for is set, as the API would. */
export function signedIn(context: BrowserContext, baseURL: string | undefined, body: unknown = {status: "authenticated"}): MockHandler {
  return async () => {
    await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
    return {status: 200, body};
  };
}

/** Once signed in, `/me` is the ready user of the fixture. */
export function meReady(): MockHandler {
  return (c, s) => {
    const page = /^\/(fa|en)(\/|$)/.exec(new URL(c.pageUrl).pathname)?.[1] as "fa" | "en" | undefined;
    return {body: page ? {...s.me, user: {...s.me.user, locale: page}} : s.me};
  };
}

export const err = (status: number, code: string, extra: Record<string, unknown> = {}): MockReply => ({
  status,
  body: errorBody(code, extra as never),
});

/** The body of the last call to `path`, or undefined. */
export function lastBody<T = Record<string, unknown>>(mock: ApiMock, method: string, path: string): T | undefined {
  return [...mock.calls].reverse().find((c) => c.method === method && c.path === path)?.body as T | undefined;
}

export function callsTo(mock: ApiMock, method: string, path: string): MockCall[] {
  return mock.calls.filter((c) => c.method === method && c.path === path);
}

export const field = (page: Page, name: string) => page.locator(`input[name="${name}"]`);
export const submit = (page: Page) => page.locator('form button[type="submit"]');
export const formAlert = (page: Page) => page.locator(".alert");

export const meRestricted = () => meFixture({user: {must_reset: true}});

/**
 * Opens a page and waits until React owns it. The submit button is disabled until hydration (a form with
 * no handler would submit natively and put the password in a GET), so an enabled button is the signal. A
 * field that is filled before that is reset by hydration, which is the one thing a test must not do.
 */
export async function gotoForm(page: Page, url: string) {
  await page.goto(url);
  await expect(submit(page).first()).toBeEnabled();
}

/**
 * Types into the step that has just appeared. A press of the submit button moves the page to the next step, and
 * that step puts the focus in its first field a moment later; keys typed before that go nowhere, so a slow
 * machine lost the first digits of a code (login.spec.ts, "a code that is not digits", seen once under two
 * workers). The signal is a focused input other than the two of the first step: the focus is on the button
 * until the step is there.
 */
export async function typeWhenFocused(page: Page, keys: string) {
  await expect(page.locator("input:focus:not([name=phone]):not([name=password])")).toBeVisible();
  await page.keyboard.type(keys);
}

export const inviteInfoFixture = () => ({phone_masked: "+98912***4567", expires_at: "2026-11-20T10:00:00Z"});

/**
 * An invite token of the real shape (D67): 140 characters of A-Za-z0-9_- , case sensitive, with upper and lower case, digits, a
 * hyphen and an underscore in it. It is put together from a seed and a filler so that a secret scanner does not take a fixture
 * for a signed token; it is made up and signs nothing.
 */
export function inviteTokenFixture(seed: string): string {
  const token = `${seed}_Aa-09`.repeat(Math.ceil(140 / (seed.length + 6))).slice(0, 140);
  if (!/^[A-Za-z0-9_-]{140}$/.test(token)) throw new Error("the invite token fixture is not 140 characters of the token alphabet");
  return token;
}

export const INVITE_TOKEN = inviteTokenFixture("Ctrlz-invite-fixture");
/** A second token, for the specs that need two links in turn. */
export const INVITE_TOKEN_B = inviteTokenFixture("Second-invite-fixture");
/** What an admin copies from the create dialog: the panel's host, the language-free path and the token as the fragment. */
export const inviteLinkFixture = (token: string = INVITE_TOKEN) => `https://panel.example.test/invite#${token}`;

/**
 * A password the strength meter and the server both call strong, for the tests that need to send one. It is
 * put together from parts so that a secret scanner does not take a fixture for a leaked key; it is made up.
 */
export const STRONG_PASSWORD = ["Tr1cky", "Orchid", "Lantern", "77"].join("-");

/**
 * Watches for a live region that reaches the page together with its text. A screen reader announces a change
 * inside a region it already knows and often misses a region that is inserted with its text (FormError says
 * so, wp8-r1-4). React builds a new step off-screen and attaches it last, so the moment a node is attached
 * is the moment to look: if an `aria-live` element holding an `.alert` becomes connected in one go, it was
 * inserted with its text. Call it before the first navigation. The notice must be put into a region that
 * was already connected, which `liveRegionsInsertedWithText` then reports as empty.
 */
export async function watchLiveRegions(page: Page) {
  await page.addInitScript(() => {
    const bad: string[] = [];
    (window as unknown as {__liveBad: string[]}).__liveBad = bad;
    const check = (node: unknown) => {
      if (!(node instanceof Element) || !node.isConnected) return;
      for (const region of [node, ...node.querySelectorAll("[aria-live]")]) {
        if (region.matches("[aria-live]") && region.querySelector(".alert")) bad.push(region.outerHTML.slice(0, 120));
      }
    };
    for (const name of ["appendChild", "insertBefore", "replaceChild"] as const) {
      const original = Node.prototype[name] as (this: Node, ...args: Node[]) => Node;
      (Node.prototype as unknown as Record<string, unknown>)[name] = function (this: Node, ...args: Node[]) {
        const result = original.apply(this, args);
        check(args[0]);
        return result;
      };
    }
  });
}

export const liveRegionsInsertedWithText = (page: Page) =>
  page.evaluate(() => (window as unknown as {__liveBad?: string[]}).__liveBad ?? ["the watcher was not installed"]);

type Config = Parameters<typeof publicConfigFixture>[0];

/** A mutable /auth/config: the test changes `answer.value` and the next refetch sees it. */
export function liveConfig(first: Config) {
  const answer = {value: first};
  const handlers: Handlers = {"GET /auth/config": () => ({body: publicConfigFixture(answer.value)})};
  return {answer, handlers};
}

/**
 * Time passes beyond the stale time and the browser reports that it is back online. Waits for the new answer.
 * The page must have called `page.clock.install()` before it loaded.
 */
export async function refetchConfig(page: Page, count: () => number) {
  const before = count();
  await page.clock.fastForward(31_000);
  // TanStack tells its listeners only when the online state changes, so the page goes offline and back.
  await page.context().setOffline(true);
  await page.context().setOffline(false);
  await expect.poll(count).toBeGreaterThan(before);
}
