import type {BrowserContext, Page} from "@playwright/test";
import {meFixture} from "@ctrlz/api-client/testing/fixtures.ts";
import {installApiMock, type ApiMock, type MockHandler, type MockKey, type MockReply} from "@ctrlz/api-client/testing/mock.ts";
import {createScreenState, LOCK_PASSWORD, screenHandlers, type ScreenOptions, type ScreenState} from "@ctrlz/api-client/testing/screenMock.ts";
import {uid} from "@ctrlz/api-client/testing/screenFixtures.ts";

import enProfiles from "../../../packages/i18n/messages/en/profiles.json";
import faProfiles from "../../../packages/i18n/messages/fa/profiles.json";
import enCommon from "../../../packages/i18n/messages/en/common.json";
import faCommon from "../../../packages/i18n/messages/fa/common.json";
import enJobs from "../../../packages/i18n/messages/en/jobs.json";
import faJobs from "../../../packages/i18n/messages/fa/jobs.json";
import enRules from "../../../packages/i18n/messages/en/rules.json";
import faRules from "../../../packages/i18n/messages/fa/rules.json";
import enServices from "../../../packages/i18n/messages/en/services.json";
import faServices from "../../../packages/i18n/messages/fa/services.json";

// What the specs of the profile screens (P2) share, in mock mode (spec 17.1): the signed-in tenant with a stateful mock of every
// route of P2 and P3 (`screenHandlers`), the ids of the fixture, the paths of the screens, and the words of the messages, so a
// spec asserts a sentence by its key and not by a string typed twice.
//
//   const mock = await openProfiles(context, baseURL, {rules: 500});
//   await page.goto(profilePath("fa", PROFILE.home, "filters"));
//
// `mock.state` is the state the handlers keep: a case can change it before it loads a page (`state.profiles[1].locked = false`), and read
// it after a write (`state.filters.get(PROFILE.home)`).

export const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;
export type Lang = (typeof LANGS)[number]["lang"];
export const SCHEMES = ["light", "dark"] as const;

/** The profiles of `profilesFixture()`: Home (kids, two Endpoints, five filters, 10,000 rules), Office (locked), Gaming (disabled), Travel (redirects), a Persian name. */
export const PROFILE = {home: uid("pr", 1), office: uid("pr", 2), gaming: uid("pr", 3), travel: uid("pr", 4), persian: uid("pr", 5), unknown: uid("pr", 999)} as const;
/** The folders of profile Home. */
export const FOLDER = {work: uid("fo", 1), streaming: uid("fo", 2), noLogs: uid("fo", 3), gone: uid("fo", 4), unknown: uid("fo", 999)} as const;
export {LOCK_PASSWORD};

export const PROFILE_TABS = ["filters", "services", "custom-rules", "options"] as const;
export const profilesPath = (lang: Lang) => `/${lang}/profiles`;
export const profilePath = (lang: Lang, id: string, tab: (typeof PROFILE_TABS)[number] | "filters/third-party" | "" = "") => `/${lang}/profiles/${id}${tab ? `/${tab}` : ""}`;
export const folderPath = (lang: Lang, id: string, folderId: string) => `/${lang}/profiles/${id}/custom-rules/${folderId}`;

const MESSAGES = {fa: {profiles: faProfiles, rules: faRules, services: faServices, jobs: faJobs}, en: {profiles: enProfiles, rules: enRules, services: enServices, jobs: enJobs}} as const;
type Namespace = keyof (typeof MESSAGES)["en"];

/** The visible word of a button the in-place forms share (`common`), which starts its accessible name: "Save: Block TTL". */
export const commonWord = (lang: Lang, key: "save" | "cancel"): string => (lang === "fa" ? faCommon : enCommon)[key];

/** The text of `<namespace>.<path>` in one language, for messages with no ICU plural; `{name}` arguments are filled in. */
export function text(lang: Lang, namespace: Namespace, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = MESSAGES[lang][namespace];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`${namespace}.${path} is not a message in ${lang}`);
  return node.replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

export type Handlers = Partial<Record<MockKey, MockHandler | MockReply>>;
export type ScreensMock = ApiMock & {screens: ScreenState};

/** A signed-in tenant over the stateful mock of the screens. `handlers` override any route. */
export async function openProfiles(
  context: BrowserContext,
  baseURL: string | undefined,
  options: ScreenOptions & {handlers?: Handlers; theme?: "light" | "dark"} = {},
): Promise<ScreensMock> {
  await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
  const {handlers, theme, ...scenario} = options;
  const screens = createScreenState(scenario);
  const mock = await installApiMock(context, {
    ...(theme ? {me: meFixture({user: {theme}})} : {}),
    handlers: {...screenHandlers(screens), ...handlers},
  });
  return Object.assign(mock, {screens});
}

/** The profile frame's header, tabs and lock banner, by the roles the frame gives them. */
export const profileHeader = (page: Page) => page.locator("header.page-header");
export const profileActions = (page: Page) => page.getByTestId("profile-actions");
/** The pill tabs: a navigation of links, the current one with aria-current (screens/FrameTabs.tsx). */
export const profileTabs = (page: Page, lang: Lang, name: string) => page.getByRole("navigation", {name: text(lang, "profiles", "frame.tabsLabel", {name})});
export const lockBanner = (page: Page) => page.locator(".profile-frame__lock");
/** The lane screen that the page renders, by its `data-screen` (screens/lanes.ts). */
export const screen = (page: Page, name: string) => page.locator(`[data-screen="${name}"]`);
