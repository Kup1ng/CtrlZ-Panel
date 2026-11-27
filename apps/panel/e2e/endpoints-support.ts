import type {Page} from "@playwright/test";
import {uid} from "@ctrlz/api-client/testing/screenFixtures.ts";

import enEndpoints from "../../../packages/i18n/messages/en/endpoints.json";
import faEndpoints from "../../../packages/i18n/messages/fa/endpoints.json";

import type {Lang} from "./profiles-support.ts";

// What the specs of the Endpoint screens (P3) share, in mock mode. The tenant, the stateful mock and the text helper are those of
// `profiles-support.ts` (one mock answers every route of P2 and P3, so a profile page and an Endpoint page can be walked in one test).
//
//   const mock = await openEndpoints(context, baseURL, {clients: 1000});
//   await page.goto(endpointPath("fa", ENDPOINT.home, "clients"));

export {LANGS, SCHEMES, openProfiles as openEndpoints, screen, type Lang} from "./profiles-support.ts";

/** The Endpoints of `endpointsFixture()`: Home router (1,000 clients, three authorized addresses, four claims), Laptop (two profiles), Office PC (locked profile, schedule), New phone (pending), Held router, Soft off, Hard off. */
export const ENDPOINT = {home: uid("ep", 1), laptop: uid("ep", 2), office: uid("ep", 3), pending: uid("ep", 4), held: uid("ep", 5), soft: uid("ep", 6), hard: uid("ep", 7), unknown: uid("ep", 999)} as const;
export const GROUP = {home: uid("gr", 1), unknown: uid("gr", 999)} as const;
export const CLAIM = {active: uid("ic", 1), pending: uid("ic", 2), grace: uid("ic", 3), suspended: uid("ic", 4)} as const;
export const AUTHORIZED = {current: uid("au", 1)} as const;

export const ENDPOINT_TABS = ["clients", "ips", "schedule"] as const;
export const endpointsPath = (lang: Lang) => `/${lang}/endpoints`;
export const endpointPath = (lang: Lang, id: string, tab: (typeof ENDPOINT_TABS)[number] | "" = "") => `/${lang}/endpoints/${id}${tab ? `/${tab}` : ""}`;
/** The dialogs of an Endpoint are two parameters in one address (dialog/useDeviceDialog.ts). */
export const deviceDialogPath = (lang: Lang, dialog: string, id?: string) => `/${lang}/endpoints?deviceDialog=${dialog}${id ? `&deviceId=${id}` : ""}`;
/** A share page, with the link value in the path (it is a secret: the page sends it in a body and in no URL). */
export const sharePath = (lang: Lang, link: string) => `/${lang}/s/${link}`;

const MESSAGES = {fa: faEndpoints, en: enEndpoints} as const;

/** The text of `endpoints.<path>` in one language, for messages with no ICU plural; `{name}` arguments are filled in. */
export function endpointsText(lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = MESSAGES[lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`endpoints.${path} is not a message in ${lang}`);
  return node.replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

export const endpointTabs = (page: Page, lang: Lang, name: string) => page.getByRole("navigation", {name: endpointsText(lang, "frame.tabsLabel", {name})});
export const endpointActions = (page: Page) => page.getByTestId("endpoint-actions");
