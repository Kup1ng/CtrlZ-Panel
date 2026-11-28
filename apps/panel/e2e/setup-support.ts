import type {Page} from "@playwright/test";
import {VALID_SHARE_LINK} from "@ctrlz/api-client/testing/screenMock.ts";

import enSetup from "../../../packages/i18n/messages/en/setup.json";
import faSetup from "../../../packages/i18n/messages/fa/setup.json";

import type {Lang} from "./profiles-support.ts";

// What the specs of the setup screens (P3: Resolvers, Help Me Configure, the share page, the verification) share, in mock mode.
// `openEndpoints(context, baseURL, {resolverNotReady: true})` gives a deployment with no DNS zone: the view says it is not ready and every
// generator answers 409 `setup_unavailable`. The verification probe of spec p3 8.4 is a request to `https://<label>.verify.<zone>/v`, which is
// another origin: a spec answers it through `stubVerify`, which is a route that the guard of 17.2 allows only through `guard.consume`.

export {VALID_SHARE_LINK};
/** A well-formed link value that the mock does not know: the page shows the same "not found" as for any dead link. */
export const DEAD_SHARE_LINK = "d".repeat(64);

const MESSAGES = {fa: faSetup, en: enSetup} as const;

/** The text of `setup.<path>` in one language, for messages with no ICU plural. */
export function setupText(lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = MESSAGES[lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`setup.${path} is not a message in ${lang}`);
  return node.replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

/** The steps of the verification, as the scripted answers of the stub zone give them (Pending, Partial, Success). */
export type VerifyAnswer = {resolver_id: string; client?: string};

/**
 * Not installed here: the guard of 17.2 fails any request outside the page's origin, and the verification probe is one by design (spec
 * p3 8.4). The spec of the verification lane installs the route through the guard's one door for it (`isVerifyProbe`, which is false until
 * P4 enables it) when that lane lands, with the three answers below. The foundation only names them, so the lane's cases and the stub agree.
 */
export const VERIFY_ANSWERS = {
  pending: [] as VerifyAnswer[],
  partial: [{resolver_id: "r00000001"}] as VerifyAnswer[],
  success: [{resolver_id: "r00000001", client: "device-1"}] as VerifyAnswer[],
} as const;

/** The screen of the wizard, found by its `step` and `setupOs` in the address (FE 9). */
export const wizardPath = (lang: Lang, endpointId: string, os: string, step: number) =>
  `/${lang}/endpoints?deviceDialog=configure&deviceId=${endpointId}&setupOs=${os}&step=${step}`;
export const noExternal = (page: Page) => page.evaluate(() => performance.getEntriesByType("resource").every((r) => new URL(r.name).origin === location.origin));
