import type {BrowserContext} from "@playwright/test";
import {installApiMock, type ApiMock} from "@ctrlz/api-client/testing/mock.ts";

// Shared by dialogs.spec.ts, states.spec.ts and rows.spec.ts (WP7). The checks that used to live
// here (external requests, console errors, CSP violations) are the shared guard of spec 17.2 now.
//
// The pages under test are the feedback lab (`/[locale]/feedback-lab`), which exists only on a
// server started with CTRLZ_LAB=1, and the stub pages of the shell.

export const LANGS = [
  {lang: "fa", dir: "rtl"},
  {lang: "en", dir: "ltr"},
] as const;

export const SCHEMES = ["light", "dark"] as const;

export const LAB = (lang: string, query = "") => `/${lang}/feedback-lab${query}`;

/** A signed-in tenant: the proxy only checks that a session cookie exists, and `/me` is mocked. */
export async function signIn(context: BrowserContext, baseURL: string | undefined): Promise<ApiMock> {
  await context.addCookies([{name: "__Host-ctrlz_session", value: "e2e", domain: new URL(baseURL!).hostname, path: "/", secure: true}]);
  return installApiMock(context);
}
