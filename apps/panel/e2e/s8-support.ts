import type {Page} from "@playwright/test";

import enApi from "../../../packages/i18n/messages/en/api.json";
import faApi from "../../../packages/i18n/messages/fa/api.json";
import enShell from "../../../packages/i18n/messages/en/shell.json";
import faShell from "../../../packages/i18n/messages/fa/shell.json";

import type {Lang} from "./profiles-support.ts";

// What the specs of package S8 share (the API tokens page, the docs, the status page, the logo menu and the feedback dialog): the words of the `api`
// and `shell` messages, so a spec asserts a sentence by its key and not by a string typed twice, and the paths of the pages.

const MESSAGES = {api: {fa: faApi, en: enApi}, shell: {fa: faShell, en: enShell}} as const;

/** The text of `<namespace>.<path>` in one language, for messages with no ICU plural; `{name}` arguments are filled in. */
export function words(namespace: "api" | "shell", lang: Lang, path: string, values: Record<string, string | number> = {}): string {
  let node: unknown = MESSAGES[namespace][lang];
  for (const part of path.split(".")) node = (node as Record<string, unknown> | undefined)?.[part];
  if (typeof node !== "string") throw new Error(`${namespace}.${path} is not a message in ${lang}`);
  return node.replace(/\{(\w+)(?:,\s*\w+)?\}/g, (_, key: string) => String(values[key] ?? ""));
}

export const apiText = (lang: Lang, path: string, values?: Record<string, string | number>) => words("api", lang, path, values);
export const shellText = (lang: Lang, path: string, values?: Record<string, string | number>) => words("shell", lang, path, values);

export const tokensPath = (lang: Lang) => `/${lang}/preferences/api`;
export const docsPath = (lang: Lang) => `/${lang}/docs`;
export const apiDocsPath = (lang: Lang) => `/${lang}/docs/api`;
export const statusPath = (lang: Lang) => `/${lang}/status`;

/** The password of the reauth dialog, which the mock accepts. */
export const REAUTH_PASSWORD = "Correct-Horse-9";

/** The row of one token of `apiTokensFixture()` by its name. */
export const tokenRow = (page: Page, name: string) => page.locator("li[data-token]").filter({has: page.getByText(name, {exact: true})});

/** The logo menu's trigger: on a phone it lives in the sidebar panel that the hamburger opens, on a wider screen it is in the sidebar itself. */
export const logoButton = (page: Page, lang: Lang) => page.getByRole("button", {name: shellText(lang, "logoMenu.label")}).filter({visible: true}).first();

/** Opens the logo menu from a freshly loaded page, through the hamburger below 768 px. */
export async function openLogoMenu(page: Page, lang: Lang) {
  const width = page.viewportSize()?.width ?? 1280;
  if (width < 768) await page.getByRole("button", {name: shellText(lang, "sidebar.openMenu")}).click();
  await logoButton(page, lang).click();
}

/** The words of common.retry: the button of a failed section. */
export const retryLabel = (lang: Lang) => (lang === "fa" ? "تلاش دوباره" : "Try again");
