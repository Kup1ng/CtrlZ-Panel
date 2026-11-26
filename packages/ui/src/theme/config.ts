export type ThemeMode = "light" | "dark" | "system";
export type ResolvedMode = "light" | "dark";

// D17: the owner chose Flat on 2026-11-07, and Glass is gone: there is no Glass stylesheet, so no
// other value can be selected. The constant stays because the class names are built from it
// (html.ts), and it is the one word to read when asking "which set is live".
export const THEME_SET = "flat";

/** The cookie that holds the mode. Not secret. A cookie, not localStorage, so the server can render the right class on the first byte. */
export const THEME_COOKIE = "ctrlz_theme";
export const THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

export function parseThemeMode(value: string | null | undefined): ThemeMode {
  return value === "light" || value === "dark" ? value : "system";
}
