import {THEME_SET, type ResolvedMode, type ThemeMode} from "./config.ts";

// Spec 5.2. The stock `light` or `dark` class stays on next to the set class because HeroUI's own
// dark selectors read `.dark ...`. `data-theme` takes the stock name, which is what HeroUI's base
// theme keys on. The names are the ones the Flat set has always had, so no stylesheet selector moved.
const NAMES: Record<ResolvedMode, {classes: readonly string[]; dataTheme: string}> = {
  light: {classes: ["light", `${THEME_SET}-light`], dataTheme: "light"},
  dark: {classes: ["dark", `${THEME_SET}-dark`], dataTheme: "dark"},
};

/** Every class the controller may add, so a swap removes exactly the old ones and leaves the font class alone. */
export const ALL_THEME_CLASSES = ["light", "dark", "flat-light", "flat-dark"] as const;

export function themeNames(resolved: ResolvedMode) {
  return NAMES[resolved];
}

export type ThemeHtmlProps = {className: string; "data-theme": string | undefined};

/**
 * Props for <html>. For `light` and `dark` the server renders the final classes,
 * so the first paint needs no script. For `system` with no `resolved` value it
 * renders none, and ThemeScript picks them before <body> is parsed.
 */
export function themeHtmlProps(mode: ThemeMode, resolved?: ResolvedMode): ThemeHtmlProps {
  const effective: ResolvedMode | undefined = mode === "system" ? resolved : mode;
  if (!effective) return {className: "", "data-theme": undefined};
  const names = NAMES[effective];
  return {className: names.classes.join(" "), "data-theme": names.dataTheme};
}
