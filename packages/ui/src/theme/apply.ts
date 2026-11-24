import type {ResolvedMode} from "./config.ts";
import {ALL_THEME_CLASSES, themeNames} from "./html.ts";

/**
 * Sets the theme classes directly on <html>. Used by useTheme.
 *
 * `data-theme-switching` is on for one frame so base.css can turn transitions off.
 */
export function applyTheme(resolved: ResolvedMode, root: HTMLElement = document.documentElement) {
  const names = themeNames(resolved);
  root.setAttribute("data-theme-switching", "");
  root.classList.remove(...ALL_THEME_CLASSES);
  root.classList.add(...names.classes);
  root.setAttribute("data-theme", names.dataTheme);
  // Two frames: the first lets the new styles compute with transitions off.
  requestAnimationFrame(() => requestAnimationFrame(() => root.removeAttribute("data-theme-switching")));
}
