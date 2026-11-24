import {useLocale} from "react-aria-components";

// HeroUI's `placement` props are physical in three places: Sheet, Sidebar.Tooltip
// and Badge. Logical words ("top start") are accepted by Popover and Dropdown, so
// those never come through here. Lint bans a bare `left` or `right` in any
// `placement` prop (spec 8.2): this file is the one place that writes them.

export type Dir = "ltr" | "rtl";
export type InlineEdge = "start" | "end";
export type PhysicalEdge = "left" | "right";

/** The physical edge that a logical inline edge is, in a writing direction. */
export function physicalEdge(edge: InlineEdge, dir: Dir): PhysicalEdge {
  const startIsLeft = dir === "ltr";
  return (edge === "start") === startIsLeft ? "left" : "right";
}

/**
 * The shell puts the sidebar on the inline start in both directions, so the
 * content lies toward the inline end. A tooltip that must not cover the content
 * opens toward `content`.
 */
export function edgeToward(target: "content" | "sidebar", dir: Dir): PhysicalEdge {
  return physicalEdge(target === "content" ? "end" : "start", dir);
}

export type BadgePlacement = "top-right" | "top-left" | "bottom-right" | "bottom-left";

/** Badge placements are physical. This maps "top, inline end" to the right one. */
export function badgePlacement(vertical: "top" | "bottom", edge: InlineEdge, dir: Dir): BadgePlacement {
  return `${vertical}-${physicalEdge(edge, dir)}`;
}

/** The writing direction React Aria derived from the locale of `I18nProvider`. */
export function useDirection(): Dir {
  return useLocale().direction;
}

/** Physical edge for a logical one, in the current direction. */
export function useLogicalEdge(edge: InlineEdge): PhysicalEdge {
  return physicalEdge(edge, useDirection());
}
