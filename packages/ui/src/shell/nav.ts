import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";

// Navigation is data, so the admin shell (WP10, apps/admin/src/nav.ts) renders
// through the same sidebar with its own list. Labels are already translated: the
// server layout builds the list with its own translator and passes plain data
// across the client boundary.

export type NavLink = {
  kind: "link";
  id: string;
  /** Without the locale: "/profiles". */
  href: string;
  label: string;
  icon: GeneralIconName;
  /** Key into useShellCounts(). Absent means this item never has a counter. */
  countKey?: string;
};

/** An item that opens something instead of going somewhere. `id` picks the handler in ShellSidebar. */
export type NavAction = {
  kind: "action";
  id: "logout";
  label: string;
  icon: GeneralIconName;
};

export type NavGroup = {
  kind: "group";
  id: string;
  label: string;
  icon: GeneralIconName;
  items: (NavLink | NavAction)[];
};

export type NavItem = NavLink | NavAction | NavGroup;

export function isCurrentPath(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}

/** Ids of the groups that hold the current page, so they start open. */
export function groupsHolding(nav: NavItem[], pathname: string): string[] {
  return nav
    .filter((item): item is NavGroup => item.kind === "group")
    .filter((g) => g.items.some((i) => i.kind === "link" && isCurrentPath(pathname, i.href)))
    .map((g) => g.id);
}

/** Flat list of every link, for the jump palette. */
export function flattenLinks(nav: NavItem[]): NavLink[] {
  return nav.flatMap((item) => (item.kind === "link" ? [item] : item.kind === "group" ? item.items.filter((i) => i.kind === "link") : []));
}
