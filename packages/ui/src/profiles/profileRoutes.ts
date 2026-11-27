// The routes of a profile (spec p2 9, FE 19.1), in one place, so a link, a tab and the switcher agree. Paths are without the locale (the
// router of `@ctrlz/i18n/navigation` adds it) and carry the profile's id, never its name (Plan.md, the P2 note about escaped names).

export const PROFILE_TABS = ["filters", "services", "rules", "options"] as const;
export type ProfileTab = (typeof PROFILE_TABS)[number];

/** The folder of a tab under `/profiles/[id]`. The Rules tab lives at `custom-rules` (WF). */
const SEGMENT: Record<ProfileTab, string> = {filters: "filters", services: "services", rules: "custom-rules", options: "options"};

export const profilesHref = "/profiles";
export const profileHref = (id: string, tab: ProfileTab = "options"): string => `/profiles/${id}/${SEGMENT[tab]}`;
export const thirdPartyHref = (id: string): string => `/profiles/${id}/filters/third-party`;
export const folderHref = (id: string, folderId: string): string => `/profiles/${id}/custom-rules/${folderId}`;

/**
 * The tab a path is in, or `null` outside any (`/profiles/<id>` itself, which redirects to Options). `filters/third-party` is the Filters
 * tab, and `custom-rules/<folderId>` is the Rules tab.
 */
export function profileTabOf(pathname: string): ProfileTab | null {
  const m = /^\/profiles\/[^/]+\/([^/]+)/.exec(pathname);
  const segment = m?.[1];
  return (PROFILE_TABS.find((tab) => SEGMENT[tab] === segment) ?? null) as ProfileTab | null;
}

/** The same tab of another profile: what the switcher opens. A folder or a sub-page does not carry over (it belongs to the first profile). */
export function switchProfileHref(pathname: string, nextId: string): string {
  return profileHref(nextId, profileTabOf(pathname) ?? "options");
}

/** The id in `/profiles/<id>/...`, or `null`. */
export function profileIdOf(pathname: string): string | null {
  return /^\/profiles\/([^/]+)/.exec(pathname)?.[1] ?? null;
}
