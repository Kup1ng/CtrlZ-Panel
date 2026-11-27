// Who fills which screen. Every route of P2 and P3 has a page file under `apps/panel/src/app/[locale]/` that renders ONE component of the list
// below, and nothing else of the lane; the component is a stub (screens/LaneStub.tsx) until its lane fills it. A lane edits its components, its
// namespace files in packages/i18n and its Playwright specs, and no shared file: the frames, the hooks, the shared components, the support
// files of e2e and the route list are the foundation's (branch scr-base).
//
// `lanes.test.ts` reads this list against the page files and the files on disk, so a route that loses its screen, a screen that no page
// renders and a lane component that was moved all fail there.

export type Lane = "P2a" | "P2b" | "P3a" | "P3b";

export type Screen = {
  lane: Lane;
  /** The route without the locale. */
  route: string;
  /** The page file, from `apps/panel/src/app/[locale]`. */
  page: string;
  /** The component file, from `packages/ui/src`, and the name it exports. */
  file: string;
  component: string;
  /** The `data-screen` of its stub, which a page-level spec finds. */
  screen: string;
};

export const SCREENS: readonly Screen[] = [
  {lane: "P2a", route: "/profiles", page: "(shell)/profiles/page.tsx", file: "profiles/ProfilesListScreen.tsx", component: "ProfilesListScreen", screen: "profiles-list"},
  {lane: "P2a", route: "/profiles/[id]/filters", page: "(shell)/profiles/[id]/filters/page.tsx", file: "profiles/ProfileFiltersScreen.tsx", component: "ProfileFiltersScreen", screen: "profile-filters"},
  {lane: "P2a", route: "/profiles/[id]/filters/third-party", page: "(shell)/profiles/[id]/filters/third-party/page.tsx", file: "profiles/ProfileThirdPartyScreen.tsx", component: "ProfileThirdPartyScreen", screen: "profile-third-party"},
  {lane: "P2a", route: "/profiles/[id]/services", page: "(shell)/profiles/[id]/services/page.tsx", file: "profiles/ProfileServicesScreen.tsx", component: "ProfileServicesScreen", screen: "profile-services"},
  {lane: "P2b", route: "/profiles/[id]/custom-rules", page: "(shell)/profiles/[id]/custom-rules/page.tsx", file: "profiles/ProfileRulesScreen.tsx", component: "ProfileRulesScreen", screen: "profile-rules"},
  {lane: "P2b", route: "/profiles/[id]/custom-rules/[folderId]", page: "(shell)/profiles/[id]/custom-rules/[folderId]/page.tsx", file: "profiles/ProfileFolderScreen.tsx", component: "ProfileFolderScreen", screen: "profile-folder"},
  {lane: "P2b", route: "/profiles/[id]/options", page: "(shell)/profiles/[id]/options/page.tsx", file: "profiles/ProfileOptionsScreen.tsx", component: "ProfileOptionsScreen", screen: "profile-options"},
  {lane: "P3a", route: "/endpoints", page: "(shell)/endpoints/page.tsx", file: "endpoints/EndpointsListScreen.tsx", component: "EndpointsListScreen", screen: "endpoints-list"},
  {lane: "P3a", route: "/s/[token]", page: "(public)/s/[token]/page.tsx", file: "endpoints/ShareScreen.tsx", component: "ShareScreen", screen: "share"},
  {lane: "P3b", route: "/endpoints/[id]/clients", page: "(shell)/endpoints/[id]/clients/page.tsx", file: "endpoints/EndpointClientsScreen.tsx", component: "EndpointClientsScreen", screen: "endpoint-clients"},
  {lane: "P3b", route: "/endpoints/[id]/ips", page: "(shell)/endpoints/[id]/ips/page.tsx", file: "endpoints/EndpointIpsScreen.tsx", component: "EndpointIpsScreen", screen: "endpoint-ips"},
  {lane: "P3b", route: "/endpoints/[id]/schedule", page: "(shell)/endpoints/[id]/schedule/page.tsx", file: "endpoints/EndpointScheduleScreen.tsx", component: "EndpointScheduleScreen", screen: "endpoint-schedule"},
  {lane: "P3b", route: "/preferences/api", page: "(shell)/preferences/api/page.tsx", file: "api/ApiTokensScreen.tsx", component: "ApiTokensScreen", screen: "api-tokens"},
  {lane: "P3b", route: "/docs", page: "(shell)/docs/page.tsx", file: "docs/DocsScreen.tsx", component: "DocsScreen", screen: "docs"},
  {lane: "P3b", route: "/docs/api", page: "(shell)/docs/api/page.tsx", file: "docs/ApiDocsScreen.tsx", component: "ApiDocsScreen", screen: "api-docs"},
  {lane: "P3b", route: "/status", page: "(shell)/status/page.tsx", file: "status/StatusScreen.tsx", component: "StatusScreen", screen: "status"},
];

/**
 * Components that no page renders by itself but that a frame mounts (the URL dialogs). They are the lane's too.
 * `ProfileDialogs` is drawn by the profile list page and by ProfileFrame. `EndpointDialogs` is drawn by the Endpoint list page, by
 * EndpointFrame and by ProfileFrame, whose header has Add Endpoint for a profile with none (p3 10, T-137): there it gets `defaultProfileId`,
 * so the add step starts on the open profile. `mountedBy` lists every file that renders it.
 */
export const FRAME_PARTS: readonly {lane: Lane; file: string; component: string; mountedBy: readonly string[]}[] = [
  {lane: "P2a", file: "profiles/ProfileDialogs.tsx", component: "ProfileDialogs", mountedBy: ["profiles/ProfileFrame.tsx"]},
  {
    lane: "P3a",
    file: "endpoints/EndpointDialogs.tsx",
    component: "EndpointDialogs",
    mountedBy: ["endpoints/EndpointsListScreen.tsx", "endpoints/EndpointFrame.tsx", "profiles/ProfileFrame.tsx"],
  },
];

/**
 * The message namespaces, by lane. A lane writes keys under its own groups of these files, in both languages, and the foundation has
 * already put a first key in each group so that two lanes never edit the same lines. `services`, `rules` and `jobs` also hold the words of
 * the shared components (the foundation's), under `three`, `expiry`, `destinations`, `flag`, `action`, `actionText` and `dialog`, `state`, `result`.
 */
export const NAMESPACE_LANES: Readonly<Record<string, Lane[]>> = {
  profiles: ["P2a"],
  services: ["P2a"],
  rules: ["P2b"],
  endpoints: ["P3a", "P3b"],
  setup: ["P3a"],
  api: ["P3b"],
  jobs: [],
};
