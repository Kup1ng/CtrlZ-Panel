import type {NavItem} from "./nav.ts";

// The tenant panel's sidebar (WF "اسکلت": Profiles and Endpoints with counters,
// Analytics and Preferences that open). Labels come from the `shell.nav.*` keys.

export type PanelNavLabels = {
  profiles: string;
  endpoints: string;
  analytics: string;
  statistics: string;
  activityLog: string;
  domainTest: string;
  preferences: string;
  account: string;
  api: string;
  logout: string;
};

export function panelNav(l: PanelNavLabels): NavItem[] {
  return [
    {kind: "link", id: "profiles", href: "/profiles", label: l.profiles, icon: "profiles", countKey: "profiles"},
    {kind: "link", id: "endpoints", href: "/endpoints", label: l.endpoints, icon: "endpoints", countKey: "endpoints"},
    {
      kind: "group",
      id: "analytics",
      label: l.analytics,
      icon: "analytics",
      items: [
        {kind: "link", id: "statistics", href: "/analytics/statistics", label: l.statistics, icon: "statistics"},
        {kind: "link", id: "activity-log", href: "/analytics/activity-log", label: l.activityLog, icon: "activityLog"},
        {kind: "link", id: "domain-test", href: "/analytics/domain-test", label: l.domainTest, icon: "domainTest"},
      ],
    },
    {
      kind: "group",
      id: "preferences",
      label: l.preferences,
      icon: "preferences",
      items: [
        {kind: "link", id: "account", href: "/preferences/account", label: l.account, icon: "account"},
        {kind: "link", id: "api", href: "/preferences/api", label: l.api, icon: "api"},
        {kind: "action", id: "logout", label: l.logout, icon: "logout"},
      ],
    },
  ];
}
