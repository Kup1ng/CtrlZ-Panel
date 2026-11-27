import type {AdminUserMenuItem} from "@ctrlz/ui/admin/shell/userMenu.ts";
import type {NavItem} from "@ctrlz/ui/shell/nav.ts";

// Spec 13 and p4-nodes 10.1. The admin's sidebar and its user menu, as data, built by the server layout with its own translator. Nine
// pages, no groups, no counters, no bell and no profile switcher. Icons are general ones of the allowlist: users, invite, sms, settings,
// audit, and for P4 overview, nodes, pair and domain.

export type AdminNavLabels = {overview: string; nodes: string; pair: string; domain: string; users: string; invites: string; sms: string; settings: string; audit: string};

export function adminNav(l: AdminNavLabels): NavItem[] {
  return [
    {kind: "link", id: "overview", href: "/overview", label: l.overview, icon: "overview"},
    {kind: "link", id: "nodes", href: "/nodes", label: l.nodes, icon: "nodes"},
    {kind: "link", id: "pair", href: "/pair", label: l.pair, icon: "pair"},
    {kind: "link", id: "domain", href: "/domain", label: l.domain, icon: "domain"},
    {kind: "link", id: "users", href: "/users", label: l.users, icon: "users"},
    {kind: "link", id: "invites", href: "/invites", label: l.invites, icon: "invite"},
    {kind: "link", id: "sms", href: "/sms", label: l.sms, icon: "sms"},
    {kind: "link", id: "settings", href: "/settings", label: l.settings, icon: "settings"},
    {kind: "link", id: "audit", href: "/audit", label: l.audit, icon: "audit"},
  ];
}

/**
 * The menu on the username in `Sidebar.Footer`. Account opens a state-only dialog (a password is typed in it, so it is
 * never bound to the URL) and Log out asks for confirmation, then ends the session.
 */
export type AdminUserMenuLabels = {account: string; logout: string};

export function adminUserMenu(l: AdminUserMenuLabels): AdminUserMenuItem[] {
  return [
    {id: "account", label: l.account, icon: "account"},
    {id: "logout", label: l.logout, icon: "logout"},
  ];
}
