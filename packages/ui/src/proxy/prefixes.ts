// Paths without the locale. The login page validates `next` against the same
// lists, so they live here and not in each proxy file.

/** Panel pages behind a session. The locale root redirects into one of them. */
// `/docs` and `/status` are the logo menu's pages (spec p3 10, T-125): the guide and the API docs, and the service status. They are inside
// the shell, so they need a session like every page of it. `/s/<link>`, the share page, has no session and is not here.
export const PANEL_PROTECTED_PREFIXES = ["/profiles", "/endpoints", "/analytics", "/preferences", "/docs", "/status"] as const;

/** A panel session is either cookie: the refresh cookie alone can still be turned into a session by the API. */
export const PANEL_SESSION_COOKIES = ["__Host-ctrlz_session", "__Host-ctrlz_refresh"] as const;

export const ADMIN_PROTECTED_PREFIXES = ["/overview", "/nodes", "/pair", "/domain", "/runbook", "/users", "/invites", "/sms", "/settings", "/audit", "/setup"] as const;
export const ADMIN_SESSION_COOKIES = ["__Host-ctrlz_admin"] as const;
