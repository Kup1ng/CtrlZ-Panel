"use client";

import type {ReactNode} from "react";

/**
 * STUB until WP4 lands (spec 14.4). The real gate reads `useSession()`, a query
 * on GET /me, and shows a skeleton while it loads, then sends `anonymous` to the
 * login page with `next`, `restricted` to /change-password and `suspended` to
 * /suspended. It is a convenience: the API is the gate. The proxy already sends
 * a visitor with no session cookie to the login page.
 *
 * Until then it renders its children as they are, so the shell can be built and
 * reviewed without an API.
 */
export function SessionGate({children}: {children: ReactNode}) {
  return children;
}
