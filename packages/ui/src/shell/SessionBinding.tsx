"use client";

import {useAdminIdentityGuard} from "@ctrlz/api-client/admin/session.ts";
import {useSessionBinding} from "@ctrlz/api-client/hooks/me.ts";
import {useLocale} from "next-intl";

import {useApp} from "../providers/appContext.tsx";
import {currentNext} from "./currentNext.ts";

// A signed-in page that is NOT inside the shell (/change-password and /suspended in the panel, /setup in
// the admin app: spec 10.7, 11.2) is not under SessionGate, so nothing binds it to the session. Without a
// binding a refused refresh leaves it where it is, another tab's logout is not heard, and a page restored
// from the back/forward cache stays readable (wp4-r5-4). Such a page mounts this once. It renders nothing.
// SessionGate itself must never wrap those pages: its gate sends a restricted, suspended or setup session
// to them, and would show its skeleton for ever.

function PanelBinding() {
  const locale = useLocale();
  useSessionBinding({locale, currentNext: () => currentNext("panel")});
  return null;
}

// Admin has no refresh and no channel (spec 13), so the guard watches the cache for a 401 `session_expired`
// and leaves for /login?ended=1 itself (wp4-r6-4): this page has no gate to do it.
function AdminBinding() {
  const locale = useLocale();
  useAdminIdentityGuard({locale, currentNext: () => currentNext("admin")});
  return null;
}

export function SessionBinding() {
  return useApp() === "admin" ? <AdminBinding /> : <PanelBinding />;
}
