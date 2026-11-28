import type {QueryClient} from "@tanstack/react-query";

import {required} from "../core.ts";
import {adminApi} from "./client.ts";
import {adminMeKeys, type AdminMe} from "./session.ts";

// Spec 11.3. The fresh-TOTP window of an admin: five minutes after a code, during which the routes marked
// `admin-fresh` in the document work (AUTH 10.5). Everything the window needs that is not a dialog is here, so
// it can be tested without a DOM. The dialog is `packages/ui/src/auth/FreshTotpDialog.tsx`, which hands a
// `totp_fresh_required` error to the recovery of `feedback/handleApiError.ts` and repeats the failed call once.

/** The longest the window can last, as AUTH 10.5 has it. Only used to bound a clock that is wrong. */
export const FRESH_WINDOW_MS = 5 * 60_000;

/**
 * `POST /auth/totp/fresh`. The answer carries `fresh_until`, which is written into the cached `/me` so the indicator
 * in the shell moves at once, without a second request. The code is never kept: not in the cache, not in a key.
 */
export async function submitFreshTotp(queryClient: QueryClient, code: string): Promise<string> {
  const {fresh_until} = required(await adminApi.POST("/auth/totp/fresh", {body: {code}}));
  queryClient.setQueryData<AdminMe>(adminMeKeys.all, (me) => (me ? {...me, fresh_until} : me));
  return fresh_until;
}

/** When the window ends, or undefined when it is closed or has run out. A bad date reads as closed. */
export function freshUntil(me: Pick<AdminMe, "fresh_until"> | undefined, now: number = Date.now()): Date | undefined {
  if (!me?.fresh_until) return undefined;
  const end = new Date(me.fresh_until);
  const left = end.getTime() - now;
  // A clock that is far off would show a window that is not there: nothing longer than the window itself counts.
  return Number.isNaN(left) || left <= 0 || left > FRESH_WINDOW_MS + 60_000 ? undefined : end;
}
