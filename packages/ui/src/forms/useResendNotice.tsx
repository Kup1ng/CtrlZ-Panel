"use client";

import {useTranslations} from "next-intl";
import {useCallback, useEffect, useRef, useState, type ReactNode} from "react";

// What a successful "Resend code" owes the visitor, once, for every page that has one (Login, Register,
// Invite, Forgot Password; wp8-r2-2). The caller mounts ResendTimer with a `key` that changes for every new
// challenge, so the button that had the focus is replaced and the focus falls to the page; and the only
// other change is the button's label, which is not a live region. `resent()` puts the focus on the code
// field, which is what the visitor does next, and says in an always-mounted status region that a new code
// was sent. The region is mounted empty and filled a moment later, and emptied between two resends, because
// a screen reader announces a change to a region it knows and misses text that arrives with the region, or
// the same text set twice.

const ANNOUNCE_DELAY_MS = 150;
const SHOWN_MS = 8000;

export function useResendNotice(focusCode: () => void): {notice: ReactNode; resent: () => void} {
  const t = useTranslations("auth");
  const [shown, setShown] = useState(false);
  const timers = useRef<number[]>([]);

  useEffect(() => {
    const pending = timers;
    return () => pending.current.forEach((id) => window.clearTimeout(id));
  }, []);

  const resent = useCallback(() => {
    focusCode();
    timers.current.forEach((id) => window.clearTimeout(id));
    setShown(false);
    timers.current = [window.setTimeout(() => setShown(true), ANNOUNCE_DELAY_MS), window.setTimeout(() => setShown(false), SHOWN_MS)];
  }, [focusCode]);

  const notice = (
    <p role="status" aria-live="polite" className="text-muted text-center text-xs empty:hidden">
      {shown ? t("resend.sent") : null}
    </p>
  );
  return {notice, resent};
}
