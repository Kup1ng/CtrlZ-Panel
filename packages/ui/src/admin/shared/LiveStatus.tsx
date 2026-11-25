"use client";

import {useEffect, useState, type ReactNode} from "react";

// A polite live region that is announced (wp10-r20-2). Screen readers register a region when it is inserted and speak what changes
// inside it afterwards; a region that is inserted already holding its text is often not spoken at all (the same reason RefreshFailed
// is role="alert"). The impact panels of Settings are what the admin must read before confirming (T-331), and they appear together
// with their first text. So the container is rendered at once and empty, and the content follows after a short delay, as a change.
// Where the text is the point and the delay is not wanted, use role="alert", which is announced on insertion.
//
// The empty container must stay in the accessibility tree (wp10-r21-1). `display: none` (what `empty:hidden` gives) removes it, and
// then the region and its text reach the assistive technology in the same step, which is the case this component exists to avoid.
// So while it is empty it is only visually hidden: `sr-only` is absolutely positioned (no flex-gap of the card, no box) and clipped,
// and it is still exposed. Once it has text, the caller's own box classes apply. The `empty:` variant sorts after the plain utilities.

/** How long the empty region stays registered before its text arrives. Long enough for the assistive technology to see it. */
const FILL_DELAY_MS = 120;

export function LiveStatus({children, className, testId}: {children: ReactNode; className?: string; testId?: string}) {
  const [filled, setFilled] = useState(false);
  useEffect(() => {
    const timer = window.setTimeout(() => setFilled(true), FILL_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, []);
  return (
    <div role="status" aria-live="polite" className={["empty:sr-only", className].filter(Boolean).join(" ")} data-testid={testId}>
      {filled ? children : null}
    </div>
  );
}
