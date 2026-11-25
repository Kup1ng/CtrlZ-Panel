"use client";

import {useCallback, useEffect, useRef, useState} from "react";

// One whole-second countdown for the things an auth form waits out: `retry_after_s` of a 429, the
// `resend_after_s` of an OTP, the life of a ticket. It stores a deadline and not a remaining count,
// so a tab that was throttled in the background still shows the right number when it wakes, and it
// re-renders only when the visible second changes.

export function secondsLeft(deadline: number, now: number): number {
  return Math.max(0, Math.ceil((deadline - now) / 1000));
}

export function useCountdown() {
  const deadline = useRef(0);
  const [remaining, setRemaining] = useState(0);
  const active = remaining > 0;

  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => setRemaining(secondsLeft(deadline.current, Date.now())), 250);
    return () => clearInterval(id);
  }, [active]);

  /** Starts (or restarts) the countdown at `seconds`. Zero, a negative value or a non-number stops it. */
  const start = useCallback((seconds: number | undefined) => {
    const s = typeof seconds === "number" && Number.isFinite(seconds) && seconds > 0 ? seconds : 0;
    deadline.current = Date.now() + s * 1000;
    setRemaining(Math.ceil(s));
  }, []);

  return {remaining, start};
}
