"use client";

import {useEffect, useRef} from "react";

// A wizard swaps one step for the next, and the control that had the focus (the password field the person just
// submitted, the code field that was just accepted) leaves with its step. The browser then puts the focus on
// <body>, outside the dialog: Escape reaches nothing, Tab starts at the top of the document, and a screen reader says
// nothing of the new step (wp9-r3-1, spec 17.5).
//
// After every change of `step` the focus goes to the step's heading (tabIndex -1), unless the new step has already
// taken it into the dialog itself (a code field that focuses on mount). The check waits one frame, so a step's own
// focus effect has run and is never overridden. The first render is skipped: the dialog places the focus on open.
export function useStepFocus<Target extends HTMLElement = HTMLHeadingElement>(step: unknown) {
  const panel = useRef<HTMLDivElement>(null);
  const heading = useRef<Target>(null);
  const mounted = useRef(false);

  useEffect(() => {
    if (!mounted.current) {
      mounted.current = true;
      return;
    }
    const frame = requestAnimationFrame(() => {
      const active = document.activeElement;
      if (active && active !== document.body && panel.current?.contains(active)) return;
      heading.current?.focus({preventScroll: true});
    });
    return () => cancelAnimationFrame(frame);
  }, [step]);

  return {panel, heading};
}
