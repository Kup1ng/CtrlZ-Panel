"use client";

import {useEffect, useRef, type RefObject} from "react";

// A control that opened something in place (a field with Save, a form) is gone when that closes, and the focused Save or Cancel button goes
// with it: the browser drops the focus to the page, and the next Tab starts at the top. This gives the focus back to the row's own control
// when `open` turns false. It does nothing when the focus is somewhere on purpose (a person who moved on keeps their place), and it never
// moves on first render. The ref sits on the control, or on a group that holds it (the selected button of a group is tried first).
//
// `again` is for a form that starts over without closing (Cancel while the stored value is the one that keeps it open): a change of it counts
// as a close, because the form is remounted and the focused Cancel goes with it (S2-r2-2).

const TARGETS = '[aria-pressed="true"], [aria-checked="true"], button:not([disabled]), [role="combobox"]';

export function useFocusBack<T extends HTMLElement>(open: boolean, again = 0): RefObject<T | null> {
  const ref = useRef<T | null>(null);
  const was = useRef(open);
  const seen = useRef(again);
  useEffect(() => {
    const closed = (was.current && !open) || seen.current !== again;
    was.current = open;
    seen.current = again;
    if (!closed) return;
    const active = document.activeElement;
    if (active && active !== document.body) return;
    const el = ref.current;
    if (!el) return;
    const target = el.matches("button, [role=combobox]") ? el : el.querySelector<HTMLElement>(TARGETS);
    target?.focus();
  }, [open, again]);
  return ref;
}
