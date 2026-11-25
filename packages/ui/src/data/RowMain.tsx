"use client";

import {Link} from "@ctrlz/i18n/navigation.ts";
import type {ReactNode} from "react";

// The one main action of a row, as a stretched link or button: its ::after covers the whole row, so
// a click anywhere on the row does it, while the controls that sit inside the row (counters, a
// switch, hover actions, a checkbox) stay real, separate, focusable elements above it with
// `relative z-10`. A link around the whole row could not hold them, since an interactive element
// may not contain another. A row with neither `href` nor `onPress` is plain text: no hover, no
// pointer (design taste: information-only rows do not react).

export const STRETCH =
  "outline-none after:absolute after:inset-0 after:content-[''] after:cursor-[var(--cursor-interactive)]";

type Props = {
  href?: string;
  onPress?: () => void;
  className?: string;
  children: ReactNode;
};

export function RowMain({href, onPress, className, children}: Props) {
  const classes = [STRETCH, className ?? ""].filter(Boolean).join(" ");
  if (href) {
    return (
      <Link href={href} data-row-main="" className={classes}>
        {children}
      </Link>
    );
  }
  if (onPress) {
    return (
      <button type="button" data-row-main="" onClick={onPress} className={`${classes} text-start`}>
        {children}
      </button>
    );
  }
  return <span className={className}>{children}</span>;
}

/** Row focus ring: the row shows it when its main action has keyboard focus, not when a counter inside does. */
export const ROW_FOCUS =
  "has-[[data-row-main]:focus-visible]:outline-2 has-[[data-row-main]:focus-visible]:outline-offset-2 has-[[data-row-main]:focus-visible]:outline-focus";
