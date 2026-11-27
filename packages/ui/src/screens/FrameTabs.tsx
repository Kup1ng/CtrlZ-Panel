"use client";

import {buttonVariants} from "@heroui/react";
import {Link} from "@ctrlz/i18n/navigation.ts";

// The pill tabs under the header of a frame (WF "Profiles", "Endpoints"): links to the pages of one profile or one Endpoint.
//
// They are NAVIGATION, not a tab panel: each tab is another address, the page behind it is drawn by the route, and the frame draws no
// panel for it. A `role="tab"` with no `tabpanel` has an `aria-controls` that points at nothing (axe: aria-valid-attr-value), so these are
// plain links in a `<nav>`, and the page the person is on says so with `aria-current="page"`, in the primary variant (dark text on the
// accent) and by weight, not by colour alone. Over 375 px they scroll sideways inside their own box, and the page does not.

export type FrameTab = {id: string; label: string; href: string};

export function FrameTabs({label, tabs, current}: {label: string; tabs: readonly FrameTab[]; current: string | null}) {
  return (
    <nav aria-label={label} className="frame-tabs -mx-1 overflow-x-auto px-1 py-1">
      <ul className="flex w-max min-w-full items-center gap-1">
        {tabs.map((tab) => {
          const active = tab.id === current;
          return (
            <li key={tab.id}>
              <Link
                href={tab.href}
                aria-current={active ? "page" : undefined}
                className={buttonVariants({variant: active ? "primary" : "ghost", size: "sm"})}
              >
                {tab.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
