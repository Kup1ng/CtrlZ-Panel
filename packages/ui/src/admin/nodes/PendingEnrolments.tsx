"use client";

import {useEnrollments} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {buttonVariants} from "@heroui/react";
import {useTranslations} from "next-intl";

import {waitingEnrolments} from "./nodeParts.ts";

// A host that has called in and waits for its fingerprint to be compared, said on the Nodes page where the admin looks first (T-340).
// Nothing shows when none waits, and while the list is loading or has failed: this is a pointer, not a section, so it never adds an error.

export function PendingEnrolments() {
  const t = useTranslations("nodes");
  const list = useEnrollments();
  const waiting = waitingEnrolments(list.data?.pages.flatMap((p) => p.items) ?? []);
  if (waiting === 0) return null;
  return (
    <div role="status" className="bg-surface-secondary flex flex-wrap items-center justify-between gap-3 rounded-(--radius-box) p-4" data-testid="pending-enrolments">
      <span className="flex items-center gap-2 text-sm font-medium">
        <Icon name="warning" className="size-4 shrink-0" />
        {t("enrol.pendingBanner.title", {count: waiting})}
      </span>
      <Link href="/nodes/enrol" className={buttonVariants({variant: "secondary", size: "sm"})}>
        {t("enrol.pendingBanner.open")}
      </Link>
    </div>
  );
}
