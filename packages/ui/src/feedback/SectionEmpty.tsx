"use client";

import {EmptyState} from "@heroui-pro/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

// Spec 8.7. The empty state of a section, a list or a grid. `DataGrid` passes it to
// `renderEmptyState` and `Command.List` too, so it stays small and takes no page chrome. The action
// is the one thing a visitor can do about it; a state with nothing to do has none.

export type SectionEmptyProps = {
  icon?: GeneralIconName;
  /** Defaults to "nothing to show", with its own line below. */
  title?: ReactNode;
  description?: ReactNode;
  /** One button or link. */
  action?: ReactNode;
  size?: "sm" | "md";
  className?: string;
};

export function SectionEmpty({icon = "search", title, description, action, size = "sm", className}: SectionEmptyProps) {
  const t = useTranslations("feedback");
  // The generic line belongs to the generic title: a caller's own title brings its own words or none.
  const text = description ?? (title === undefined ? t("empty.text") : undefined);
  return (
    <EmptyState size={size} className={className}>
      <EmptyState.Header>
        <EmptyState.Media variant="icon">
          <Icon name={icon} className="size-5" />
        </EmptyState.Media>
        <EmptyState.Title>{title ?? t("empty.title")}</EmptyState.Title>
        {text ? <EmptyState.Description>{text}</EmptyState.Description> : null}
      </EmptyState.Header>
      {action ? <EmptyState.Content>{action}</EmptyState.Content> : null}
    </EmptyState>
  );
}
