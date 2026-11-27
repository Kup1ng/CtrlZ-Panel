"use client";

import {Button, Chip} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";
import {useTranslations} from "next-intl";

// WF "Rules" and "Endpoints": a click on a row opens selection mode, and the header gets a bar with the count, SELECT ALL and the
// actions that work on the selection (Copy, Move, Edit, Delete; Enable, Disable). It sits above the list and stays in view while the
// list scrolls. It is a toolbar: one tab stop, arrow keys inside (HeroUI's Toolbar is not needed for the keys, the buttons are
// ordinary and the order follows the reading direction).
//
// Every button's name has the count in it ("Delete 12 selected items"), so the control is never "Delete" alone. A destructive action
// is `variant: "danger"` and its icon and word carry it, not only the colour.

export type BarAction = {
  id: string;
  label: string;
  icon?: GeneralIconName;
  variant?: "default" | "danger";
  isDisabled?: boolean;
  onPress: () => void;
};

export type SelectionBarProps = {
  count: number;
  /** Everything of the filter is selected (Select All), so `count` is the server's total and not only the loaded rows. */
  allMatching?: boolean;
  /** How many rows the list has in all, when known, for the Select All button's name. */
  total?: number;
  /** Select All on a filter that is not all loaded and has no known count: the chip says "every matching item" and not a number that is wrong. */
  countUnknown?: boolean;
  onSelectAll?: () => void;
  onClear: () => void;
  actions: BarAction[];
  className?: string;
};

export function SelectionBar({count, allMatching = false, total, countUnknown = false, onSelectAll, onClear, actions, className}: SelectionBarProps) {
  const c = useTranslations("common");
  const format = useAppFormat();
  const shown = format.number(count);
  return (
    <div
      role="toolbar"
      aria-label={c("selection.barLabel")}
      className={["selection-bar bg-surface sticky top-0 z-20 flex flex-wrap items-center gap-2 px-3 py-2", className ?? ""].filter(Boolean).join(" ")}
    >
      <Chip size="sm" variant="soft" aria-live="polite">
        <Chip.Label>{countUnknown ? c("selection.everyMatching") : c("count.selected", {count})}</Chip.Label>
      </Chip>
      {onSelectAll && !allMatching ? (
        <Button size="sm" variant="ghost" aria-label={total === undefined ? c("selection.selectAll") : c("selection.selectAllAria", {count: total})} onPress={onSelectAll}>
          {c("selection.selectAll")}
        </Button>
      ) : null}
      {allMatching ? <span className="text-muted text-xs">{c("selection.allMatching")}</span> : null}
      <div className="ms-auto flex flex-wrap items-center gap-1">
        {actions.map((a) => (
          <Button
            key={a.id}
            size="sm"
            variant={a.variant === "danger" ? "danger-soft" : "ghost"}
            isDisabled={a.isDisabled || count === 0}
            aria-label={`${a.label}: ${countUnknown ? c("selection.everyMatching") : c("count.selected", {count})}`}
            onPress={a.onPress}
          >
            {a.icon ? <Icon name={a.icon} className="size-4" /> : null}
            <span>{a.label}</span>
          </Button>
        ))}
        <Button isIconOnly size="sm" variant="ghost" aria-label={c("selection.clear")} onPress={onClear}>
          <Icon name="close" className="size-4" />
        </Button>
      </div>
      <span className="sr-only">{shown}</span>
    </div>
  );
}
