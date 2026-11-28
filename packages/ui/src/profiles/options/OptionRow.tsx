"use client";

import {Button} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

import type {IconName} from "@ctrlz/icons/generated/registry.ts";

import {ROW_ICON, type OptionRow as RowName} from "./optionModel.ts";

// WF "Profile Options" (T-215), the shape of every row: icon, name, a description with Learn more, the control at the end, and under
// them, across the whole row, the value that needs more room (two fields and Save). Below `sm` the control drops under the text, so a
// long Persian name never squeezes a control, and the row is two lines on a phone.
//
// Learn more opens `helpPane=option.<name>` (SectionHelp), so the explanation has an address of its own and Back closes it.

export type OptionRowProps = {
  name: RowName;
  title: string;
  description: ReactNode;
  /** The control at the end of the row. */
  control?: ReactNode;
  /** The dependent value, opened in place. */
  children?: ReactNode;
  onLearnMore: (name: RowName) => void;
};

function RowIcon({name}: {name: RowName}) {
  if (name === "lock") return <Icon name="lock" />;
  // `hasSubIcon` is not needed: the slugs of ROW_ICON are the files of svg/options, and optionModel.test.ts holds the two together.
  return <SubIcon group="options" name={ROW_ICON[name] as IconName<"options">} className="size-6" />;
}

export function OptionRow({name, title, description, control, children, onLearnMore}: OptionRowProps) {
  const t = useTranslations("rules");
  return (
    <li data-option={name} className="bg-surface flex flex-col gap-3 rounded-(--radius-box) px-4 py-3 shadow-surface">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span aria-hidden="true" className="tile-11 bg-default text-foreground grid size-11 shrink-0 place-items-center text-xl">
          <RowIcon name={name} />
        </span>
        <div className="flex min-w-0 flex-1 basis-56 flex-col gap-0.5">
          <h3 className="text-foreground text-sm font-medium">{title}</h3>
          <p className="text-muted text-xs">{description}</p>
          <Button
            size="sm"
            variant="ghost"
            className="-ms-2 mt-0.5 h-auto min-h-7 self-start px-2 text-xs"
            aria-label={t("options.learnMoreAria", {name: title})}
            onPress={() => onLearnMore(name)}
          >
            <Icon name="info" className="size-3.5" />
            {t("options.learnMore")}
          </Button>
        </div>
        {control ? <div className="flex shrink-0 flex-wrap items-center gap-2">{control}</div> : null}
      </div>
      {children}
    </li>
  );
}
