"use client";

import {ListBox, Select} from "@heroui/react";
import type {ReactNode} from "react";

// A Select with no visible label, for a toolbar and a row where the name is the control's own accessible name (the filter, the sort, the
// side of a Geo Rule). It is `admin/shared/FieldSelect` without the label above and the description.

export type MiniOption = {id: string; label: ReactNode; textValue: string; isDisabled?: boolean};

export function MiniSelect({label, value, onChange, options, className, isDisabled}: {label: string; value: string; onChange: (value: string) => void; options: MiniOption[]; className?: string; isDisabled?: boolean}) {
  return (
    <Select
      aria-label={label}
      variant="secondary"
      value={value}
      isDisabled={isDisabled}
      className={className}
      onChange={(next) => {
        if (typeof next === "string") onChange(next);
      }}
    >
      <Select.Trigger>
        <Select.Value />
        <Select.Indicator />
      </Select.Trigger>
      <Select.Popover>
        <ListBox>
          {options.map((o) => (
            <ListBox.Item key={o.id} id={o.id} textValue={o.textValue} isDisabled={o.isDisabled}>
              {o.label}
              <ListBox.ItemIndicator />
            </ListBox.Item>
          ))}
        </ListBox>
      </Select.Popover>
    </Select>
  );
}
