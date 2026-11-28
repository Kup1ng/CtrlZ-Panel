"use client";

import {Description, FieldError, Label, ListBox, Select} from "@heroui/react";
import type {ReactNode} from "react";

// One labelled Select with a flat list of options: the shape every admin choice has (a gateway, a template, a language).
// The option label may be a node (a product name in `<Tech>`), and `textValue` is what a screen reader and the type-ahead use.

export type FieldOption = {id: string; label: ReactNode; textValue: string; isDisabled?: boolean};

export function FieldSelect({
  label,
  description,
  error,
  placeholder,
  options,
  value,
  onChange,
  name,
  isDisabled,
}: {
  label: string;
  description?: string;
  error?: string;
  placeholder?: string;
  options: FieldOption[];
  value: string | null;
  onChange: (value: string) => void;
  name?: string;
  isDisabled?: boolean;
}) {
  return (
    <Select
      name={name}
      variant="secondary"
      fullWidth
      placeholder={placeholder}
      value={value}
      isDisabled={isDisabled}
      isInvalid={error !== undefined}
      onChange={(next) => {
        if (typeof next === "string") onChange(next);
      }}
    >
      <Label>{label}</Label>
      <Select.Trigger>
        <Select.Value />
        <Select.Indicator />
      </Select.Trigger>
      {description ? <Description>{description}</Description> : null}
      <FieldError>{error}</FieldError>
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
