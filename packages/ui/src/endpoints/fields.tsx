"use client";

import {Description, FieldError, Label, ListBox, Select, Switch} from "@heroui/react";
import type {ReactNode} from "react";

// Two small field shapes the Endpoint dialogs repeat: a labelled Select over a flat list, and a Switch with its sentence under it.

export type Choice = {id: string; label: ReactNode; textValue: string; isDisabled?: boolean};

export function SelectField({
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
  description?: ReactNode;
  error?: string;
  placeholder?: string;
  options: Choice[];
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

export function SwitchRow({
  label,
  description,
  isSelected,
  onChange,
  isDisabled,
  name,
  error,
}: {
  label: string;
  description: string;
  isSelected: boolean;
  onChange: (value: boolean) => void;
  isDisabled?: boolean;
  name?: string;
  error?: string;
}) {
  return (
    // `data-invalid` is what the form looks for to know a field shows the message it was given, and where to put the focus (forms/useApiForm.ts).
    <div className="flex flex-col gap-1" data-invalid={error ? "true" : undefined}>
      <Switch name={name} isSelected={isSelected} onChange={onChange} isDisabled={isDisabled} className="w-full items-start justify-between gap-3">
        <Switch.Content className="min-w-0 flex-1">
          <Label>{label}</Label>
          <Description>{description}</Description>
        </Switch.Content>
        <Switch.Control>
          <Switch.Thumb />
        </Switch.Control>
      </Switch>
      {error ? (
        <p role="alert" className="text-danger-soft-foreground text-xs">
          {error}
        </p>
      ) : null}
    </div>
  );
}
