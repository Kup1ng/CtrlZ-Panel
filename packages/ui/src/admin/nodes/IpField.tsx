"use client";

import {Description, FieldError, Input, Label, TextField} from "@heroui/react";

// An address or a host name typed by an admin (a node's bind or advertised address, the source an enrolment is bound to, a zone or a host of the domain page). Left to right whatever the
// page's direction, never autofilled, and its message comes from the form, so the words are the page's own and not the browser's.

export function IpField({
  name,
  label,
  description,
  placeholder,
  value,
  onChange,
  error,
  isDisabled,
  className,
}: {
  name: string;
  label: string;
  description?: string;
  /** An example of the shape, for a field that is empty (a host name). A hint, never a value that is sent. */
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
  error?: string | undefined;
  isDisabled?: boolean;
  className?: string;
}) {
  return (
    <TextField name={name} variant="secondary" fullWidth autoComplete="off" className={className} isDisabled={isDisabled} isInvalid={error !== undefined} value={value} onChange={onChange}>
      <Label>{label}</Label>
      <Input dir="ltr" {...(placeholder ? {placeholder} : {})} inputMode="text" spellCheck={false} autoCapitalize="none" className="text-start font-mono" />
      {description ? <Description>{description}</Description> : null}
      <FieldError>{error}</FieldError>
    </TextField>
  );
}
