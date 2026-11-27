"use client";

import {Description, FieldError, Input, Label, TextField} from "@heroui/react";

// The name of a profile, shared by Add and Duplicate (spec p2 3.7: 1 to 64 characters). The text is cleaned by the caller (`cleanProse`);
// the field only shows what the form gives it, and a message of the page or the server through `error`.

export type ProfileNameFieldProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  hint: string;
  error?: string;
  isDisabled?: boolean;
};

export function ProfileNameField({label, value, onChange, hint, error, isDisabled}: ProfileNameFieldProps) {
  return (
    <TextField name="name" variant="secondary" fullWidth autoComplete="off" isDisabled={isDisabled} isInvalid={error !== undefined} value={value} onChange={onChange}>
      <Label>{label}</Label>
      <Input />
      <Description>{hint}</Description>
      <FieldError>{error}</FieldError>
    </TextField>
  );
}
