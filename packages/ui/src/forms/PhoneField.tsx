"use client";

import {Description, FieldError, Input, Label, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";

import {stripInvisible} from "./invisible.ts";

// Spec 10, "PhoneField". It sends what the user typed: the server normalises the number (AUTH 14.3),
// so Persian digits, a +98 prefix or spaces all work, and the client never guesses at the format.
// Invisible format characters (LRM, RLM, ZWNJ) that a paste brings along are dropped as they arrive: the API refuses
// them with a 400 that no field can show (wp8-r10-1, forms/invisible.ts).
// A phone number is a technical token, so the input is left to right in both languages.

export function PhoneField({
  name = "phone",
  label,
  value,
  onChange,
  isDisabled,
  description,
  error,
  autoComplete = "tel",
}: {
  name?: string;
  label?: string;
  value: string;
  onChange: (value: string) => void;
  isDisabled?: boolean;
  /** A hint under the field. A string, so that it is rendered as the field's own Description and read with it (wp8-r9-1). */
  description?: string;
  /** A message for this field: the field is invalid while it is set. */
  error?: string;
  /**
   * `off` is for a form that types SOMEONE ELSE's number (the admin's create user), which a browser must not fill with the admin's own.
   * `username` on the password sign-in, where the number is the account name that the password manager saves with the
   * password, and on nothing else (wp8-r17-5). A field takes one autocomplete name, so the other forms keep `tel`.
   */
  autoComplete?: "tel" | "username" | "off";
}) {
  const t = useTranslations("auth");
  return (
    <TextField
      name={name}
      type="tel"
      autoComplete={autoComplete}
      inputMode="tel"
      variant="secondary"
      fullWidth
      isDisabled={isDisabled}
      isInvalid={error !== undefined}
      value={value}
      onChange={(next) => onChange(stripInvisible(next))}
    >
      <Label>{label ?? t("fields.phone.label")}</Label>
      <Input dir="ltr" placeholder={t("fields.phone.placeholder")} className="text-start" />
      {description ? <Description>{description}</Description> : null}
      <FieldError>{error}</FieldError>
    </TextField>
  );
}
