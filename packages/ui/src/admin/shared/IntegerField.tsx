"use client";

import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Description, FieldError, Input, Label, TextField} from "@heroui/react";
import {useState} from "react";

import {parseInteger} from "./integer.ts";

// A whole number typed by an admin: a cap, a number of days or hours. It is a text field and not HeroUI's NumberField,
// because React Aria's NumberField in the Persian locale accepts Persian digits only and silently drops a Latin digit that
// the keyboard types (measured: "500" typed on /fa/settings left the old value). An admin on an English keyboard types
// Latin digits on a Persian page all the time, so every numeral system is read here (`toAsciiDigits`), and the value is
// shown back in the page's own digits once the field is left (spec 4.4).
//
// The bounds are held the way NumberField held them: a value above the maximum or under the minimum becomes the bound when
// the field is left, so a request is never made with a number the API would refuse, and an empty field stays empty (the
// form refuses it with its own words). A decimal, a minus sign or a letter is not a number: the text stays in the box, the
// field is marked and says `invalidMessage`, and the value is undefined, so no form can send it (wp10-r2-3). While the
// field has the focus the text is the admin's, untouched.

export function IntegerField({
  name,
  label,
  description,
  error,
  invalidMessage,
  value,
  onChange,
  min,
  max,
  isDisabled,
  className,
}: {
  name: string;
  label: string;
  description?: string;
  error?: string;
  /** Said as soon as the text is not a whole number; the page's range message is the natural choice. */
  invalidMessage?: string;
  value: number | undefined;
  onChange: (value: number | undefined) => void;
  min: number;
  max: number;
  isDisabled?: boolean;
  className?: string;
}) {
  const format = useAppFormat();
  const shown = value === undefined ? "" : format.number(value, {useGrouping: false});
  // What is in the box while it has the focus. Outside the focus the box shows `value`, so a reset from outside is seen.
  const [typing, setTyping] = useState<string | null>(null);

  // The text that is not a number, kept after the field is left so the admin sees what was refused.
  const [rejected, setRejected] = useState<string | null>(null);
  const kept = rejected !== null && value === undefined ? rejected : null;

  const refused = kept !== null || (typing !== null && parseInteger(typing).kind === "invalid");

  const parse = (text: string): number | undefined => {
    const parsed = parseInteger(text);
    return parsed.kind === "number" ? parsed.value : undefined;
  };

  return (
    <TextField
      name={name}
      variant="secondary"
      fullWidth
      autoComplete="off"
      className={className}
      isDisabled={isDisabled}
      isInvalid={error !== undefined || refused}
      value={typing ?? kept ?? shown}
      onChange={(text) => {
        setTyping(text);
        setRejected(null);
        onChange(parse(text));
      }}
      onFocus={() => setTyping(kept ?? shown)}
      onBlur={() => {
        const text = typing ?? kept ?? shown;
        const parsed = parse(text);
        const held = parsed === undefined ? undefined : Math.min(max, Math.max(min, parsed));
        setRejected(parseInteger(text).kind === "invalid" ? text : null);
        setTyping(null);
        if (held !== parsed) onChange(held);
      }}
    >
      <Label>{label}</Label>
      <Input dir="ltr" inputMode="numeric" className="text-start tabular-nums" />
      {description ? <Description>{description}</Description> : null}
      <FieldError>{error ?? (refused ? invalidMessage : undefined)}</FieldError>
    </TextField>
  );
}
