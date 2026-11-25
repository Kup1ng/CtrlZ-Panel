"use client";

import {toAsciiDigits} from "@ctrlz/i18n/digits.ts";
import {InputOTP, Label} from "@heroui/react";
import {useId, type ChangeEvent, type ReactNode, type Ref} from "react";

import {stripInvisible} from "./invisible.ts";

// Spec 10.3. A six-digit code, for the SMS code and for the authenticator code.
//
// - `dir="ltr"` on the wrapper: a code is a technical token, so the slots run left to right in Persian.
// - The slots show what was typed, Persian or Arabic digits included, because the pattern admits them;
//   `onComplete` hands the caller the ASCII form, and that is the only value that is ever sent.
// - `autoComplete="one-time-code"` lets a phone offer the code from the SMS.
// - Pasting "123 456" or "123-456" works: spaces and hyphens are dropped before the pattern is checked. So are
//   the invisible format characters (LRM, RLM, ZWNJ, ZWSP) that a Persian message or a chat app wraps a code in.
//   input-otp checks the pattern on what it is given and drops the whole paste without a word when it fails, so
//   every path that brings text in strips them first: the paste transformer, and the change handler for what
//   autofill, a drop or an IME puts in the input (wp8-r11-1).
// - The caller decides what completing does and blocks a second submit with its own pending state.
//   The value is controlled, so a wrong code can clear the slots and put the focus back on the first.

export const OTP_LENGTH = 6;

/**
 * The nonce of this page's CSP, from the `csp-nonce` meta tag that RootDocument writes (the one React Aria
 * reads too). input-otp puts one `<style>` element in the head when it mounts, and under the strict
 * `style-src-elem` of spec 15.2 the browser refuses it unless it carries the nonce. It is read in the
 * browser only: the element is made in an effect, and the prop is never rendered into the HTML.
 */
function pageNonce(): string | undefined {
  if (typeof document === "undefined") return undefined;
  // The .nonce property: the attribute reads "" in a document with a CSP header (gate-r30-1).
  return (document.querySelector('meta[name="csp-nonce"]') as HTMLMetaElement | null)?.nonce || undefined;
}

// Latin, Persian (U+06F0..06F9) and Arabic-Indic (U+0660..0669) digits.
const OTP_PATTERN = "^[0-9\\u06F0-\\u06F9\\u0660-\\u0669]*$";

export const dropSeparators = (text: string) => stripInvisible(text).replace(/[\s\-‐-―]/g, "");

/**
 * Runs before input-otp's own change handler (capture phase on the wrapper) and cleans what the input holds, so
 * a code that autofill delivers with a mark in it is taken, not dropped. Only invisible characters are removed
 * here: a letter or a stray space still fails the pattern, as it should.
 */
function cleanInput(event: ChangeEvent<HTMLElement>) {
  const input = event.target;
  if (!(input instanceof HTMLInputElement)) return;
  const clean = stripInvisible(input.value);
  if (clean !== input.value) input.value = clean;
}

export function OtpField({
  label,
  description,
  value,
  onChange,
  onComplete,
  isDisabled,
  errorMessage,
  name,
  ref,
}: {
  label: string;
  description?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  /** Called with the code as ASCII digits when every slot is filled. */
  onComplete: (code: string) => void;
  isDisabled?: boolean;
  errorMessage?: string;
  name?: string;
  /** The input behind the slots, for the caller's `focus()`. */
  ref?: Ref<HTMLInputElement>;
}) {
  const id = useId();
  const descriptionId = `${id}-description`;
  const errorId = `${id}-error`;
  const invalid = errorMessage !== undefined;
  const describedBy = [description ? descriptionId : null, invalid ? errorId : null].filter(Boolean).join(" ") || undefined;

  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={id}>{label}</Label>
      {description ? (
        <div id={descriptionId} className="text-muted text-sm">
          {description}
        </div>
      ) : null}
      <div dir="ltr" className="flex justify-center" onChangeCapture={cleanInput}>
        <InputOTP
          id={id}
          ref={ref}
          name={name}
          nonce={pageNonce()}
          maxLength={OTP_LENGTH}
          pattern={OTP_PATTERN}
          inputMode="numeric"
          autoComplete="one-time-code"
          pasteTransformer={dropSeparators}
          variant="secondary"
          isDisabled={isDisabled}
          isInvalid={invalid}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          value={value}
          onChange={onChange}
          onComplete={(code) => onComplete(toAsciiDigits(code))}
        >
          <InputOTP.Group>
            <InputOTP.Slot index={0} />
            <InputOTP.Slot index={1} />
            <InputOTP.Slot index={2} />
          </InputOTP.Group>
          {/* The dash between the groups is decoration: HeroUI gives it role="img" with no name, which axe fails. */}
          <InputOTP.Separator aria-hidden="true" role="presentation" />
          <InputOTP.Group>
            <InputOTP.Slot index={3} />
            <InputOTP.Slot index={4} />
            <InputOTP.Slot index={5} />
          </InputOTP.Group>
        </InputOTP>
      </div>
      {invalid ? (
        <p id={errorId} role="alert" className="text-sm text-(--danger-text)">
          {errorMessage}
        </p>
      ) : null}
    </div>
  );
}
