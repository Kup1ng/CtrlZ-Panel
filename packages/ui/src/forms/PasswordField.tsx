"use client";

import {Button, Description, FieldError, InputGroup, Label, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState, useSyncExternalStore, type ClipboardEvent, type DragEvent} from "react";

import {NO_MANAGER} from "./noAutofill.ts";

// Spec 10, "PasswordField": a field with a show toggle. The toggle is a text button, since the
// allowlist of general icons has no eye and the word is clearer in both languages. The value is
// never stored by this component: the form owns it, and a hidden field is a plain password input,
// so the browser's password manager still sees it.
//
// `new-password` also turns on the browser's own generator; `current-password` is for sign-in.
// `off` is for a write-only secret that is not a password of the person typing it (an SMS gateway key). It is NOT an
// `<input type="password">`: the browsers' own managers (Chrome, Edge, Firefox, Safari) ignore `autocomplete="off"` on a
// password field, ignore the opt-out attributes of 1Password and the others, and offer to save or to update the console
// login with what was typed there (wp10-r1-5, wp10-r2-6). They only look at type=password, so the field is a text input
// that is masked by CSS (`-webkit-text-security`) until Show is pressed.
//
// A CSS mask is not a password input, and the field says so in what it does (wp10-r3-5, wp10-r3-7):
//   - It fails closed. Only a browser that reports the property (`CSS.supports`) gets the text input. One that does not, and the
//     server render, which cannot know, get a real `type="password"` with `autocomplete="new-password"`: the lesser evil is a
//     manager prompt, never a key drawn in clear text as it is pasted.
//   - Copy, cut and drag are cancelled while it is masked, which a password input does by itself, so the secret cannot reach the
//     clipboard (and Windows clipboard history or sync) without Show. Show is the one deliberate way to reveal it.
//   - What it does NOT give is the screen reader's protection: a text input is read out as it is typed and on focus, where a
//     password input is spoken as dots. That cannot be had without type=password and so without the manager prompt, which is
//     the other half of the same trade (wp10-r2-6). It is listed in Plan.md as a known limit of the gateway dialog.

const SECURITY_PROPERTY = "-webkit-text-security";

/** Whether the browser can draw the mask. `css` is injectable for the test; no global means the answer is no. */
export function supportsTextSecurity(css: {supports?: (property: string, value: string) => boolean} | undefined): boolean {
  try {
    return css?.supports?.(SECURITY_PROPERTY, "disc") === true;
  } catch {
    return false;
  }
}

const noSubscription = () => () => undefined;
// The server render does not know: it answers no, and the client takes over after hydration.
const useMaskSupported = () => useSyncExternalStore(noSubscription, () => supportsTextSecurity(typeof CSS === "undefined" ? undefined : CSS), () => false);

const keepSecret = (event: ClipboardEvent | DragEvent) => event.preventDefault();

export function PasswordField({
  name = "password",
  label,
  value,
  onChange,
  autoComplete,
  isDisabled,
  description,
  error,
}: {
  name?: string;
  label?: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: "current-password" | "new-password" | "off";
  isDisabled?: boolean;
  /** A hint under the field. A string, so that it is rendered as the field's own Description and read with it (wp8-r9-1). */
  description?: string;
  /** A message for this field: the field is invalid while it is set. */
  error?: string;
}) {
  const t = useTranslations("auth");
  const [visible, setVisible] = useState(false);
  const writeOnly = autoComplete === "off";
  const maskable = useMaskSupported();
  // A write-only secret in a browser that cannot mask is a password input, and then the browser's own rules apply.
  const asPassword = writeOnly && !maskable;
  const cssMasked = writeOnly && maskable && !visible;

  // A shown password is a plain text input to the browser, whose form history may keep the value of a
  // submitted text field and offer it to the next visitor of a shared computer (wp8-r5-7). So it is hidden
  // again the moment the form sends: every form disables its fields while a call runs, and the field follows
  // that, in the same commit that disables it, before the answer can arrive. It is not hidden by the
  // `submit` event itself (wp8-r6-4): a form checks its own fields inside `onSubmit` and may stop at an empty
  // phone number, and the visitor who showed the password to check a typo would find it hidden again by an
  // Enter that sent nothing. It stays hidden after a failure. A form that uses this field must pass
  // `isDisabled` while it sends; every auth form does.
  if (isDisabled && visible) setVisible(false);
  return (
    <TextField
      name={name}
      type={visible || (writeOnly && maskable) ? "text" : "password"}
      autoComplete={asPassword ? "new-password" : autoComplete}
      variant="secondary"
      fullWidth
      isDisabled={isDisabled}
      isInvalid={error !== undefined}
      value={value}
      onChange={onChange}
    >
      <Label>{label ?? t("fields.password.label")}</Label>
      <InputGroup variant="secondary" fullWidth>
        {/* A password is typed and read left to right whatever the page language is. While it is shown the
            input is type="text", which a browser spell-checks: Chrome Enhanced Spell Check and Edge Editor
            send that text to a cloud service, and a phone keyboard learns it. So all three are switched off,
            on the hidden input too, so there is no moment when they are on (wp8-r1-11). */}
        <InputGroup.Input
          dir="ltr"
          className={cssMasked ? "text-start [-webkit-text-security:disc]" : "text-start"}
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="none"
          {...(writeOnly ? NO_MANAGER : {})}
          {...(cssMasked ? {onCopy: keepSecret, onCut: keepSecret, onDragStart: keepSecret} : {})}
        />
        <InputGroup.Suffix className="pe-1">
          <Button
            size="sm"
            variant="ghost"
            // The name changes with the state and there is no aria-pressed: a toggle that has both is read as
            // "Hide password, pressed", which says the opposite of what it shows (wp8-r3-4). The name also
            // keeps the visible word ("Show", "Hide") in it, as WCAG 2.5.3 asks.
            aria-label={visible ? t("fields.password.hideLabel") : t("fields.password.showLabel")}
            isDisabled={isDisabled}
            onPress={() => setVisible((v) => !v)}
          >
            {visible ? t("fields.password.hide") : t("fields.password.show")}
          </Button>
        </InputGroup.Suffix>
      </InputGroup>
      {description ? <Description>{description}</Description> : null}
      <FieldError>{error}</FieldError>
    </TextField>
  );
}
