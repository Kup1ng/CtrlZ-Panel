"use client";

import {Button, Description, FieldError, Label, TextArea, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState, useSyncExternalStore, type ClipboardEvent, type CSSProperties, type DragEvent} from "react";

import {supportsTextSecurity} from "../../forms/PasswordField.tsx";
import {NO_MANAGER} from "../../forms/noAutofill.ts";

// The text of a PEM file for the certificate upload: pasted, or read from a file the admin picks. The text is read in the browser and goes
// nowhere but the state of the dialog that owns it and the one request that sends it (FE 9, 10).
//
// The private key is the one that needs care. It lives in state only: no URL, no storage, no query. It is a textarea, never a password input
// (a browser's manager looks at type=password and would offer to save it as the console login, wp10-r1-5), with a name that is not
// `username` or `password`, the opt-out attributes of the managers that read them, `autocomplete="off"`, and no spellcheck, plus the opt-out attributes of the writing assistants (NO_MANAGER), so
// the text is not sent to a spelling service or an assistant, or kept in form history. It is masked by CSS while it is hidden, in a browser that can draw the mask (the same
// test as PasswordField, which fails closed); copy, cut and drag are cancelled while it is masked, so the key cannot reach the clipboard or
// its history without the deliberate Show. The opt-outs apply to the chain box as well: a combined file with the key can be put there by mistake (PG-r3-4). The file input is emptied as soon as the file is read, so the path is not kept either.

const noSubscription = () => () => undefined;
const useMaskSupported = () => useSyncExternalStore(noSubscription, () => supportsTextSecurity(typeof CSS === "undefined" ? undefined : CSS), () => false);
const keepSecret = (event: ClipboardEvent | DragEvent) => event.preventDefault();

export function PemField({
  name,
  label,
  description,
  value,
  onChange,
  error,
  isDisabled,
  secret = false,
  maxBytes,
  onFileProblem,
  testId,
}: {
  name: string;
  label: string;
  description?: string;
  value: string;
  onChange: (value: string) => void;
  error?: string | undefined;
  isDisabled?: boolean;
  /** A private key: masked, and not copyable while masked. */
  secret?: boolean;
  /** A file larger than this is not read. */
  maxBytes: number;
  /** Said when the chosen file is too large or cannot be read. */
  onFileProblem: (problem: "tooLong" | "unreadable") => void;
  testId: string;
}) {
  const t = useTranslations("nodes");
  const maskable = useMaskSupported();
  const [visible, setVisible] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  // A masked key cannot be read back, so the toggle is the way to check a paste. It goes back to hidden when the dialog sends (fields disabled).
  if (isDisabled && visible) setVisible(false);
  const masked = secret && maskable && !visible;
  // Where the browser cannot draw the mask the key is on screen in clear (the field fails closed to a plain textarea), so at least it does not
  // leave by copy, cut or drag: the mask is the display, this is the export (PG-r1-13). The Show toggle exists only where there is a mask.
  const closed = secret && !visible;

  async function read(chosen: File | undefined) {
    if (!chosen) return;
    if (chosen.size > maxBytes) return onFileProblem("tooLong");
    try {
      onChange(await chosen.text());
    } catch {
      onFileProblem("unreadable");
    } finally {
      // The input keeps the name of the file it read: it is emptied so nothing about it stays in the page.
      if (file.current) file.current.value = "";
    }
  }

  return (
    <div className="flex flex-col gap-2">
      <TextField name={name} variant="secondary" fullWidth autoComplete="off" isDisabled={isDisabled} isInvalid={error !== undefined} value={value} onChange={onChange}>
        <Label>{label}</Label>
        <TextArea
          rows={5}
          dir="ltr"
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
          wrap="off"
          className="resize-y text-start font-mono text-xs"
          data-testid={testId}
          {...NO_MANAGER}
          {...(masked ? {style: {WebkitTextSecurity: "disc"} as CSSProperties} : {})}
          {...(closed ? {onCopy: keepSecret, onCut: keepSecret, onDragStart: keepSecret} : {})}
        />
        {description ? <Description>{description}</Description> : null}
        <FieldError>{error}</FieldError>
      </TextField>
      <div className="flex flex-wrap items-center gap-2">
        <input
          ref={file}
          type="file"
          accept=".pem,.crt,.cer,.key,text/plain"
          className="sr-only"
          tabIndex={-1}
          aria-hidden
          data-testid={`${testId}-file`}
          disabled={isDisabled}
          onChange={(event) => void read(event.currentTarget.files?.[0])}
        />
        <Button size="sm" variant="tertiary" isDisabled={isDisabled} onPress={() => file.current?.click()} aria-label={t("domain.certs.upload.chooseFile", {field: label})}>
          {t("domain.certs.upload.file")}
        </Button>
        {secret && maskable ? (
          <Button size="sm" variant="tertiary" isDisabled={isDisabled} aria-pressed={visible} aria-label={visible ? t("domain.certs.upload.hide", {field: label}) : t("domain.certs.upload.show", {field: label})} onPress={() => setVisible((v) => !v)}>
            {visible ? t("domain.certs.upload.hideWord") : t("domain.certs.upload.showWord")}
          </Button>
        ) : null}
        {value !== "" ? (
          <Button size="sm" variant="tertiary" isDisabled={isDisabled} aria-label={t("domain.certs.upload.clear", {field: label})} onPress={() => onChange("")}>
            {t("domain.certs.upload.clearWord")}
          </Button>
        ) : null}
      </div>
    </div>
  );
}
