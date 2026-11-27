"use client";

import {Button, toast} from "@heroui/react";
import {copyOneTimeSecret, copyPlainText, ONE_TIME_SECRET_ATTRIBUTE} from "@ctrlz/api-client/clipboard.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

import {useWipeCopiedOnClose} from "../dialog/useWipeCopiedOnClose.ts";
import {useInWipeScope} from "../dialog/WipeScope.tsx";
import {Tech} from "./Tech.tsx";

// WF "Resolvers": every value a person is given to set a device up (an address, a host name, a DoH URL, a stamp) is a row: a name, the
// value in `Tech` (left to right, selectable, broken anywhere so a long stamp wraps instead of widening the page at 375), and a Copy
// button whose name has the label in it ("Copy DNS 1"), so a dialog with twelve of them has twelve different buttons.
//
// `secret` is for what is shown once or is a credential in itself (the DoH URL carries the token, a share URL, an API token value): it goes
// through the one writer of one-time secrets, and the clipboard is emptied when the dialog goes away (useWipeCopiedOnClose). A plain value
// is written and left alone, since the person copies an address to paste it into the settings of a device after the dialog is closed.

export type TechCopyRowProps = {
  /** What the value is: "DNS 1", "DoH URL". In the button's name. */
  label: string;
  value: string;
  /** Written as a one-time secret and wiped when the screen goes away. */
  secret?: boolean;
  /** A line under the value: the guide text of a stamp, a hint. */
  hint?: ReactNode;
  /** Let a long label wrap onto more lines instead of being cut: for a label that holds a protocol and an address. */
  wrapLabel?: boolean;
  className?: string;
};

function SecretWipe() {
  useWipeCopiedOnClose();
  return null;
}

export function TechCopyRow({label, value, secret = false, hint, wrapLabel = false, className}: TechCopyRowProps) {
  const c = useTranslations("common");
  // A dialog that holds a WipeScope wipes once when it goes; a row with no scope above it wipes when it goes itself.
  const scoped = useInWipeScope();
  // The value is select-all: a hand copy of it has to be recognised as a copy of the secret (FE 12.3, clipboard.ts).
  const secretProps = secret ? {[ONE_TIME_SECRET_ATTRIBUTE]: ""} : {};
  return (
    <div className={["tech-copy-row flex min-w-0 flex-col gap-1", className ?? ""].filter(Boolean).join(" ")}>
      {secret && !scoped ? <SecretWipe /> : null}
      <div className="flex min-w-0 items-center justify-between gap-2">
        <span className={["text-muted min-w-0 text-xs", wrapLabel ? "[overflow-wrap:anywhere]" : "truncate"].join(" ")}>{label}</span>
        <Button
          size="sm"
          variant="tertiary"
          aria-label={c("copyNamed", {name: label})}
          onPress={async () => {
            try {
              await (secret ? copyOneTimeSecret(value) : copyPlainText(value));
              toast.success(c("copied"));
            } catch {
              toast.danger(c("copyFailed"));
            }
          }}
        >
          <Icon name="copy" className="size-4" />
          {c("copy")}
        </Button>
      </div>
      <Tech className="bg-default block select-all px-2 py-1.5 text-sm break-all [overflow-wrap:anywhere]" {...secretProps}>{value}</Tech>
      {hint ? <p className="text-muted text-xs">{hint}</p> : null}
    </div>
  );
}
