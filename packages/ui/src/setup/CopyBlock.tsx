"use client";

import {Button, toast} from "@heroui/react";
import {copyOneTimeSecret, copyPlainText, ONE_TIME_SECRET_ATTRIBUTE} from "@ctrlz/api-client/clipboard.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {useWipeCopiedOnClose} from "../dialog/useWipeCopiedOnClose.ts";
import {useInWipeScope} from "../dialog/WipeScope.tsx";

// Text of several lines with one Copy button: the commands of a generator, a policy file, the drop-in of systemd-resolved. TechCopyRow is
// for one line; this keeps the line breaks and wraps long lines, left to right. `secret` is for text that carries the DoH token.

function Wipe() {
  useWipeCopiedOnClose();
  return null;
}

export function CopyBlock({label, text, secret = false}: {label: string; text: string; secret?: boolean}) {
  const c = useTranslations("common");
  const scoped = useInWipeScope();
  const secretProps = secret ? {[ONE_TIME_SECRET_ATTRIBUTE]: ""} : {};
  return (
    <div className="flex min-w-0 flex-col gap-1" data-testid="copy-block">
      {secret && !scoped ? <Wipe /> : null}
      <div className="flex min-w-0 items-center justify-between gap-2">
        <span className="text-muted min-w-0 truncate text-xs">{label}</span>
        <Button
          size="sm"
          variant="tertiary"
          aria-label={c("copyNamed", {name: label})}
          onPress={async () => {
            try {
              await (secret ? copyOneTimeSecret(text) : copyPlainText(text));
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
      <pre dir="ltr" translate="no" className="bg-default max-h-56 overflow-auto px-2 py-1.5 font-mono text-xs whitespace-pre-wrap select-all [overflow-wrap:anywhere]" {...secretProps}>
        {text}
      </pre>
    </div>
  );
}
