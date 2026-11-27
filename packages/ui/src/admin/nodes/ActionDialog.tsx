"use client";

import {Button} from "@heroui/react";
import type {QueryKey} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useRef, useState, type ReactNode} from "react";

import {ConfirmFrame} from "../../dialog/ConfirmFrame.tsx";
import {useErrorText} from "../../feedback/errorText.ts";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {useCheckedWrite, type WriteGuard} from "../shared/useCheckedWrite.ts";

// One confirmation for a write of the node pages (p4-nodes 9.2: every one is `admin-fresh`): the dialog says what the call does, the
// call goes through `useCheckedWrite().send` so that the fresh-code dialog opens and the call is repeated once, and a refusal of the route
// is shown in the dialog with the words of its code. `status` decides the look: a danger confirm for what cannot be undone, an accent one
// for the rest. The caller keeps `open` and gives the work in `run`; `onDone` runs after it succeeded and before the dialog closes.

export function ActionDialog<Data = unknown, Value = unknown, Key extends QueryKey = QueryKey>({
  open,
  onClose,
  status = "danger",
  icon,
  title,
  children,
  confirmLabel,
  run,
  onDone,
  testId,
  blocked = false,
  guard,
  onStale,
}: {
  open: boolean;
  onClose: () => void;
  status?: "accent" | "warning" | "danger";
  icon: ReactNode;
  title: ReactNode;
  children: ReactNode;
  confirmLabel: string;
  run: () => Promise<unknown>;
  onDone?: () => void;
  testId?: string;
  /** The page knows the call would be refused: the confirm stays off and the children say why. */
  blocked?: boolean;
  /**
   * The server value the confirmation was worded for. It is read again just before the call, also the repeat after the fresh code,
   * and when it moved nothing is sent: `onStale` runs (the page asks its lists again) and the dialog closes, so the admin reads the
   * new state before deciding again (wp10-r7-5, PG-r1-14).
   */
  guard?: WriteGuard<Data, Value, Key>;
  onStale?: () => void | Promise<unknown>;
}) {
  const c = useTranslations("common");
  const errorText = useErrorText();
  const {send, write} = useCheckedWrite();
  const [error, setError] = useState<unknown>(null);
  const [pending, setPending] = useState(false);
  const busy = useRef(false);

  function close() {
    if (busy.current) return;
    setError(null);
    onClose();
  }

  async function confirm() {
    if (busy.current) return;
    busy.current = true;
    setPending(true);
    setError(null);
    try {
      if (guard) {
        const sent = await write(guard, run);
        if (!sent) {
          await onStale?.();
          setError(null);
          onClose();
          return;
        }
      } else await send(run);
      onDone?.();
      setError(null);
      onClose();
    } catch (failure) {
      // A session that ended or a fresh code that was refused is handled where the call is made; the rest reads in the dialog.
      if (!isHandledError(failure)) setError(failure);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  const Confirm = status === "danger" ? Button : PrimaryButton;
  return (
    <ConfirmFrame
      isOpen={open}
      onOpenChange={(next) => !next && close()}
      status={status}
      icon={icon}
      title={title}
      footer={
        <>
          <Button slot="close" variant="tertiary" isDisabled={pending}>
            {c("cancel")}
          </Button>
          <Confirm {...(status === "danger" ? {variant: "danger" as const} : {})} isPending={pending} isDisabled={blocked} onPress={() => void confirm()} data-testid={testId}>
            {confirmLabel}
          </Confirm>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {children}
        {error ? (
          <p role="alert" className="text-sm text-(--danger-text)" data-testid="action-error">
            {errorText(error)}
          </p>
        ) : null}
      </div>
    </ConfirmFrame>
  );
}
