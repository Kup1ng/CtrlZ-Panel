"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode} from "react";

import {EditorActions} from "./EditorActions.tsx";

// Spec 12 (WF "Preferences"): a full-width row with its value and an Edit button. Edit opens the editor
// on the same row. Only one row of a group is open at a time: opening another one closes the first, and
// the editor of a closed row is unmounted, so whatever it held (a typed password, a code, a secret) is
// gone with it and nothing waits in a hidden panel.
//
// The editor is either the content itself, which then has its own forms and calls `close`, or, for a
// single step, the content plus `onContinue`: the row draws Continue and Cancel under it, and the editor
// closes when `onContinue` resolves to `true`. A failure is the editor's to show: `onContinue` resolves
// to `false` after it has shown one.

type Group = {openId: string | null; setOpenId: (id: string | null) => void};
const GroupContext = createContext<Group | null>(null);

/** Rows inside one group share "one open at a time". A row outside a group manages itself. */
export function InlineEditGroup({children}: {children: ReactNode}) {
  const [openId, setOpenId] = useState<string | null>(null);
  const value = useMemo(() => ({openId, setOpenId}), [openId]);
  return <GroupContext value={value}>{children}</GroupContext>;
}

export type EditorControl = {close: () => void};

export type InlineEditRowProps = {
  /** Unique within the group. */
  id: string;
  label: ReactNode;
  value: ReactNode;
  /** One short line under the value. */
  description?: ReactNode;
  /** The editor. A function receives `close`. Without an editor the row has no Edit button. */
  editor?: ReactNode | ((control: EditorControl) => ReactNode);
  /** Single-step editors: Continue runs this. Resolve `true` to close the row. */
  onContinue?: () => Promise<boolean> | boolean;
  continueLabel?: string;
  /** Visible text of the Edit button (default: "Edit"). */
  editLabel?: string;
  /** Accessible name of the Edit button, which must start with the visible text (WCAG 2.5.3). */
  editAriaLabel?: string;
  /** Controls at the end of the row while it is closed, beside Edit. */
  trailing?: ReactNode;
  isDisabled?: boolean;
  className?: string;
  /** Called after the row opened or closed. */
  onOpenChange?: (open: boolean) => void;
};

export function InlineEditRow({
  id,
  label,
  value,
  description,
  editor,
  onContinue,
  continueLabel,
  editLabel,
  editAriaLabel,
  trailing,
  isDisabled = false,
  className,
  onOpenChange,
}: InlineEditRowProps) {
  const c = useTranslations("common");
  const group = useContext(GroupContext);
  const [ownOpen, setOwnOpen] = useState(false);
  const open = group ? group.openId === id : ownOpen;
  const [pending, setPending] = useState(false);
  const editButton = useRef<HTMLButtonElement>(null);
  const wasOpen = useRef(false);
  const notify = useRef(onOpenChange);
  useEffect(() => {
    notify.current = onOpenChange;
  });

  const setOpen = useCallback(
    (next: boolean) => {
      if (group) group.setOpenId(next ? id : group.openId === id ? null : group.openId);
      else setOwnOpen(next);
    },
    [group, id],
  );

  // The editor's own controls are gone once it closes, so the focus goes back to Edit instead of to the page.
  // Only when the row closed by its own action: a row that closed because another one opened (the group keeps one
  // open) must leave the focus where that other editor put it. Passive effects run in tree order, so a row that
  // comes later in the page would otherwise pull the focus down from the editor that just opened above it (wp9-r1-1).
  const otherOpen = group !== null && group.openId !== null && group.openId !== id;
  useEffect(() => {
    if (wasOpen.current && !open && !otherOpen) editButton.current?.focus();
    if (wasOpen.current !== open) notify.current?.(open);
    wasOpen.current = open;
  }, [open, otherOpen]);

  const close = useCallback(() => setOpen(false), [setOpen]);
  const editorNode = typeof editor === "function" ? editor({close}) : editor;

  return (
    <section
      data-row-id={id}
      data-open={open || undefined}
      className={["bg-surface rounded-(--radius-box) shadow-surface", className ?? ""].filter(Boolean).join(" ")}
    >
      <div className="flex min-h-16 flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3">
        <div className="flex min-w-0 flex-1 basis-40 flex-col gap-0.5">
          <h3 className="text-muted text-xs font-normal">{label}</h3>
          <div className="text-foreground min-w-0 text-sm font-medium wrap-break-word">{value}</div>
          {description ? <p className="text-muted text-xs">{description}</p> : null}
        </div>
        {!open && (trailing || editor !== undefined) ? (
          // Under the text when the line is too narrow for both (a phone), at the end of it otherwise.
          <div className="ms-auto flex flex-wrap items-center gap-2">
            {trailing}
            {editor !== undefined ? (
              <Button
                ref={editButton}
                size="sm"
                variant="tertiary"
                isDisabled={isDisabled}
                aria-label={editAriaLabel}
                onPress={() => setOpen(true)}
              >
                {editLabel ?? c("edit")}
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
      {open && editor !== undefined ? (
        // The editor appears with a short fade and nudge; a person who asked for less motion gets it at once.
        <div className="flex flex-col gap-4 px-4 pb-4 transition-[opacity,translate] duration-200 starting:-translate-y-1 starting:opacity-0 motion-reduce:transition-none">
          {onContinue ? (
            <form
              className="flex flex-col gap-4"
              onSubmit={async (event) => {
                event.preventDefault();
                if (pending) return;
                setPending(true);
                try {
                  if (await onContinue()) close();
                } finally {
                  setPending(false);
                }
              }}
            >
              {editorNode}
              <EditorActions submitLabel={continueLabel ?? c("next")} isPending={pending} onCancel={close} />
            </form>
          ) : (
            editorNode
          )}
        </div>
      ) : null}
    </section>
  );
}
