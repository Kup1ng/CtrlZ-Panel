"use client";

import type {ReactNode} from "react";

import {DialogFrame} from "./DialogFrame.tsx";
import type {UrlDialog} from "./useUrlDialog.ts";

// Spec 9. `DialogFrame` bound to a `useUrlDialog` result:
//
//   const dialog = useUrlDialog("ruleDialog");
//   <UrlModal dialog={dialog} title={...} footer={...}>{body}</UrlModal>
//
// The caller owns the hook, because it usually needs `dialog.value` to decide what to show. `isOpen`
// overrides the parameter for a value the caller does not accept (a hand-typed `helpPane=nonsense`
// opens nothing, and the URL is left for the caller to clean).

export type UrlModalProps = {
  dialog: Pick<UrlDialog, "isOpen" | "close">;
  isOpen?: boolean;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  isDismissable?: boolean;
  /** A call is in flight whose answer the dialog must show (see DialogFrame): Escape, the backdrop and the close button are off. */
  isLocked?: boolean;
  className?: string;
};

export function UrlModal({dialog, isOpen = dialog.isOpen, ...frame}: UrlModalProps) {
  return <DialogFrame isOpen={isOpen} onClose={dialog.close} {...frame} />;
}
