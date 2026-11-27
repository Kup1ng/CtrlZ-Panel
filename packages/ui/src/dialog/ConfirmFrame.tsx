"use client";

import {AlertDialog} from "@heroui/react";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

// The one frame of every confirmation (T-486, spec 9): an AlertDialog that is 440px wide like DialogFrame, so a
// confirmation and a form dialog are the same size at 1280 and the two never differ by 40px. HeroUI's alert dialog
// has no `scroll` prop (the Modal's is a Container variant): its body is already `min-h-0 flex-1 overflow-y-auto` under a
// `max-h-full` dialog, so a long body scrolls inside and the header and the footer stay. What it lacks is the width,
// because its container is `sm:w-fit` and a short text would shrink the dialog below 440, so the width is fixed here.
// Under the `sm` breakpoint the dialog takes the width of the screen less the container's 16px gutters, as DialogFrame does.

export type ConfirmFrameProps = {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  /** The icon inside the status disc; without one HeroUI draws the status's own. */
  icon?: ReactNode;
  status?: "accent" | "warning" | "danger";
  children: ReactNode;
  /** The buttons. A Cancel button is `slot="close"`. */
  footer: ReactNode;
};

export function ConfirmFrame({isOpen, onOpenChange, title, icon, status = "danger", children, footer}: ConfirmFrameProps) {
  const c = useTranslations("common");
  return (
    <AlertDialog.Backdrop isOpen={isOpen} onOpenChange={onOpenChange}>
      <AlertDialog.Container placement="center">
        <AlertDialog.Dialog className="sm:w-[440px] sm:max-w-[440px]">
          <AlertDialog.CloseTrigger aria-label={c("close")} />
          <AlertDialog.Header>
            <AlertDialog.Icon status={status}>{icon}</AlertDialog.Icon>
            <AlertDialog.Heading>{title}</AlertDialog.Heading>
          </AlertDialog.Header>
          <AlertDialog.Body>{children}</AlertDialog.Body>
          <AlertDialog.Footer>{footer}</AlertDialog.Footer>
        </AlertDialog.Dialog>
      </AlertDialog.Container>
    </AlertDialog.Backdrop>
  );
}
