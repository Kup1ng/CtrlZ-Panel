"use client";

import {Modal} from "@heroui/react";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

// The standard frame of spec 9 (WF: centred, about 440px wide, the page dimmed behind it, a titled
// header, and a footer that stays while a tall body scrolls inside). `UrlModal` binds it to a URL
// parameter. A dialog that holds a secret (a TOTP secret, recovery codes, a one-time password, a
// reauth step) uses this one directly with its own state, so nothing of it reaches the address bar.
//
// `Modal.Container scroll="inside"` is what keeps the footer fixed; `Modal.Backdrop variant="opaque"`
// is the dimmed page of T-486. A Modal needs no trigger when it is controlled. Sheets are not used
// for dialogs in P1 because the wireframes centre them at every width.

export type DialogFrameProps = {
  isOpen: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  /** Buttons. Without any, the frame has no footer. */
  footer?: ReactNode;
  /** Escape and a click outside close it. Turn off for a step the user must finish or cancel on purpose. */
  isDismissable?: boolean;
  /**
   * A call is in flight whose answer the dialog must show (a one-time secret comes back in it). Escape, a click
   * outside and the close button are all off until it ends, so the dialog cannot be gone when the answer arrives
   * (wp9-r1-2). Cancel buttons inside the body are the caller's to disable.
   */
  isLocked?: boolean;
  className?: string;
};

export function DialogFrame({isOpen, onClose, title, children, footer, isDismissable = true, isLocked = false, className}: DialogFrameProps) {
  const c = useTranslations("common");
  const dismissable = isDismissable && !isLocked;
  return (
    <Modal.Backdrop
      isOpen={isOpen}
      onOpenChange={(open) => !open && !isLocked && onClose()}
      variant="opaque"
      isDismissable={dismissable}
      isKeyboardDismissDisabled={!dismissable}
    >
      {/* A phone has the toast at the foot of the page, over the dialog's footer: the dialog leaves it room (scr-m-4). */}
      <Modal.Container placement="center" scroll="inside" className="max-sm:pb-28">
        <Modal.Dialog className={["sm:max-w-[440px]", className ?? ""].filter(Boolean).join(" ")}>
          {isLocked ? null : <Modal.CloseTrigger aria-label={c("close")} />}
          <Modal.Header>
            <Modal.Heading>{title}</Modal.Heading>
          </Modal.Header>
          <Modal.Body>{children}</Modal.Body>
          {footer ? <Modal.Footer>{footer}</Modal.Footer> : null}
        </Modal.Dialog>
      </Modal.Container>
    </Modal.Backdrop>
  );
}
