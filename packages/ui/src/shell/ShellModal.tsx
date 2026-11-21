"use client";

import {Modal} from "@heroui/react";
import {useTranslations} from "next-intl";
import type {ReactNode} from "react";

// The standard frame of spec 9 (WF: centred, about 440px wide, dimmed page,
// titled header, fixed footer with the body scrolling inside). It is
// dialog/UrlModal.tsx's job (WP7); the shell needs it for the bell and the help
// pane before that file exists, so this is the same markup, kept private to the
// shell. WP7 can swap the import.

export function ShellModal({
  isOpen,
  onClose,
  title,
  children,
  footer,
}: {
  isOpen: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const c = useTranslations("common");
  return (
    <Modal.Backdrop isOpen={isOpen} onOpenChange={(open) => !open && onClose()} variant="opaque">
      <Modal.Container placement="center" scroll="inside">
        <Modal.Dialog className="sm:max-w-[440px]">
          <Modal.CloseTrigger aria-label={c("close")} />
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
