"use client";

import {useState, type ReactNode} from "react";
import {createPortal} from "react-dom";

// WF: a dialog's footer stays at the bottom while a tall body scrolls (FE 9). `UrlModal` takes the footer as a prop, but the buttons of Add and
// Import need the state of the form that lives in the body, so the dialog hands the body an empty footer element and the body draws its
// buttons INTO it. The submit button names its form with the `form` attribute, since it is no longer inside it.
//
//   const {footer, slot} = useFooterSlot();
//   <UrlModal footer={footer}>{open ? <Body slot={slot} /> : null}</UrlModal>
//   inside the body:  <FooterPortal slot={slot}><EditorActions form="add-profile" .../></FooterPortal>

export function useFooterSlot() {
  const [slot, setSlot] = useState<HTMLElement | null>(null);
  const footer = <div ref={setSlot} className="flex w-full flex-col gap-2" />;
  return {footer, slot};
}

export function FooterPortal({slot, children}: {slot: HTMLElement | null; children: ReactNode}) {
  return slot ? createPortal(children, slot) : null;
}
