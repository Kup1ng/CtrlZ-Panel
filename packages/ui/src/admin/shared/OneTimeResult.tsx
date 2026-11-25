"use client";

import {ONE_TIME_SECRET_ATTRIBUTE} from "@ctrlz/api-client/clipboard.ts";
import {Alert, Button, Checkbox} from "@heroui/react";
import {Tech} from "../../data/Tech.tsx";
import {ConfirmFrame} from "../../dialog/ConfirmFrame.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {useLeaveGuard} from "../../dialog/useLeaveGuard.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState, type ReactNode} from "react";

import {CopyButton} from "./CopyButton.tsx";
import {restoreFocusLater} from "./restoreFocus.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// Spec 13.1 and 13.2: the result panel of a create call that returns a value shown once (a user's one-time password,
// an invite's link). It is state-only: a secret never joins the URL (the `dialog=` parameter of the form that
// made it was removed before this opened), it lives in the props of this component and goes when the panel closes.
//
// Closing with the value unread asks to confirm. "Read" means the admin pressed Copy or ticked "I have saved it": a
// value that was never taken cannot be shown again, so the click that would lose it has to be a second, deliberate one.
// Back, reload and a closed tab ask too (`useLeaveGuard`), as the account page's recovery codes do.
//
// The panel is mounted only while it has a value, so every way of closing it unmounts the modal and React Aria's own hand-back
// of the focus can find nothing to go to (wp10-r7-1, see restoreFocus.ts). `returnFocus` names the page's own button
// the focus goes back to when that happens, whichever way the panel was closed.

export type OneTimeValue = {id: string; label: string; value: string; copyLabel: string};

export function OneTimeResult({
  title,
  intro,
  values,
  onClose,
  returnFocus,
}: {
  title: ReactNode;
  /** One line above the values: what they are for. */
  intro?: ReactNode;
  values: OneTimeValue[];
  onClose: () => void;
  /** The element that opened the form this panel came from. Used only when the focus is lost as the panel goes. */
  returnFocus: () => HTMLElement | null;
}) {
  const t = useTranslations("admin");
  const c = useTranslations("common");
  const [saved, setSaved] = useState(false);
  const [confirm, setConfirm] = useState(false);

  const request = () => (saved ? onClose() : setConfirm(true));
  useLeaveGuard(true, request);

  const target = useRef(returnFocus);
  useEffect(() => {
    target.current = returnFocus;
  });
  useEffect(() => () => restoreFocusLater(() => target.current()), []);

  return (
    <>
      <DialogFrame
        isOpen
        onClose={request}
        title={title}
        footer={
          <div className="flex w-full flex-wrap items-center justify-between gap-3">
            <Checkbox name="saved" isSelected={saved} onChange={setSaved}>
              <Checkbox.Content>
                <Checkbox.Control>
                  <Checkbox.Indicator />
                </Checkbox.Control>
                {t("result.saved")}
              </Checkbox.Content>
            </Checkbox>
            <PrimaryButton onPress={request}>
              {c("done")}
            </PrimaryButton>
          </div>
        }
      >
        <div className="flex flex-col gap-4" data-testid="one-time-result">
          <Alert status="warning">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Description>{t("result.warning")}</Alert.Description>
            </Alert.Content>
          </Alert>
          {intro ? <p className="text-muted text-sm">{intro}</p> : null}
          {values.map((v) => (
            <div key={v.id} className="flex flex-col gap-1">
              <span className="text-muted text-xs">{v.label}</span>
              <div className="flex items-center justify-between gap-2">
                <span data-testid={`one-time-${v.id}`} {...{[ONE_TIME_SECRET_ATTRIBUTE]: ""}} className="min-w-0 text-sm [overflow-wrap:anywhere] select-all">
                  <Tech>{v.value}</Tech>
                </span>
                <CopyButton text={v.value} label={v.copyLabel} onCopied={() => setSaved(true)} />
              </div>
            </div>
          ))}
          <p className="text-muted text-xs" data-testid="copy-note">
            {t("copyNote")}
          </p>
        </div>
      </DialogFrame>

      <ConfirmFrame
        isOpen={confirm}
        onOpenChange={setConfirm}
        status="warning"
        icon={<Icon name="warning" className="size-5" />}
        title={t("result.confirmTitle")}
        footer={
          <>
            <Button slot="close" variant="tertiary">
              {t("result.keep")}
            </Button>
            <Button variant="danger" onPress={onClose}>
              {t("result.closeAnyway")}
            </Button>
          </>
        }
      >
        <p>{t("result.confirmText")}</p>
      </ConfirmFrame>
    </>
  );
}
