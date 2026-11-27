"use client";

import {useSendFeedback, type FeedbackKind} from "@ctrlz/api-client/hooks/apiTokens.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Button, Description, FieldError, Label, TextArea, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanMultiline, nameLength} from "../forms/invisible.ts";
import {SubmitButton} from "../forms/SubmitButton.tsx";
import {useApiForm} from "../forms/useApiForm.ts";

// Request Feature and Contact (spec p3 10, Plan T-125): one message to the owner of the service, posted to `POST /feedback`, which lands in the
// admin inbox of P7. No external link and no mail address: the dialog is the whole channel. The body is 1 to 4,000 characters, several lines
// allowed (D6 round 2), so it is cleaned with `cleanMultiline` and counted in code points as the server counts. 20 a day per tenant: past that
// the answer is the ordinary 429 with its wait.
//
// A state-only dialog: what a person writes is not put in the address, and the draft goes with the dialog when it closes (it is also
// dropped when the message was sent).

const MAX = 4000;

export function FeedbackDialog({kind, onClose}: {kind: FeedbackKind | null; onClose: () => void}) {
  // The dialog keeps the last kind while it animates out, so its title does not change under the closing frame.
  const [shown, setShown] = useState<FeedbackKind>("feature");
  // State that follows a prop, set while rendering: an effect would draw one frame with the old kind.
  if (kind && kind !== shown) setShown(kind);
  return <FeedbackBody key={shown} kind={shown} isOpen={kind !== null} onClose={onClose} />;
}

function FeedbackBody({kind, isOpen, onClose}: {kind: FeedbackKind; isOpen: boolean; onClose: () => void}) {
  const t = useTranslations("shell");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const f = useAppFormat();
  const send = useSendFeedback();
  const form = useApiForm({focus: "body"});
  const [body, setBody] = useState("");
  const busy = useRef(false);
  const length = nameLength(body);

  const close = () => {
    if (send.isPending) return;
    setBody("");
    form.clear();
    onClose();
  };

  async function submit() {
    if (busy.current || form.blocked) return;
    const text = cleanMultiline(body);
    if (text === "") return form.setFieldError("body", e("fields.required"));
    if (nameLength(text) > MAX) return form.setFieldError("body", e("fields.too_long"));
    busy.current = true;
    form.clear();
    try {
      await send.mutateAsync({kind, body: text});
      setBody("");
      toast.success(t(`feedback.${kind}.sent`));
      onClose();
    } catch (error) {
      form.fail(error, {field: "body"});
    } finally {
      busy.current = false;
    }
  }

  return (
    <DialogFrame isOpen={isOpen} onClose={close} isLocked={send.isPending} title={t(`feedback.${kind}.title`)}>
      <AuthForm form={form} onSubmit={() => void submit()}>
        <p className="text-muted text-sm">{t(`feedback.${kind}.text`)}</p>
        <TextField
          fullWidth
          isDisabled={send.isPending}
          name="body"
          value={body}
          isInvalid={form.fieldMessage("body") !== undefined}
          onChange={(value) => form.bind("body", setBody).onChange(value)}
        >
          <Label>{t(`feedback.${kind}.label`)}</Label>
          <TextArea rows={6} maxLength={MAX * 2} data-testid="feedback-body" />
          <Description className={length > MAX ? "text-danger-soft-foreground" : undefined}>
            {t("feedback.counter", {count: f.number(length), max: f.number(MAX)})}
          </Description>
          <FieldError>{form.fieldMessage("body")}</FieldError>
        </TextField>
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
        <div className="flex items-center justify-end gap-2">
          <Button variant="tertiary" isDisabled={send.isPending} onPress={close}>
            {c("cancel")}
          </Button>
          <SubmitButton isPending={send.isPending} retryIn={form.retryIn}>
            {t("feedback.send")}
          </SubmitButton>
        </div>
      </AuthForm>
    </DialogFrame>
  );
}
