"use client";

import {useRequestIpClaim, type IPClaim} from "@ctrlz/api-client/hooks/clients.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {Button, FieldError, Input, Label, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../../feedback/CapacityNotice.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {useApiForm} from "../../forms/useApiForm.ts";
import {latinDigits, looksLikeCidr} from "./ipModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// `ipDialog=claim` (spec p3 10, 4.3, T-267): ask for an address to be the Endpoint's Plain DNS identity. A typed address or prefix, or the
// address this browser reaches the panel from. What the server answers decides what comes next: an active claim is done, a claim waiting for
// proof opens the proof dialog in this one's place, and one that needs an administrator says so and waits.
//
// The panel's view of the address can differ from the address a device's DNS comes from (carrier NAT, IPv6), and the dialog says so under the
// button that takes it.

export function ClaimDialog({endpointId, onClose, onClaimed}: {endpointId: string; onClose: () => void; onClaimed: (claim: IPClaim) => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const request = useRequestIpClaim();
  const form = useApiForm({focus: "cidr", fieldNamespace: "profiles"});
  const busy = useRef(false);
  const [text, setText] = useState("");
  const [pending, setPending] = useState(false);

  async function send(body: {cidr: string} | {useMyAddress: true}) {
    if (busy.current || form.blocked) return;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      const claim = await request.mutateAsync({endpointId, ...body});
      if (claim.needs_admin) toast.info(t("ips.claim.needsAdmin"));
      else if (claim.state !== "pending_proof") toast.success(t("ips.claim.done"));
      onClaimed(claim);
    } catch (error) {
      form.fail(error, {rename: {"/cidr": "cidr"}});
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  function submit() {
    const cidr = latinDigits(text).trim();
    if (cidr === "") return form.setFieldError("cidr", e("fields.required"));
    if (!looksLikeCidr(cidr)) return form.setFieldError("cidr", e("fields.invalid"));
    void send({cidr});
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={pending}
      title={t("ips.claim.title")}
      footer={
        <>
          <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={pending} isDisabled={form.retryIn > 0} onPress={submit}>
            {t("ips.claim.submit")}
          </PrimaryButton>
        </>
      }
    >
      <AuthForm form={form} onSubmit={submit}>
        <p className="text-muted text-sm">{t("ips.claim.intro")}</p>
        <TextField fullWidth name="cidr" value={text} isDisabled={pending} isInvalid={form.fieldMessage("cidr") !== undefined} onChange={(v) => form.bind("cidr", setText).onChange(v)}>
          <Label>{t("ips.claim.field")}</Label>
          <Input autoComplete="off" dir="ltr" inputMode="text" spellCheck={false} autoCapitalize="none" placeholder="203.0.113.7" />
          <p className="text-muted text-xs">{t("ips.claim.fieldHint")}</p>
          <FieldError>{form.fieldMessage("cidr")}</FieldError>
        </TextField>
        <div className="flex flex-col gap-1">
          <Button variant="outline" isDisabled={pending || form.retryIn > 0} onPress={() => void send({useMyAddress: true})}>
            {t("ips.claim.useMine")}
          </Button>
          <p className="text-muted text-xs">{t("ips.claim.useMineNote")}</p>
        </div>
        <CapacityNotice error={form.formError} />
        <FormError error={exceededCap(form.formError) ? null : form.formError} form={form} onRetry={submit} />
      </AuthForm>
    </DialogFrame>
  );
}
