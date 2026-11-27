"use client";

import {Description, Label, Radio, RadioGroup} from "@heroui/react";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {PROFILE_KINDS, useCreateProfile, type ProfileKind} from "@ctrlz/api-client/hooks/profiles.ts";
import {sessionGuard} from "@ctrlz/api-client/sessionEnd.ts";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {UrlModal} from "../dialog/UrlModal.tsx";
import {parseProfileDialog} from "../dialog/dialogValues.ts";
import type {UrlDialog} from "../dialog/useUrlDialog.ts";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {useScreenFieldText} from "../feedback/useScreenFieldText.ts";
import {AuthForm} from "../forms/AuthForm.tsx";
import {EditorActions} from "../forms/EditorActions.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanProse, nameLength} from "../forms/invisible.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {useAnnounceCreated} from "./profileCreated.ts";
import {FooterPortal, useFooterSlot} from "./footerSlot.tsx";
import {ProfileNameField} from "./ProfileNameField.tsx";

// Spec p2 9.2, WF "Profiles" (T-128, T-129, T-136). `profileDialog=add`: the seven types as cards, from the `kind` enum of the document, and a
// name. A card is a radio of one group, so the keyboard picks one with the arrows. The new profile goes first in the list with a highlight.
// When some of its destinations are not available yet a toast says so (`flagged`).

export const PROFILE_NAME_MAX = 64;

export function AddProfileDialog({dialog}: {dialog: UrlDialog}) {
  const t = useTranslations("profiles");
  const open = parseProfileDialog(dialog.value) === "add";
  const [busy, setBusy] = useState(false);
  const {footer, slot} = useFooterSlot();
  return (
    <UrlModal dialog={dialog} isOpen={open} isLocked={busy} title={t("dialogs.add.title")} footer={footer}>
      {open ? <AddForm onClose={dialog.close} onBusy={setBusy} slot={slot} /> : null}
    </UrlModal>
  );
}

function AddForm({onClose, onBusy, slot}: {onClose: () => void; onBusy: (busy: boolean) => void; slot: HTMLElement | null}) {
  const t = useTranslations("profiles");
  const fieldText = useScreenFieldText();
  const create = useCreateProfile();
  const announce = useAnnounceCreated();
  const form = useApiForm({focus: "name", fieldNamespace: "profiles"});
  const [name, setName] = useState("");
  const [kind, setKind] = useState<ProfileKind>("custom");
  const [pending, setPending] = useState(false);
  const [capped, setCapped] = useState<unknown>(null);
  const busy = useRef(false);

  async function submit() {
    if (busy.current || form.blocked) return;
    const clean = cleanProse(name);
    if (clean === "") return form.setFieldError("name", fieldText("required", "name"));
    if (nameLength(clean) > PROFILE_NAME_MAX) return form.setFieldError("name", fieldText("too_long", "name"));
    busy.current = true;
    setPending(true);
    onBusy(true);
    form.clear();
    setCapped(null);
    // An answer that arrives after the session ended is not the present person's: nothing of it is announced or marked (S1-r3-5).
    const alive = sessionGuard();
    try {
      const created = await create.mutateAsync({name: clean, kind});
      if (!alive()) return;
      announce(created, t("dialogs.add.created", {name: created.profile.name}));
      busy.current = false;
      setPending(false);
      onBusy(false);
      onClose();
    } catch (error) {
      if (!alive()) return;
      busy.current = false;
      setPending(false);
      onBusy(false);
      // A limit is not wrong input: the notice says what was reached (CapacityNotice) and the form keeps what was typed.
      if (exceededCap(error)) setCapped(error);
      else form.fail(error, {rename: {"/name": "name", "/kind": "kind"}});
    }
  }

  return (
    <AuthForm id="add-profile" form={form} onSubmit={() => void submit()}>
      <ProfileNameField
        label={t("dialogs.add.name")}
        hint={t("dialogs.nameHint", {max: PROFILE_NAME_MAX})}
        value={name}
        isDisabled={pending}
        {...form.bind("name", setName)}
      />
      <RadioGroup name="kind" variant="secondary" value={kind} isDisabled={pending} onChange={(value) => setKind(value as ProfileKind)}>
        <Label>{t("dialogs.add.kind")}</Label>
        <div className="grid gap-2">
          {PROFILE_KINDS.map((id) => (
            <Radio key={id} value={id}>
              <Radio.Content className="bg-surface data-[selected=true]:border-accent data-[selected=true]:bg-accent/10 data-[focus-visible=true]:border-accent relative flex w-full flex-col items-start gap-0.5 rounded-(--radius-box) border border-border px-4 py-3 pe-12 transition-colors motion-reduce:transition-none">
                <Radio.Control className="absolute end-4 top-3.5 size-5">
                  <Radio.Indicator />
                </Radio.Control>
                <span className="text-start text-sm font-medium">{t(`kinds.${id}.name`)}</span>
                <Description>{t(`kinds.${id}.text`)}</Description>
              </Radio.Content>
            </Radio>
          ))}
        </div>
      </RadioGroup>
      <CapacityNotice error={capped} />
      <FormError error={form.formError} form={form} onRetry={() => void submit()} />
      <FooterPortal slot={slot}>
        <EditorActions form="add-profile" submitLabel={t("dialogs.add.submit")} isPending={pending} retryIn={form.retryIn} onCancel={onClose} />
      </FooterPortal>
    </AuthForm>
  );
}
