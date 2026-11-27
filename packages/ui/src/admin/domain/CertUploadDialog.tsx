"use client";

import {domainKeys, useUploadCertificate} from "@ctrlz/api-client/admin/hooks/domain.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, toast} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {answerMayBeLost} from "../../account/accountApi.ts";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {EditorActions} from "../../forms/EditorActions.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {FieldSelect} from "../shared/FieldSelect.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {CERTIFICATE_KINDS, CHAIN_MAX, KEY_MAX, pemProblem, type PemProblem, type UploadKind, withoutPrivateKey} from "./domainParts.ts";
import {PemField} from "./PemField.tsx";

// p4-nodes 4.3 and 9.2, T-344: `POST /certificates`. The admin gives the kind (wildcard of the zone, the panel host, the admin host), the
// chain and the private key; the server checks that the chain is a public one, that its names are the ones the kind needs, that the key is
// the leaf's, and that it is not about to expire (`cert_invalid`, `cert_not_public`, `cert_key_mismatch`, `cert_expiring`).
//
// The dialog is state-only and not a `?dialog=` of the address: the text it holds is a private key. The key is in this component's state
// and in the one request, and nowhere else: the mutation is reset when the call has ended, so the query cache's mutation record holds no
// copy of the body, and the dialog unmounts on close, which drops the state. A failed upload keeps what was typed so that it can be fixed
// and sent again; a successful one empties it.

export function CertUploadDialog({open, onClose}: {open: boolean; onClose: () => void}) {
  const t = useTranslations("nodes");
  const [busy, setBusy] = useState(false);
  return (
    <DialogFrame isOpen={open} onClose={onClose} isLocked={busy} title={t("domain.certs.upload.title")} className="sm:max-w-[560px]">
      {open ? <Form onClose={onClose} onBusy={setBusy} /> : null}
    </DialogFrame>
  );
}

function Form({onClose, onBusy}: {onClose: () => void; onBusy: (busy: boolean) => void}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const upload = useUploadCertificate();
  const queryClient = useQueryClient();
  const {send, pending} = useCheckedWrite();
  const form = useAdminForm();
  const [kind, setKind] = useState<UploadKind | null>(null);
  const [chain, setChain] = useState("");
  const [key, setKey] = useState("");
  const [lost, setLost] = useState(false);
  const busy = useRef(false);

  const problem = (field: "chain" | "key", code: PemProblem | "unreadable" | "keyInChain") => form.setFieldError(field === "chain" ? "chain_pem" : "key_pem", t(`domain.certs.upload.problem.${code}`));

  async function submit() {
    if (busy.current || form.blocked) return;
    // The first thing wrong is the one said: a form shows one field message at a time.
    if (!kind) return form.setFieldError("kind", t("domain.certs.upload.problem.kind"));
    const chainProblem = pemProblem("chain", chain);
    if (chainProblem) return problem("chain", chainProblem);
    const keyProblem = pemProblem("key", key);
    if (keyProblem) return problem("key", keyProblem);
    busy.current = true;
    onBusy(true);
    setLost(false);
    form.clear();
    let done = false;
    try {
      const created = await send(() => upload.mutateAsync({kind, chain_pem: chain.trim(), key_pem: key.trim()}));
      done = true;
      toast.success(t("domain.certs.upload.done", {when: format.date(created.not_after)}));
      // Nothing of the key outlives the call: the fields are emptied before the dialog closes, whatever the close does.
      setChain("");
      setKey("");
      onClose();
    } catch (error) {
      if (answerMayBeLost(error)) {
        // The answer was lost after the server may have stored the certificate: the list is asked again and the admin told, not offered a blind retry.
        void queryClient.invalidateQueries({queryKey: domainKeys.certificates});
        setLost(true);
      } else form.fail(error);
    } finally {
      // The body held the key: the mutation record is dropped, answered or not.
      upload.reset();
      if (!done) busy.current = false;
      onBusy(false);
    }
  }

  const disabled = pending;
  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <p className="text-muted text-sm">{t("domain.certs.upload.text")}</p>
      <FieldSelect
        name="kind"
        label={t("domain.certs.upload.kind")}
        placeholder={t("domain.certs.upload.pickKind")}
        error={form.fieldMessage("kind")}
        value={kind}
        onChange={(v) => {
          setKind(v as UploadKind);
          form.clearField("kind");
        }}
        isDisabled={disabled}
        options={CERTIFICATE_KINDS.map((k) => ({id: k, textValue: t(`domain.certs.kinds.${k}`), label: t(`domain.certs.kinds.${k}`)}))}
      />
      {kind ? <p className="text-muted -mt-2 text-xs">{t(`domain.certs.upload.kindHint.${kind}`)}</p> : null}
      <PemField
        name="pem_chain"
        label={t("domain.certs.upload.chain")}
        description={t("domain.certs.upload.chainHint")}
        value={chain}
        onChange={(v) => {
          // A private key that reaches this box, by a paste or a file, is removed at once and not held in the state of the chain (PG-r3-4).
          const clean = withoutPrivateKey(v);
          setChain(clean.text);
          if (clean.removed) problem("chain", "keyInChain");
          else form.clearField("chain_pem");
        }}
        error={form.fieldMessage("chain_pem")}
        isDisabled={disabled}
        maxBytes={CHAIN_MAX}
        onFileProblem={(p) => problem("chain", p)}
        testId="cert-chain"
      />
      <PemField
        name="pem_key_material"
        label={t("domain.certs.upload.key")}
        description={t("domain.certs.upload.keyHint")}
        value={key}
        onChange={(v) => {
          setKey(v);
          form.clearField("key_pem");
        }}
        error={form.fieldMessage("key_pem")}
        isDisabled={disabled}
        secret
        maxBytes={KEY_MAX}
        onFileProblem={(p) => problem("key", p)}
        testId="cert-key"
      />
      {lost ? (
        <Alert status="warning" data-testid="cert-lost">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Description>{t("domain.certs.upload.lost")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <EditorActions submitLabel={t("domain.certs.upload.submit")} isPending={disabled} retryIn={form.retryIn} onCancel={() => {
        setChain("");
        setKey("");
        onClose();
      }}
      />
    </AuthForm>
  );
}
