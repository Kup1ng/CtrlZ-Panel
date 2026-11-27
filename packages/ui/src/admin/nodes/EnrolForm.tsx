"use client";

import {NODE_LIMIT, useCreateEnrollment, useNodes} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Switch} from "@heroui/react";
import {useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useRef, useState} from "react";

import {answerMayBeLost} from "../../account/accountApi.ts";
import {useLeaveGuard} from "../../dialog/useLeaveGuard.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {nodeKeys} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {OneTimeResult} from "../shared/OneTimeResult.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {IpField} from "./IpField.tsx";
import {ReplacementSteps} from "./ReplacementOrder.tsx";
import {NodeCard} from "./NodeCard.tsx";
import {looksLikeIp} from "./nodeParts.ts";

// p4-nodes 4.2 step 1, T-340. The admin gives the four addresses of the new host (and, if they like, the one address the enrolment may come
// from) and gets the install command once. The command carries the token, so it is shown in a state-only dialog, kept in no query, no key,
// no URL and no storage, and the mutation is reset as soon as the answer is in the dialog's state (FE 9, 10). It starts with a space on
// purpose, so the dialog says to copy it whole. The advertised addresses follow the bind addresses until the admin says the host is behind 1:1 NAT.

const FIELDS = ["dns_bind_ip", "dns_advertised_ip", "proxy_bind_ip", "proxy_advertised_ip"] as const;
type Field = (typeof FIELDS)[number];

type Result = {command: string; expiresAt: string};
const SUBMIT_ID = "enrol-submit";

export function EnrolForm() {
  const t = useTranslations("nodes");
  const a = useTranslations("admin");
  const format = useAppFormat();
  const create = useCreateEnrollment();
  const queryClient = useQueryClient();
  const {send, pending: writing} = useCheckedWrite();
  const form = useAdminForm();
  const nodes = useNodes();
  const [values, setValues] = useState<Record<Field | "bound_ip", string>>({bound_ip: "", dns_bind_ip: "", dns_advertised_ip: "", proxy_bind_ip: "", proxy_advertised_ip: ""});
  const [same, setSame] = useState(true);
  const [result, setResult] = useState<Result | null>(null);
  const [lost, setLost] = useState(false);
  const busy = useRef(false);
  const [pending, setPending] = useState(false);
  // The answer carries a command that cannot be shown again: leaving while the call runs would drop it.
  useLeaveGuard(pending);

  const known = nodes.data?.pages.flatMap((p) => p.items) ?? [];
  const full = known.length >= NODE_LIMIT && !nodes.hasNextPage;
  const set = (field: keyof typeof values, value: string) => {
    setValues((current) => ({...current, [field]: value}));
    form.clearField(field);
  };
  const fieldLabel = (field: Field) =>
    field === "dns_bind_ip" ? t("enrol.form.dnsBind") : field === "dns_advertised_ip" ? t("enrol.form.dnsAdvertised") : field === "proxy_bind_ip" ? t("enrol.form.proxyBind") : t("enrol.form.proxyAdvertised");
  const advertised = (field: "dns_advertised_ip" | "proxy_advertised_ip") => (same ? values[field === "dns_advertised_ip" ? "dns_bind_ip" : "proxy_bind_ip"] : values[field]);

  async function submit() {
    if (busy.current || form.blocked) return;
    const body = {
      dns_bind_ip: values.dns_bind_ip.trim(),
      dns_advertised_ip: advertised("dns_advertised_ip").trim(),
      proxy_bind_ip: values.proxy_bind_ip.trim(),
      proxy_advertised_ip: advertised("proxy_advertised_ip").trim(),
    };
    let refused = false;
    const check = (field: keyof typeof values, text: string, optional = false) => {
      // A form shows one field message at a time (setFieldError replaces the last), so the first field that is wrong is the one said.
      if (refused || (text === "" ? optional : looksLikeIp(text))) return;
      refused = true;
      form.setFieldError(field, text === "" ? t("enrol.form.required") : t("enrol.form.invalid"));
    };
    check("dns_bind_ip", body.dns_bind_ip);
    check("proxy_bind_ip", body.proxy_bind_ip);
    if (!same) {
      check("dns_advertised_ip", body.dns_advertised_ip);
      check("proxy_advertised_ip", body.proxy_advertised_ip);
    }
    const bound = values.bound_ip.trim();
    check("bound_ip", bound, true);
    if (refused) return;

    busy.current = true;
    setPending(true);
    setLost(false);
    form.clear();
    try {
      const created = await send(() => create.mutateAsync({...body, ...(bound ? {bound_ip: bound} : {})}));
      setResult({command: created.install_command, expiresAt: created.expires_at});
      // The command now lives in this component's state only.
      create.reset();
      setValues({bound_ip: "", dns_bind_ip: "", dns_advertised_ip: "", proxy_bind_ip: "", proxy_advertised_ip: ""});
    } catch (error) {
      if (hasCode(error, "address_refused", "service_unavailable")) form.fail(error);
      else if (answerMayBeLost(error)) {
        void queryClient.invalidateQueries({queryKey: nodeKeys.enrollments});
        setLost(true);
      } else form.fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  const disabled = pending || writing;
  return (
    <>
      <NodeCard title={t("enrol.form.title")} description={t("enrol.form.text")} testId="enrol-form">
        {full ? (
          <Alert status="warning" data-testid="enrol-full">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t("enrol.form.full.title")}</Alert.Title>
              <Alert.Description>{t("enrol.form.full.text")}</Alert.Description>
              <div className="mt-2 flex flex-col gap-2">
                <ReplacementSteps />
              </div>
            </Alert.Content>
          </Alert>
        ) : null}
        <AuthForm form={form} onSubmit={() => void submit()}>
          <div className="grid gap-4 sm:grid-cols-2">
            {FIELDS.filter((f) => !same || f.endsWith("bind_ip")).map((field) => (
              <IpField key={field} name={field} label={fieldLabel(field)} value={values[field]} onChange={(v) => set(field, v)} isDisabled={disabled} error={form.fieldMessage(field)} />
            ))}
          </div>
          <div className="flex items-center justify-between gap-3">
            <div className="flex min-w-0 flex-col">
              <span className="text-sm font-medium">{t("enrol.form.same")}</span>
              <span className="text-muted text-xs">{t("enrol.form.sameHint")}</span>
            </div>
            <Switch name="same" aria-label={t("enrol.form.same")} isSelected={same} isDisabled={disabled} onChange={setSame}>
              <Switch.Content>
                <Switch.Control>
                  <Switch.Thumb />
                </Switch.Control>
              </Switch.Content>
            </Switch>
          </div>
          <IpField
            name="bound_ip"
            label={t("enrol.form.bound")}
            description={t("enrol.form.boundHint")}
            value={values.bound_ip}
            onChange={(v) => set("bound_ip", v)}
            isDisabled={disabled}
            error={form.fieldMessage("bound_ip")}
            className="sm:max-w-sm"
          />
          {lost ? (
            <Alert status="warning" data-testid="enrol-lost">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Description>{t("enrol.form.lost")}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}
          <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
          <OfflineNotice />
          <div className="flex justify-end">
            <PrimaryButton type="submit" isPending={disabled} isDisabled={form.retryIn > 0} data-testid={SUBMIT_ID}>
              {form.retryIn > 0 ? a("settings.retryIn", {seconds: form.retryIn}) : t("enrol.form.submit")}
            </PrimaryButton>
          </div>
        </AuthForm>
      </NodeCard>
      {result ? (
        <OneTimeResult
          returnFocus={() => document.querySelector<HTMLElement>(`[data-testid="${SUBMIT_ID}"]`)}
          title={t("enrol.result.title")}
          intro={
            <>
              {t("enrol.result.intro")} {t("enrol.result.expires", {when: format.dateTime(result.expiresAt)})}
              <span className="mt-2 block">{t("enrol.result.spaceNote")}</span>
            </>
          }
          values={[{id: "command", label: t("enrol.result.command"), value: result.command, copyLabel: t("enrol.result.copy")}]}
          onClose={() => setResult(null)}
        />
      ) : null}
    </>
  );
}
