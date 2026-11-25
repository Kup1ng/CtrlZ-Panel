"use client";

import {gatewaysQueryOptions, useGateways, useSaveRouting, type SmsGatewayRow, type SmsProvider} from "@ctrlz/api-client/admin/hooks/sms.ts";
import {Button, Card, Skeleton, toast} from "@heroui/react";
import {Tech} from "../../data/Tech.tsx";
import {SectionError} from "../../feedback/SectionError.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {ConflictNote} from "../shared/ConflictNote.tsx";
import {FieldSelect} from "../shared/FieldSelect.tsx";
import {RefreshFailed} from "../shared/RefreshFailed.tsx";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {providerLabel} from "./providers.ts";
import {keepFocus, keepRetry} from "../shared/restoreFocus.ts";

// Spec 13.3, the Routing tab: which gateway sends first and which one takes over when it fails. Only a gateway with
// credentials can be chosen (the API refuses one without, and the same one twice), so the lists hold those and the
// page refuses the same pair itself before it asks. `PUT /sms/routing` needs the fresh TOTP window.

export function RoutingTab() {
  const t = useTranslations("admin");
  const gateways = useGateways();
  if (gateways.isPending) return <Skeleton className="h-40 w-full rounded-(--radius-box)" />;
  if (!gateways.data) return <SectionError error={gateways.error} onRetry={keepRetry(() => gateways.refetch())} />;
  return (
    <Card className="max-w-xl gap-4 p-6" data-testid="sms-routing">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("sms.routing.title")}</Card.Title>
        <Card.Description>{t("sms.routing.text")}</Card.Description>
      </Card.Header>
      <Card.Content>
        <RefreshFailed error={gateways.error} onRetry={() => gateways.refetch()} />
        <RoutingForm gateways={gateways.data} />
      </Card.Content>
    </Card>
  );
}

type Route = {primary: string | null; fallback: string | null};
const routeOf = (gateways: SmsGatewayRow[]): Route => ({
  primary: gateways.find((g) => g.role === "primary")?.provider ?? null,
  fallback: gateways.find((g) => g.role === "fallback")?.provider ?? null,
});
// Only the route is compared: a gateway's breaker and last-success times change on their own and are no edit of anyone.
const sameRoute = (a: Route, b: Route) => a.primary === b.primary && a.fallback === b.fallback;

function RoutingForm({gateways}: {gateways: SmsGatewayRow[]}) {
  const t = useTranslations("admin");
  const save = useSaveRouting();
  // The read, the fresh-code dialog and the PUT are one pending state (wp10-r7-2, wp10-r7-5).
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  const currentRoute = routeOf(gateways);
  const currentPrimary = currentRoute.primary;
  const currentFallback = currentRoute.fallback;
  // The route as the gateways say it now, followed when another admin or a refetch changes it and the form is untouched (wp10-r3-3).
  const {draft, edit, dirty, reset, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm<Route>({primary: currentPrimary, fallback: currentFallback}, sameRoute);
  const {primary, fallback} = draft;
  // A role another admin changed after this one chose it: Save waits for an answer, since the write would undo their route (wp10-r5-3).
  const conflicted = conflicts.length > 0;
  const note = (key: "primary" | "fallback") =>
    conflicts.includes(key) ? (
      <ConflictNote
        name={key}
        value={serverValue[key] === null ? "" : <Tech mono={false}>{providerLabel(serverValue[key])}</Tech>}
        onKeep={() => keepMine(key)}
        onUseServer={() => {
          takeServer(key);
          form.clearField(key);
        }}
      />
    ) : null;
  const busy = useRef(false);

  const usable = gateways.filter((g) => g.configured);
  const options = usable.map((g) => ({id: g.provider, label: <Tech mono={false}>{providerLabel(g.provider)}</Tech>, textValue: providerLabel(g.provider)}));

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    if (primary === null) return form.setFieldError("primary", t("sms.routing.primaryRequired"));
    if (primary === fallback) return form.setFieldError("fallback", t("sms.routing.same"));
    busy.current = true;
    form.clear();
    try {
      // The page does not refetch while it stays open, so the route this write replaces is read before every try of it, the
      // one after the fresh-code dialog included (wp10-r6-5, wp10-r7-5).
      const written = await write({options: gatewaysQueryOptions(), pick: routeOf, seen: currentRoute, same: sameRoute}, () =>
        save.mutateAsync({primary: primary as SmsProvider, ...(fallback !== null ? {fallback: fallback as SmsProvider} : {})}),
      );
      if (!written) return;
      saved(draft);
      toast.success(t("sms.routing.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  if (usable.length === 0) return <p className="text-muted text-sm">{t("sms.routing.noneConfigured")}</p>;

  return (
    <AuthForm form={form} onSubmit={() => void submit()}>
      <div className="flex flex-col gap-2">
      <FieldSelect
        name="primary"
        label={t("sms.routing.primary")}
        placeholder={t("sms.routing.choose")}
        options={options}
        value={primary}
        onChange={(value) => {
          edit({primary: value});
          form.clearField("primary");
          form.clearField("fallback");
        }}
        error={form.fieldMessage("primary")}
        isDisabled={pending}
      />
      {note("primary")}
      </div>
      <div className="flex flex-col gap-2">
      <FieldSelect
        name="fallback"
        label={t("sms.routing.fallback")}
        description={t("sms.routing.fallbackHint")}
        placeholder={t("sms.routing.choose")}
        options={options}
        value={fallback}
        onChange={(value) => {
          edit({fallback: value});
          form.clearField("fallback");
        }}
        error={form.fieldMessage("fallback")}
        isDisabled={pending}
      />
      {note("fallback")}
      </div>
      <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
      <OfflineNotice />
      <div className="flex flex-wrap justify-end gap-2">
        <Button
          variant="tertiary"
          isDisabled={!dirty || pending}
          onPress={() => {
            form.clear();
            reset();
          }}
        >
          {t("settings.cancel")}
        </Button>
        <Button type="submit" variant="primary" isPending={pending} isDisabled={!dirty || conflicted || form.retryIn > 0}>
          {form.retryIn > 0 ? t("settings.retryIn", {seconds: form.retryIn}) : t("sms.routing.submit")}
        </Button>
      </div>
    </AuthForm>
  );
}
