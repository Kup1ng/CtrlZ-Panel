"use client";

import {unresolvedAlerts, useAckAlert, useAlerts} from "@ctrlz/api-client/admin/hooks/alerts.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Button} from "@heroui/react";
import {Tech} from "../../data/Tech.tsx";
import {useErrorText} from "../../feedback/errorText.ts";
import {keepFocus, selectedTabOf} from "../shared/restoreFocus.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {alertText, isSmsAlert} from "../../shell/adminAlertText.ts";
import {useTranslations} from "next-intl";

// Spec 13.3. Above the tabs: the unresolved alerts about the SMS service, each with an acknowledge button. This is where an
// operator sees a credential, credit or outbox cap problem (T-099, T-328). The words are the same as the banner's (13.6);
// here the closed code the worker recorded is shown as well, in `<Tech>`, since this is the page where it is acted on.
// A failed acknowledge is said under the alert and leaves it, so nothing is hidden that was not really resolved.
//
// The acknowledge button leaves with its alert when the call succeeds (and the whole section with the last alert), so the focus
// it held would fall to <body> (wp10-r12-1, the class of wp10-r9-1). keepFocus gives it to the next alert's button, or when none
// is left to the selected tab of the SMS tabs, which is where the admin was going next. A failure is read from `ack.error`, so the
// rejection is swallowed here: keepFocus only waits for the call to settle.

const STATUS = {critical: "danger", warning: "warning", info: "accent"} as const;

export function SmsAlerts() {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const errorText = useErrorText();
  const alerts = useAlerts();
  const ack = useAckAlert();
  // The acknowledgement needs the fresh TOTP window: the dialog opens and the call is repeated once (admin-fresh, gate-r32-3).
  const {send} = useCheckedWrite();
  const rows = unresolvedAlerts(alerts.data).filter(isSmsAlert);
  if (rows.length === 0) return null;
  const afterAck = () => document.querySelector<HTMLElement>('[data-testid="sms-alerts"] button:not([disabled])') ?? selectedTabOf(t("sms.tabs.label"));

  return (
    <section aria-label={t("sms.alerts.region")} className="mb-6 flex flex-col gap-2" data-testid="sms-alerts">
      {rows.map((alert) => {
        const words = alertText(alert, (key) => t.has(`alerts.${key}` as never));
        const failed = ack.isError && ack.variables === alert.id;
        return (
          <Alert key={alert.id} status={STATUS[alert.severity]}>
            <Alert.Indicator />
            <Alert.Content className="min-w-0">
              <Alert.Title>{t(`alerts.${words.titleKey}` as never, words.values as never)}</Alert.Title>
              <Alert.Description className="[overflow-wrap:anywhere]">
                {words.textKey ? t(`alerts.${words.textKey}` as never, words.values as never) : null}{" "}
                {words.code ? <Tech className="text-xs">{words.code}</Tech> : null}
              </Alert.Description>
              <p className="text-muted mt-1 text-xs">{format.dateTime(alert.created_at)}</p>
              {failed ? (
                <p role="alert" className="mt-1 text-sm text-(--danger-text)">
                  {errorText(ack.error)}
                </p>
              ) : null}
            </Alert.Content>
            <Button size="sm" variant="tertiary" isPending={ack.isPending && ack.variables === alert.id} onPress={() => keepFocus(() => send(() => ack.mutateAsync(alert.id)).catch(() => undefined), null, afterAck)}>
              {t("sms.alerts.ack")}
            </Button>
          </Alert>
        );
      })}
    </section>
  );
}
