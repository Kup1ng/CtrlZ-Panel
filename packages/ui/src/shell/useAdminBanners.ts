"use client";

import {noticesOf, unresolvedAlerts, useAckAlert, useAckNotices, useAlerts} from "@ctrlz/api-client/admin/hooks/alerts.ts";
import {skewIsWarning, useAdminClockOffset} from "@ctrlz/api-client/admin/clockSkew.ts";
import {useAdminSession} from "@ctrlz/api-client/admin/session.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useEffect, useState} from "react";

import {useFreshRecoverable} from "../auth/FreshTotpDialog.tsx";
import {useErrorText} from "../feedback/errorText.ts";
import {keepBannerFocus} from "../admin/shared/restoreFocus.ts";
import {alertText} from "./adminAlertText.ts";
import type {ShellBanner} from "./BannerStack.tsx";

// Spec 13.6. The admin's banners, in this order: the critical operator alerts (an outage must not sit behind a routine
// notice, wp10-r1-2), the notices of `AdminMe` (a console reset, a changed SMS gateway), then the other alerts.
//
// Dismissing a notice hides that banner for the life of this page. `POST /me/notices/ack` clears every notice that predates
// the session, and the client cannot tell which those are, so it is sent only when the last notice on the page has been
// dismissed: every notice has then been on screen and closed by a person. An ack on the first dismissal erased the ones
// still behind "n more", which exist to warn the owner who was not here (wp10-r1-6). A notice made in this session comes
// back from `/me` after the ack, and a new one is a new banner.

const NOTICE_SEVERITY = {password_reset: "warning", totp_reset: "warning", sms_gateway_changed: "warning"} as const;
const ALERT_STATUS = {critical: "danger", warning: "warning", info: "accent"} as const;

export function useAdminBanners(): ShellBanner[] {
  const t = useTranslations("admin");
  const format = useAppFormat();
  const errorText = useErrorText();
  const {status, me} = useAdminSession();
  const ready = status === "ready";
  const alerts = useAlerts({enabled: ready});
  const {mutate: ackNotices} = useAckNotices();
  const {mutateAsync: ackAlert} = useAckAlert();
  // The acknowledgement needs the fresh TOTP window: the dialog opens and the call is repeated once (admin-fresh, gate-r32-3).
  const run = useFreshRecoverable();
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set());
  const clockOffset = useAdminClockOffset();

  const notices = noticesOf(me).map((notice) => ({notice, id: `notice:${notice.kind}:${notice.at}`}));
  const unread = notices.filter(({id}) => !hidden.has(id));
  const allDismissed = ready && notices.length > 0 && unread.length === 0;
  // The ack goes out once the last notice on the page has been closed (see above), and again for a notice that arrives later.
  useEffect(() => {
    if (allDismissed) ackNotices();
  }, [allDismissed, ackNotices]);

  if (!ready) return [];
  const alertRows = unresolvedAlerts(alerts.data);
  const alertBanner = (alert: (typeof alertRows)[number]): ShellBanner => {
    const words = alertText(alert, (key) => t.has(`alerts.${key}` as never));
    return {
      id: `alert:${alert.id}`,
      status: ALERT_STATUS[alert.severity],
      title: t(`alerts.${words.titleKey}` as never, words.values as never),
      text: words.textKey ? t(`alerts.${words.textKey}` as never, words.values as never) : undefined,
      // The banner leaves once the acknowledgement has gone through, so the focus is given back when the call has settled.
      // A failure leaves the banner and the focus where they are, and is said in a toast: nothing else in the shell reads this
      // mutation's error, so without it Dismiss looks like a dead button (wp10-r14-2). A 401 also ends the session through the guard.
      onDismiss: () =>
        keepBannerFocus(() =>
          run(() => ackAlert(alert.id)).catch((error: unknown) => {
            toast.danger(errorText(error));
          }),
        ),
    };
  };
  const out: ShellBanner[] = alertRows.filter((a) => a.severity === "critical").map(alertBanner);

  // Spec 7.10 (T-088): the browser clock against the `Date` of /me. Positive means the server is ahead, so this device is behind.
  // The id carries the direction, so a dismissal does not hide a clock that went the other way.
  if (skewIsWarning(clockOffset) && clockOffset !== undefined) {
    const id = `clock:${clockOffset > 0 ? "behind" : "ahead"}`;
    if (!hidden.has(id)) {
      out.push({
        id,
        status: "warning",
        title: t("clock.title"),
        text: t(clockOffset > 0 ? "clock.behind" : "clock.ahead", {seconds: Math.round(Math.abs(clockOffset) / 1000)}),
        onDismiss: () => keepBannerFocus(() => setHidden((prev) => new Set(prev).add(id))),
      });
    }
  }

  for (const {notice, id} of unread) {
    // A kind this client does not know (the enum is closed today, so this is for a newer API) still shows, generically.
    const known = t.has(`notices.${notice.kind}.title` as never);
    const base = known ? `notices.${notice.kind}` : "notices.generic";
    out.push({
      id,
      status: NOTICE_SEVERITY[notice.kind] ?? "warning",
      title: t(`${base}.title` as never),
      text: t(`${base}.text` as never, {time: format.dateTime(notice.at)} as never),
      onDismiss: () => keepBannerFocus(() => setHidden((prev) => new Set(prev).add(id))),
    });
  }

  for (const alert of alertRows) if (alert.severity !== "critical") out.push(alertBanner(alert));
  return out;
}
