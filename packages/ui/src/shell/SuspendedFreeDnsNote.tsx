"use client";

import {useFreeDns} from "@ctrlz/api-client/hooks/freeDns.ts";
import {useTranslations} from "next-intl";

// The second sentence of the notice `ip_suspended` (Plan T-557, D55): what a query from the suspended address gets now. It depends on the switch of
// free DNS, which is read when the notice is opened, so the notice is right for the state of the day and not of the day it was made. While the
// switch is not known (the route cannot be read and the tab has no good answer under five minutes old) the sentence is left out.
export function SuspendedFreeDnsNote() {
  const t = useTranslations("shell");
  const free = useFreeDns();
  if (free.enabled === null) return null;
  return (
    <p className="text-muted mt-1 text-sm [overflow-wrap:anywhere]" data-testid="suspended-free-dns">
      {free.enabled ? t("bell.freeDns.suspendedOn") : t("bell.freeDns.suspendedOff")}
    </p>
  );
}
