"use client";

import {useIpClaims, type IPClaim} from "@ctrlz/api-client/hooks/clients.ts";
import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useFreeDns} from "@ctrlz/api-client/hooks/freeDns.ts";
import {useSessions} from "@ctrlz/api-client/hooks/sessions.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useSyncExternalStore} from "react";

import {Tech} from "../data/Tech.tsx";
import {endpointHref} from "../endpoints/endpointRoutes.ts";
import {pairIsIpv6, readClosed, shouldRemind, subscribeClosed, writeClosed} from "./freeDnsModel.ts";

// Plan T-557 (D55) on the Endpoint page: two notices for an Endpoint that has Plain DNS on. They say what an unidentified device gets, and
// that depends on the switch of free DNS, so neither is drawn while the switch is not known (`useFreeDns` keeps the last good answer for five
// minutes and then gives `null`).
//
//   - the pair is IPv6: claims are IPv4 only, so Plain DNS over it is never matched to this Endpoint;
//   - the add-address reminder: the address of the current session (the one the sign-in was made from) is an IPv4 address that no claim of the
//     Endpoint holds. It can be closed, and it stays closed until that address changes. The session row keeps the address of the sign-in and
//     nothing refreshes it, so after a move to another network the reminder is about the old one; the text says "last sign-in" and not "now"
//     (V1-r1-2). Judging the address of the browser as it is needs a field of the API that returns the caller's address (docs/wireframes/p4-comparison.md).

export function FreeDnsNotices({endpoint}: {endpoint: Endpoint}) {
  const free = useFreeDns({enabled: endpoint.legacy_dns});
  if (!endpoint.legacy_dns || free.enabled === null) return null;
  return (
    <>
      {pairIsIpv6(free.primary, free.fallback) ? <PairIpv6 enabled={free.enabled} /> : null}
      {free.enabled ? <AddReminder endpoint={endpoint} /> : null}
    </>
  );
}

function PairIpv6({enabled}: {enabled: boolean}) {
  const t = useTranslations("endpoints");
  return (
    <Alert status="warning" role="status" data-testid="free-dns-ipv6">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{t("freeDns.ipv6.title")}</Alert.Title>
        <Alert.Description>{enabled ? t("freeDns.ipv6.on") : t("freeDns.ipv6.off")}</Alert.Description>
      </Alert.Content>
    </Alert>
  );
}

function AddReminder({endpoint}: {endpoint: Endpoint}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const router = useRouter();
  const sessions = useSessions();
  const claims = useIpClaims(endpoint.id);
  // `undefined` on the server and in the first client render, so the reminder never flashes; the saved value is read right after.
  const closedFor = useSyncExternalStore(subscribeClosed, () => readClosed(endpoint.id), () => undefined);

  const ip = sessions.data?.find((row) => row.current)?.ip;
  if (closedFor === undefined || !shouldRemind({enabled: true, legacyDns: endpoint.legacy_dns, ip, claims: claims.data as readonly IPClaim[] | undefined, closedFor})) return null;
  return (
    <Alert status="accent" role="status" data-testid="free-dns-remind">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{t("freeDns.remind.title")}</Alert.Title>
        <Alert.Description>
          {t.rich("freeDns.remind.text", {ip: ip ?? "", tech: (chunks) => <Tech>{chunks}</Tech>})}
        </Alert.Description>
        <Button size="sm" variant="outline" className="mt-2" onPress={() => router.push(`${endpointHref(endpoint.id, "ips")}?ipDialog=claim`)}>
          {t("freeDns.remind.add")}
        </Button>
      </Alert.Content>
      <Button
        isIconOnly
        size="sm"
        variant="ghost"
        aria-label={c("close")}
        onPress={() => {
          if (ip) writeClosed(endpoint.id, ip);
        }}
      >
        <Icon name="close" className="size-4" />
      </Button>
    </Alert>
  );
}

/**
 * What Plain DNS devices get once Legacy DNS is off for an Endpoint (T-223): its claims stop identifying them, so they fall to free DNS, or are
 * refused when the switch is off. Nothing while the switch is not known.
 */
export function FreeDnsLegacyOff({className}: {className?: string}) {
  const t = useTranslations("endpoints");
  const free = useFreeDns();
  if (free.enabled === null) return null;
  return (
    <p className={className ?? "text-muted text-xs"} data-testid="legacy-off-free-dns">
      {free.enabled ? t("freeDns.legacyOff.on") : t("freeDns.legacyOff.off")}
    </p>
  );
}
