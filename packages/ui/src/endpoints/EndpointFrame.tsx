"use client";

import {Alert, Button, Chip, Skeleton} from "@heroui/react";
import {useEndpoint, useEndpointTypes, type Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {isUuid} from "@ctrlz/api-client/hooks/support.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link, usePathname} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useLocale, useTranslations} from "next-intl";
import {useMemo, type ReactNode} from "react";

import {ReauthProvider} from "../auth/ReauthDialog.tsx";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {profileHref} from "../profiles/profileRoutes.ts";
import {FrameTabs} from "../screens/FrameTabs.tsx";
import {NotFoundView} from "../shell/NotFoundView.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {EndpointDialogs} from "./EndpointDialogs.tsx";
import {EndpointFrameContext, type EndpointFrameValue} from "./EndpointFrameContext.tsx";
import {endpointHref, endpointTabOf, ENDPOINT_TABS} from "./endpointRoutes.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p3 10. The layout of `/endpoints/[id]/*`:
//
//   [icon] name / type                    [Resolvers or Configure] [Edit]
//   profile link(s) and the status, in words
//   the held notice (D34), when an administrator holds it
//   [Clients] [Addresses] [Schedule]     pill tabs, links
//   the screen
//
// The frame owns the Endpoint (one query), the 404 for an id that is not one or that the API does not know (the text never says
// which), the held notice, and the URL dialogs that act on an Endpoint (`deviceDialog=...&deviceId=<id>`, drawn by `EndpointDialogs`).
// A screen gets the Endpoint from `useEndpointFrame()`.

export function EndpointFrame({id, children}: {id: string; children: ReactNode}) {
  const t = useTranslations("endpoints");
  const query = useEndpoint(id);
  if (!isUuid(id) || (query.isError && (query.error as {code?: string} | null)?.code === "not_found")) return <NotFoundView />;
  if (query.isError && !query.data) return <SectionError error={query.error} onRetry={() => void query.refetch()} />;
  if (!query.data) {
    return (
      <div role="status" aria-label={t("frame.loading")} className="flex flex-col gap-3">
        <Skeleton className="h-10 w-1/2" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }
  return (
    <ReauthProvider>
      <EndpointFrameBody endpoint={query.data}>{children}</EndpointFrameBody>
    </ReauthProvider>
  );
}

function EndpointFrameBody({endpoint, children}: {endpoint: Endpoint; children: ReactNode}) {
  const t = useTranslations("endpoints");
  const locale = useLocale();
  const format = useAppFormat();
  const pathname = usePathname();
  const devices = useDeviceDialog();
  const types = useEndpointTypes();
  const profiles = useProfiles();
  const tab = endpointTabOf(pathname);
  const value = useMemo<EndpointFrameValue>(() => ({endpoint, held: endpoint.admin_hold}), [endpoint]);

  const typeName = types.data?.find((x) => x.key === endpoint.type);
  const typeLabel = typeName ? (locale === "fa" ? typeName.name_fa : typeName.name_en) : endpoint.type;
  const profileName = (id: string) => profiles.data?.find((p) => p.id === id)?.name ?? "…";
  const pending = endpoint.status === "pending";

  // One history entry holds the dialog and its Endpoint, so Back closes both (dialog/useDeviceDialog.ts).
  const open = (dialog: "resolvers" | "configure" | "edit") => devices.open(dialog, endpoint.id);

  return (
    <EndpointFrameContext value={value}>
      <PageHeader icon="endpoints" title={endpoint.name} subtitle={typeLabel} helpKey="endpoints" />

      <div className="flex flex-wrap items-center gap-2" data-testid="endpoint-actions">
        {pending ? (
          <>
            <Chip size="sm" variant="soft" color="warning">
              <Chip.Label>{t("frame.notConfigured")}</Chip.Label>
            </Chip>
            <PrimaryButton size="sm" aria-label={t("frame.configureAria", {name: endpoint.name})} onPress={() => open("configure")}>
              {t("frame.configure")}
            </PrimaryButton>
          </>
        ) : (
          <>
            <Chip size="sm" variant="soft">
              <Chip.Label>{t(`state.${endpoint.admin_state}`)}</Chip.Label>
            </Chip>
            <Button size="sm" variant="outline" aria-label={t("frame.resolversAria", {name: endpoint.name})} onPress={() => open("resolvers")}>
              <Icon name="globe" className="size-4" />
              {t("frame.resolvers")}
            </Button>
          </>
        )}
        <Button size="sm" variant="outline" aria-label={t("frame.editAria", {name: endpoint.name})} onPress={() => open("edit")}>
          <Icon name="edit" className="size-4" />
          {t("frame.edit")}
        </Button>
        <span className="text-muted flex min-w-0 flex-wrap items-center gap-x-3 text-xs">
          <Link href={profileHref(endpoint.profile_id)} className="underline-offset-2 hover:underline">
            {t("frame.profile", {name: profileName(endpoint.profile_id)})}
          </Link>
          {endpoint.profile2_id ? (
            <Link href={profileHref(endpoint.profile2_id)} className="underline-offset-2 hover:underline">
              {t("frame.profileTwo", {name: profileName(endpoint.profile2_id)})}
            </Link>
          ) : null}
          <span>{endpoint.last_query_at ? t("lastQuery", {when: format.relative(endpoint.last_query_at)}) : t("noQuery")}</span>
        </span>
      </div>

      {value.held ? (
        <Alert status="warning" role="status">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t("frame.held")}</Alert.Title>
          </Alert.Content>
        </Alert>
      ) : null}

      <FrameTabs
        label={t("frame.tabsLabel", {name: endpoint.name})}
        current={tab}
        tabs={ENDPOINT_TABS.map((id) => ({id, label: t(`frame.tabs.${id}`), href: endpointHref(endpoint.id, id)}))}
      />

      <div className="endpoint-frame__content">{children}</div>

      <EndpointDialogs endpoint={endpoint} />
    </EndpointFrameContext>
  );
}
