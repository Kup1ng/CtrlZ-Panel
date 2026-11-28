"use client";

import {Button, Skeleton} from "@heroui/react";
import {useEndpoint, type Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {WipeScope} from "../dialog/WipeScope.tsx";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {ClientPicker} from "./ClientPicker.tsx";
import {ResolverSections} from "./ResolverSections.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// `deviceDialog=resolvers&deviceId=<id>` (spec p3 10, T-239, T-240, WF "Endpoints"). It opens by itself after an Endpoint is created, from
// the Resolvers button of a row and of the frame. The body is `ResolverSections`; this adds the client picker, the not-ready state and the
// way into Help Me Configure. The values carry the DoH token, so the view is read when the dialog opens and the cache forgets it soon
// after (gcTime of resolverViewQuery); nothing of it reaches the address.

export function ResolversDialog({endpoint, client = "", onClient = () => {}}: {endpoint?: Endpoint; client?: string; onClient?: (client: string) => void}) {
  const devices = useDeviceDialog();
  const isOpen = devices.dialog === "resolvers" && devices.deviceId !== null;
  // The body is only mounted while open: no request for a view nobody looks at. The client choice is SetupDialogs's, so Help Me Configure opens on the
  // client that was picked here (S7-r2-6), and it starts over on each opening.
  if (!isOpen || !devices.deviceId) return null;
  return (
    <ResolversBody
      id={devices.deviceId}
      known={endpoint?.id === devices.deviceId ? endpoint : undefined}
      client={client}
      onClient={onClient}
      onClose={devices.close}
      onConfigure={() => devices.open("configure", devices.deviceId!)}
    />
  );
}

function ResolversBody({id, known, client, onClient, onClose, onConfigure}: {id: string; known?: Endpoint; client: string; onClient: (client: string) => void; onClose: () => void; onConfigure: () => void}) {
  const t = useTranslations("setup");
  const c = useTranslations("common");
  const fetched = useEndpoint(known ? undefined : id);
  const endpoint = known ?? fetched.data;
  const view = useResolverView(id, client);

  const title = endpoint ? t("resolvers.dialogTitle", {name: endpoint.name}) : t("resolvers.title");
  // The picker stays while the view of another client loads, and when that view fails: it is outside the part that swaps, so a choice is not lost
  // to its own request and a client that fails (deleted in another tab) can be replaced by another. Only an Endpoint that cannot be read hides it.
  const failed = !known && fetched.isError;
  const notReady = view.data?.ready === false;
  let body;
  if (!known && fetched.isError) body = <SectionError error={fetched.error} onRetry={() => void fetched.refetch()} />;
  else if (view.isError) body = <SectionError error={view.error} onRetry={() => void view.refetch()} />;
  else if (!view.data || (!known && !endpoint)) {
    body = (
      <div role="status" aria-label={c("loading")} className="flex flex-col gap-3">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  } else if (!view.data.ready) {
    body = <SectionEmpty icon="warning" title={t("unavailable.title")} description={t("unavailable.text")} />;
  } else {
    body = <ResolverSections view={view.data} legacyOff={endpoint ? !endpoint.legacy_dns : false} />;
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="secondary" onPress={onClose}>
            {c("close")}
          </Button>
          <PrimaryButton onPress={onConfigure} isDisabled={notReady || failed || view.isError} aria-label={t("resolvers.configureAria", {name: endpoint?.name ?? ""})}>
            <Icon name="help" className="size-4" />
            {t("resolvers.configure")}
          </PrimaryButton>
        </>
      }
    >
      <WipeScope>
        <div className="flex flex-col gap-4">
          {failed || notReady ? null : <ClientPicker endpointId={id} value={client} onChange={onClient} label={t("client.label")} />}
          {body}
        </div>
      </WipeScope>
    </DialogFrame>
  );
}
