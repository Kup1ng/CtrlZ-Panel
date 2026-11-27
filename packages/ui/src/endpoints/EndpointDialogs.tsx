"use client";

// The URL dialogs of Endpoints: deviceDialog=add|edit|delete|resolvers|configure|client with deviceId, endpointGroupDialog, setupOs, step
// (spec p3 10, 8.3), parsed with parseDeviceDialog and the others of dialog/dialogValues.ts.
//
// Add, edit, delete and the groups are drawn here; `resolvers` and `configure` by SetupDialogs (setup/), `client` by the Clients page.

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {useEndpoint, type Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {usePathname, useRouter} from "@ctrlz/i18n/navigation.ts";
import {useTranslations} from "next-intl";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {SectionError} from "../feedback/SectionError.tsx";
import {EndpointDeleteDialog} from "./EndpointDeleteDialog.tsx";
import {EndpointFormDialog} from "./EndpointFormDialog.tsx";
import {EndpointGroupDialogs} from "./EndpointGroupDialogs.tsx";
import {endpointIdOf, endpointsHref} from "./endpointRoutes.ts";
import {SetupDialogs} from "../setup/SetupDialogs.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

/**
 * Mounted by the list page (no props), by EndpointFrame (`endpoint`, the open Endpoint) and by ProfileFrame (`defaultProfileId`, the open
 * profile: the add step starts on it, so Add Endpoint in a profile's header does not ask for the profile again, T-137). Only one frame is
 * on a page, so the dialog is drawn once. The lock password dialog is LockPasswordsDialog of locks/LockDialogs.tsx.
 */
export function EndpointDialogs({endpoint, defaultProfileId}: {endpoint?: Endpoint; defaultProfileId?: string}) {
  const devices = useDeviceDialog();
  const router = useRouter();
  const pathname = usePathname();
  const dialog = devices.dialog;
  const wantsEndpoint = dialog !== null && dialog !== "add";
  // The frame already holds the Endpoint it is about; any other (the list's Edit, a link) is read by its id.
  const own = endpoint && endpoint.id === devices.deviceId ? endpoint : undefined;
  const query = useEndpoint(wantsEndpoint && !own ? (devices.deviceId ?? undefined) : undefined);
  const target = own ?? query.data;

  return (
    <>
      <EndpointGroupDialogs />
      {/* S7: Resolvers and Help Me Configure (deviceDialog=resolvers|configure). */}
      <SetupDialogs endpoint={endpoint} />
      {dialog === "add" ? <EndpointFormDialog key="add" mode={{kind: "add", ...(defaultProfileId ? {defaultProfileId} : {})}} onClose={devices.close} /> : null}
      {dialog === "edit" && target ? <EndpointFormDialog key={`edit-${target.id}`} mode={{kind: "edit", endpoint: target}} onClose={devices.close} /> : null}
      {dialog === "delete" && target ? (
        <EndpointDeleteDialog
          key={`delete-${target.id}`}
          endpoints={[target]}
          onClose={devices.close}
          // The page of an Endpoint that is gone has nothing to show: leave it for the list.
          onDeleted={() => {
            if (endpointIdOf(pathname) !== target.id) return false;
            router.replace(endpointsHref);
            return true;
          }}
        />
      ) : null}
      {wantsEndpoint && !target && query.isError ? <MissingEndpoint error={query.error} onRetry={() => void query.refetch()} onClose={devices.close} /> : null}
    </>
  );
}

/**
 * A dialog for an id that is not the tenant's Endpoint (a stale link): it says so and closes. The text never says which of the two it was.
 * Only a 404 says that. A read that failed any other way (5xx, a timeout, offline) says it failed and offers Retry, so a valid link is not
 * taken for a deleted Endpoint (S5-r3-4).
 */
function MissingEndpoint({error, onRetry, onClose}: {error: unknown; onRetry: () => void; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      title={t("dialogs.missing.title")}
      footer={
        <PrimaryButton onPress={onClose}>
          {c("close")}
        </PrimaryButton>
      }
    >
      {hasCode(error, "not_found") ? <p className="text-sm">{t("dialogs.missing.text")}</p> : <SectionError error={error} onRetry={onRetry} />}
    </DialogFrame>
  );
}
