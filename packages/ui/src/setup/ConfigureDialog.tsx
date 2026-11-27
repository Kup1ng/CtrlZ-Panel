"use client";

import {Skeleton} from "@heroui/react";
import {useEndpoint, type Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {useTranslations} from "next-intl";
import {useSearchParams} from "next/navigation";
import {useCallback, useMemo, useRef} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {DialogLockProvider, useDialogLockState} from "../dialog/DialogLock.tsx";
import {WipeScope} from "../dialog/WipeScope.tsx";
import {parseSetupOs, parseStep} from "../dialog/dialogValues.ts";
import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {LEAVE_GUARD_MARK} from "../dialog/useLeaveGuard.ts";
import {urlWithMany} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {ClientPicker} from "./ClientPicker.tsx";
import {ConfigureFlow} from "./ConfigureFlow.tsx";
import {parseSetupNav, setupOsValue} from "./platforms.ts";
import {SecretHoldScope, useSecretHold} from "./SecretHold.tsx";
import type {SetupNav} from "./setupSource.ts";

// `deviceDialog=configure&deviceId=<id>[&setupOs=<platform>[&step=<n>]]` (spec p3 8.3, 10, T-241 to T-243). The dialog is the frame; the
// flow in it is ConfigureFlow, which the share page uses too. The platform and the step live in the address, written with a replace so
// the steps of one wizard are one history entry: Back leaves the dialog, it does not walk the steps backwards.
//
// The client is the one chosen in Resolvers (SetupDialogs keeps it for both dialogs) and can be changed at the top, outside the part that swaps while
// the view of another client loads. The values of a client carry its label (`<resolver>-<client>.<zone>`), so every value, generator and profile in
// the flow is asked with it; a device set up with the Endpoint's own values would be filtered by the base profile, not the client's (S7-r2-6). It is
// state and not an address parameter: it is not one of the closed set of dialog parameters (FE 9), and a reload falls back to the Endpoint itself,
// with the picker still there to choose again.

export function ConfigureDialog({endpoint, client = "", onClient = () => {}}: {endpoint?: Endpoint; client?: string; onClient?: (client: string) => void}) {
  const devices = useDeviceDialog();
  if (devices.dialog !== "configure" || !devices.deviceId) return null;
  return <ConfigureBody id={devices.deviceId} known={endpoint?.id === devices.deviceId ? endpoint : undefined} client={client} onClient={onClient} />;
}

/** The picker of the dialog. It is held while a link is made or shown: a change of client reloads the flow and would take that link off the screen. */
function ClientBar({endpointId, client, onClient}: {endpointId: string; client: string; onClient: (client: string) => void}) {
  const t = useTranslations("setup");
  const hold = useSecretHold();
  return <ClientPicker endpointId={endpointId} value={client} onChange={onClient} label={t("client.label")} isDisabled={hold.pending || hold.shown} />;
}

function ConfigureBody({id, known, client, onClient}: {id: string; known?: Endpoint; client: string; onClient: (client: string) => void}) {
  const t = useTranslations("setup");
  const devices = useDeviceDialog();
  const params = useSearchParams();
  const fetched = useEndpoint(known ? undefined : id);
  const endpoint = known ?? fetched.data;
  const view = useResolverView(id, client);
  const lock = useDialogLockState();

  const parsed = parseSetupNav(parseSetupOs(params.get("setupOs")));
  const platform = parsed?.platform;
  const version = parsed?.version ?? null;
  const nav = useMemo<SetupNav>(() => ({os: platform?.id ?? null, step: platform ? parseStep(params.get("step")) : null, version}), [platform, version, params]);

  const write = useCallback((next: SetupNav) => {
    // The leave guard of the flow marks its own history entry in the state, and this rewrite must not take the mark away. Only the mark is passed on:
    // Next copies its own markers into the state it is given, and one it finds already there makes it skip reading the new address.
    const mark = (window.history.state as Record<string, unknown> | null)?.[LEAVE_GUARD_MARK];
    window.history.replaceState(mark === undefined ? null : {[LEAVE_GUARD_MARK]: mark}, "", urlWithMany(window.location.href, {setupOs: setupOsValue(next.os, next.version), step: next.step === null ? null : String(next.step)}));
  }, []);
  const clear = useCallback(() => write({os: null, step: null}), [write]);
  const close = useCallback(() => {
    clear();
    devices.close();
  }, [clear, devices]);

  // The frame's X and Escape go through the flow when it is mounted, because it owns the guard of a shown link (S7-r3-2).
  const closeRef = useRef<(() => void) | null>(null);
  const requestClose = useCallback(() => (closeRef.current ?? close)(), [close]);

  let body;
  if (!known && fetched.isError) body = <SectionError error={fetched.error} onRetry={() => void fetched.refetch()} />;
  else if (view.isError) body = <SectionError error={view.error} onRetry={() => void view.refetch()} />;
  else if (!view.data || !endpoint) {
    body = (
      <div role="status" aria-label={t("wizard.loading")} className="flex flex-col gap-3">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    );
  } else if (!view.data.ready) {
    body = <SectionEmpty icon="warning" title={t("unavailable.title")} description={t("unavailable.text")} />;
  } else {
    body = (
      <ConfigureFlow
        source={{kind: "endpoint", endpoint, view: view.data}}
        nav={nav}
        onNavigate={write}
        onSeeResolvers={() => {
          clear();
          devices.open("resolvers", id);
        }}
        onDone={close}
        client={client}
        closeRef={closeRef}
      />
    );
  }

  // The client is named in the title, so nothing about the values on screen is left to a reader's guess. The label is isolated for the bidi algorithm.
  const title = !endpoint
    ? t("wizard.title")
    : client
      ? t("configure.dialogTitleClient", {name: endpoint.name, client: `\u2068${client}\u2069`})
      : t("configure.dialogTitle", {name: endpoint.name});
  // As in Resolvers: the picker stays while the view of another client loads, and when that view fails, so a client that fails can be replaced.
  const hidePicker = (!known && fetched.isError) || view.data?.ready === false;

  return (
    <DialogFrame isOpen onClose={requestClose} isLocked={lock.locked} title={title}>
      {/* One wipe for the dialog (not one per secret row), so Next and Back do not empty the clipboard before a value is pasted. */}
      <WipeScope>
        <DialogLockProvider change={lock.change}>
          <SecretHoldScope>
            <div className="flex flex-col gap-4">
              {hidePicker ? null : <ClientBar endpointId={id} client={client} onClient={onClient} />}
              {body}
            </div>
          </SecretHoldScope>
        </DialogLockProvider>
      </WipeScope>
    </DialogFrame>
  );
}
