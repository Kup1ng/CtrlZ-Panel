"use client";

import {useSearchParams} from "next/navigation";
import {useCallback} from "react";

import {parseDeviceDialog, parseDeviceId, type DeviceDialog} from "./dialogValues.ts";
import {readPushed, urlWithMany, writePushed} from "./useUrlDialog.ts";

// The Endpoint dialogs are two parameters: `deviceDialog=<kind>` and `deviceId=<id>` (FE 9, spec p3 10). They open and close TOGETHER, in
// one history entry, so a Back closes the dialog and leaves no `deviceId` behind, and a direct link to `?deviceDialog=edit&deviceId=<id>`
// opens it with its Endpoint. `useUrlDialog` is for one parameter; this is for the pair.
//
// Both values are parsed (dialogValues.ts): a `deviceDialog` that is not one of the six, or one that needs an Endpoint with no valid
// `deviceId`, is `null`, and the dialog stays shut.

export type DeviceDialogState = {
  /** The dialog to show, or `null` (nothing asked, an unknown name, or one that needs an Endpoint and has none). */
  dialog: DeviceDialog | null;
  deviceId: string | null;
  isOpen: boolean;
  /** Opens `dialog` for the Endpoint `id` (not needed for `add`). Opening one that is open replaces it, with no new history entry. */
  open: (dialog: DeviceDialog, id?: string) => void;
  /** Back if this tab pushed the entry, so the person stays where they were; otherwise removes both parameters. */
  close: () => void;
};

export function useDeviceDialog(): DeviceDialogState {
  const params = useSearchParams();
  const dialog = parseDeviceDialog(params.get("deviceDialog"));
  const deviceId = parseDeviceId(params.get("deviceId"));
  const usable = dialog !== null && (dialog === "add" || deviceId !== null);

  const open = useCallback((next: DeviceDialog, id?: string) => {
    const target = urlWithMany(window.location.href, {deviceDialog: next, deviceId: id ?? null});
    if (new URL(window.location.href).searchParams.get("deviceDialog")) {
      window.history.replaceState(null, "", target);
      return;
    }
    window.history.pushState(null, "", target);
    writePushed("deviceDialog", true);
  }, []);

  const close = useCallback(() => {
    if (readPushed("deviceDialog")) {
      writePushed("deviceDialog", false);
      window.history.back();
    } else {
      window.history.replaceState(null, "", urlWithMany(window.location.href, {deviceDialog: null, deviceId: null}));
    }
  }, []);

  return {dialog: usable ? dialog : null, deviceId, isOpen: usable, open, close};
}
