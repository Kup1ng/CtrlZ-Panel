"use client";

import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useState} from "react";

import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {ConfigureDialog} from "./ConfigureDialog.tsx";
import {ResolversDialog} from "./ResolversDialog.tsx";

/**
 * The two Endpoint dialogs of the setup (`deviceDialog=resolvers` and `deviceDialog=configure`, spec p3 10). EndpointDialogs mounts this once,
 * on the list and in the frame of an Endpoint, with the open Endpoint when it knows it (the dialogs fetch it by `deviceId` otherwise).
 *
 * The client chosen in one of them is kept here for the other: Help Me Configure from Resolvers is about the same client (S7-r2-6). It belongs to
 * one Endpoint and goes when neither dialog is open.
 */
export function SetupDialogs({endpoint}: {endpoint?: Endpoint}) {
  const devices = useDeviceDialog();
  const [chosen, setChosen] = useState<{id: string; client: string} | null>(null);
  const open = devices.dialog === "resolvers" || devices.dialog === "configure";
  // Reset while rendering (React's own pattern for state that follows a prop): an effect would draw one frame with the old client.
  if (!open && chosen !== null) setChosen(null);
  const client = open && chosen !== null && chosen.id === devices.deviceId ? chosen.client : "";
  const onClient = (next: string) => setChosen({id: devices.deviceId ?? "", client: next});
  return (
    <>
      <ResolversDialog endpoint={endpoint} client={client} onClient={onClient} />
      <ConfigureDialog endpoint={endpoint} client={client} onClient={onClient} />
    </>
  );
}
