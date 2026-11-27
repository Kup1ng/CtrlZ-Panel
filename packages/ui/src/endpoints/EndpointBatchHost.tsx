"use client";

import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";

import {EditEndpointsDialog, MoveEndpointsDialog} from "./EndpointBatchDialogs.tsx";
import {EndpointDeleteDialog} from "./EndpointDeleteDialog.tsx";

// The three dialogs of the selection bar (spec p3 10, T-230). They are state of the list and not of the address: the ids of a selection
// do not belong in a URL, and a reload drops the selection with them.

export type BatchDialog = "move" | "edit" | "delete" | null;

export function EndpointBatchDialogsHost({dialog, endpoints, onClose, onDone}: {dialog: BatchDialog; endpoints: Endpoint[]; onClose: () => void; onDone: () => void}) {
  if (dialog === null || endpoints.length === 0) return null;
  if (dialog === "move") return <MoveEndpointsDialog endpoints={endpoints} onClose={onClose} onDone={onDone} />;
  if (dialog === "edit") return <EditEndpointsDialog endpoints={endpoints} onClose={onClose} onDone={onDone} />;
  return <EndpointDeleteDialog endpoints={endpoints} onClose={onClose} onDeleted={onDone} />;
}
