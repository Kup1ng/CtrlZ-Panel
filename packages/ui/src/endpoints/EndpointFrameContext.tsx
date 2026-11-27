"use client";

import type {Endpoint} from "@ctrlz/api-client/hooks/endpoints.ts";
import {createContext, useContext} from "react";

// What every screen under `/endpoints/[id]` gets from the frame (EndpointFrame.tsx): the Endpoint, already loaded, with its 404 shown by
// the frame. `held` is `admin_hold` (D34): the Endpoint cannot be deleted, and its screens say so.

export type EndpointFrameValue = {
  endpoint: Endpoint;
  held: boolean;
};

export const EndpointFrameContext = createContext<EndpointFrameValue | null>(null);

export function useEndpointFrame(): EndpointFrameValue {
  const value = useContext(EndpointFrameContext);
  if (!value) throw new Error("useEndpointFrame needs the EndpointFrame of /endpoints/[id]");
  return value;
}
