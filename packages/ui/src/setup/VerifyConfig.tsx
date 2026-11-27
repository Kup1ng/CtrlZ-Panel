"use client";

import {createContext, useContext} from "react";

// Whether the setup verification (spec p3 8.4) is offered, and where its probes may go. The value is `CTRLZ_VERIFY_ORIGIN`, read on the
// server by RootDocument and checked by `parseVerifyOrigins` (so it is up to two `https://*.verify.dns.<domain>`: the zone, and the previous
// zone while a domain transition runs, p4-nodes 10.3); the browser has no way to read the server's environment, and the policy of the page
// allows exactly these origins and no other (spec 15.3). An empty list is an installation without it, and in private CA mode (P4): the wizard then shows the manual dig and nslookup check instead.

const VerifyOriginContext = createContext<readonly string[]>([]);

export const VerifyOriginProvider = VerifyOriginContext.Provider;

export function useVerifyOrigins(): readonly string[] {
  return useContext(VerifyOriginContext);
}
