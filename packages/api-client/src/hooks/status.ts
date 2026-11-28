import {queryOptions, useQuery} from "@tanstack/react-query";

import {pollEvery} from "../activity.ts";
import {api} from "../client.ts";
import {isApiError} from "../errors.ts";

// Spec p3 10, the Status page: what P3 can honestly say about the service is whether THIS panel answers. The probe is `GET /auth/config`, which is
// public, cached by the API for 30 seconds and answered without a session, because a probe that sent the session cookie every 30 seconds would
// slide the idle limit of the session for as long as the page stayed open (AUTH 3.3). The pair's health and the analytics ingest are not here yet:
// P4 and P5 add their own rows to the page and their own routes, so the page names them as "not reported" and does not guess.
//
// A failure is the answer of the probe and not an error of the query: the query never throws, never retries, and keeps showing the last result
// while the next one is on its way.

export const statusKeys = {panel: ["status", "panel"] as const};

export type PanelProbe = {
  /** The API answered with something other than a server error. */
  reachable: boolean;
  /** A 5xx (including 503 `server_busy`): the panel is there and says it cannot serve. */
  degraded: boolean;
  /** Milliseconds from the request to the answer, rounded; for a failed probe, how long it took to fail. */
  ms: number;
  /** When the answer came (epoch ms). */
  at: number;
};

/** How long the probe waits before it says the panel is not answering (S8-r3-6). A half-open socket never fails by itself, and this is the one case the page exists to name. */
export const PROBE_TIMEOUT_MS = 10_000;

export async function probePanel(signal?: AbortSignal, timeoutMs: number = PROBE_TIMEOUT_MS): Promise<PanelProbe> {
  const started = performance.now();
  const deadline = AbortSignal.timeout(timeoutMs);
  const done = (reachable: boolean, degraded: boolean): PanelProbe => ({reachable, degraded, ms: Math.round(performance.now() - started), at: Date.now()});
  try {
    await api.GET("/auth/config", {signal: signal ? AbortSignal.any([signal, deadline]) : deadline});
    return done(true, false);
  } catch (error) {
    // The query's own abort (the page was left) is not an answer; the deadline is: it reads as a panel that does not answer.
    if (signal?.aborted) throw error;
    // An error body is an answer: the server is there. A refused connection or a timeout has no status, and a 502 or 504 is the front door saying
    // that the API behind it did not answer: neither is the panel answering.
    if (isApiError(error) && error.status !== 502 && error.status !== 504) return done(true, error.status >= 500);
    return done(false, false);
  }
}

export const panelProbeQuery = () =>
  queryOptions({
    queryKey: statusKeys.panel,
    queryFn: ({signal}) => probePanel(signal),
    retry: false,
    staleTime: 0,
    // Only while a person is at the page: a probe of an abandoned tab is noise.
    refetchInterval: pollEvery(30_000),
    refetchOnWindowFocus: false,
  });

export function usePanelProbe() {
  return useQuery(panelProbeQuery());
}
