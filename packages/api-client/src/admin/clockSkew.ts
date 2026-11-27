import {skipToken, useQuery, type QueryClient} from "@tanstack/react-query";

// Spec 7.10 (T-088). The panel host and the nodes keep one time with chrony; the admin's own browser is the one clock
// nobody keeps. A browser clock that is minutes off makes the fresh-TOTP window (admin/fresh.ts) read as closed or
// open when it is not, and makes every time on the page wrong, so at login the shell compares the `Date` header of
// `GET /me` with its own clock and says so above 30 seconds. Nothing is changed on the server: this is a warning.

/** Above this the shell warns (spec 7.10). The server's `Date` has one-second resolution, which is far below it. */
export const CLOCK_SKEW_LIMIT_MS = 30_000;

export const adminClockKeys = {skew: ["admin", "clock-skew"] as const};

/**
 * How far the server is ahead of this browser, in ms (negative: behind), or undefined when the answer has no usable
 * `Date`. The browser time is the middle of the request, because the header was written somewhere between the two ends:
 * a slow network does not read as a wrong clock. A header that is not a date says nothing rather than something wrong.
 */
export function serverClockOffset(dateHeader: string | null | undefined, sentAt: number, receivedAt: number): number | undefined {
  if (!dateHeader) return undefined;
  const server = Date.parse(dateHeader);
  if (!Number.isFinite(server)) return undefined;
  return server - (sentAt + receivedAt) / 2;
}

export function skewIsWarning(offsetMs: number | undefined): boolean {
  return offsetMs !== undefined && Math.abs(offsetMs) > CLOCK_SKEW_LIMIT_MS;
}

/** Written by the `/me` fetch (session.ts), read by the shell's banners. The latest answer wins, so a fixed clock clears the warning. */
export function recordServerClock(queryClient: QueryClient, response: Pick<Response, "headers">, sentAt: number, receivedAt: number): void {
  const offset = serverClockOffset(response.headers.get("Date"), sentAt, receivedAt);
  queryClient.setQueryData<number | null>(adminClockKeys.skew, offset ?? null);
}

/** The offset in ms of the latest `/me`, or undefined before there is one. Nothing is fetched here: `/me` writes it. */
export function useAdminClockOffset(): number | undefined {
  const {data} = useQuery<number | null>({queryKey: adminClockKeys.skew, queryFn: skipToken, staleTime: Infinity});
  return data ?? undefined;
}
