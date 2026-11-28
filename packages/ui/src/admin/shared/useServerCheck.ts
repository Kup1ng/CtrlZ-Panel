import {useQueryClient, type FetchQueryOptions, type QueryClient, type QueryKey} from "@tanstack/react-query";
import {useCallback} from "react";

// A write of the admin app has no version or If-Match, and the app's queries do not refetch while a page stays open (stale
// time 30 s, no refocus refetch, no interval, queryDefaults.ts). A form's draft can only follow the server, or flag a
// conflict, when a new server value reaches it, so on a stable connection the form would send every field it did not edit
// with the value it loaded, and another admin's emergency limit would be undone with both admins seeing "Saved" (wp10-r6-5).
//
// So a form asks the server for the value it is about to replace, with a stale time of 0, before it builds the write:
//   - The answer is the value the form last saw: the write goes ahead, and it is the newest value that is replaced.
//   - The answer differs: it has been put in the page's query, the form's draft hook has moved its baseline and
//     marked the conflicts (useServerForm, useServerDraft), and nothing is sent. The admin sees what changed and presses
//     Save again, which is then the deliberate act the conflict gate wants.
// This is a check, not a lock. The window that is left is the time between the last read and the PUT, until the API takes an
// If-Match. It is NOT only "two admins pressing Save in the same second": a write that needs the fresh TOTP window waits in a dialog
// that has no timeout, and the read must be asked again just before the repeated PUT, which is why forms call it through
// `useCheckedWrite` (wp10-r7-5) and never directly.
//
// The read goes through a query of its own, not the page's (wp10-r9-4). A fetch that fails sets `error` on the query it ran in,
// and every page of the admin app renders its section error, in place of the form, when its query has an error. Run on the page's
// key, a 503 at Save would unmount the open form with its edits (and, in Gateways, the dialog with the pasted key), and the form's
// catch block would run on a component that is gone. Run on a key of its own, the failure reaches only this call, the form
// stays, and its catch block shows the error with Retry. The page's query is written (setQueryData) only with an answer.

/** The key a check runs under: outside every key the pages read, so that no observer and no invalidation of theirs sees it. */
export function checkKey(key: QueryKey): QueryKey {
  return ["admin-write-check", ...key];
}

/**
 * True when the server still holds `seen`. `pick` reads the form's value out of the query's data, and `same` is the form's own
 * comparison (two spellings of one value are one value). A fetch that fails throws, so the form's catch block shows it with Retry:
 * a write against a value that cannot be read is not sent, and the page's own query is left as it was.
 */
export async function checkServerValue<Data, Value, Key extends QueryKey>(
  queryClient: QueryClient,
  options: FetchQueryOptions<Data, unknown, Data, Key>,
  pick: (data: Data) => Value,
  seen: Value,
  same: (a: Value, b: Value) => boolean,
): Promise<boolean> {
  // The query function does not read its key (every admin query function is a plain call), so it runs unchanged under another one.
  const latest = await queryClient.fetchQuery({...options, queryKey: checkKey(options.queryKey as QueryKey), gcTime: 0, staleTime: 0} as unknown as FetchQueryOptions<Data>);
  queryClient.setQueryData(options.queryKey as QueryKey, latest);
  return same(pick(latest), seen);
}

export function useServerCheck() {
  const queryClient = useQueryClient();
  return useCallback(
    <Data, Value, Key extends QueryKey>(
      options: FetchQueryOptions<Data, unknown, Data, Key>,
      pick: (data: Data) => Value,
      seen: Value,
      same: (a: Value, b: Value) => boolean,
    ): Promise<boolean> => checkServerValue(queryClient, options, pick, seen, same),
    [queryClient],
  );
}
