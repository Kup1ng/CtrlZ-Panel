import {urlWith} from "../../dialog/useUrlDialog.ts";

/**
 * Takes a `?dialog=` parameter out of the address WITHOUT going back in history. A form that was opened by the
 * `+` button leaves the URL as soon as its call succeeds, and what comes next is a state-only panel with a secret
 * and a leave guard of its own. `useUrlDialog().close()` calls `history.back()` when this tab pushed the entry, and that
 * traversal arrives after the panel has mounted: the guard would take it for the admin pressing Back and ask "close
 * anyway?" over a panel that has only just opened. Replacing the entry has no traversal and leaves the same address.
 */
export function stripDialogParam(param: string): void {
  window.history.replaceState(null, "", urlWith(window.location.href, param, null));
}
