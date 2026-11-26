"use client";

import {toast} from "@heroui/react";
import type {FetchQueryOptions, QueryKey} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useRef, useState} from "react";

import {useFreshRecoverable} from "../../auth/FreshTotpDialog.tsx";
import {focusedElement, rememberFocus, restoreFocusAfter, type FocusOrigin} from "./restoreFocus.ts";
import {useServerCheck} from "./useServerCheck.ts";

// The one way an admin form writes a value that another admin could have changed (wp10-r6-5, wp10-r7-2, wp10-r7-5).
//
//   const {write, pending} = useCheckedWrite();
//   if (!(await write({options, pick, seen, same}, () => save.mutateAsync(body)))) return;   // false: the value moved
//
// Two rules live here so that no form can forget one of them:
//
// 1. The read is part of the call that is repeated. A write that needs the fresh TOTP window answers `totp_fresh_required`,
//    the dialog opens, and the same call runs again when the admin has typed the code, which can be minutes later (the
//    dialog has no timeout). A read made once before the first try says nothing about the server at that later moment, so
//    another admin's change made while the dialog was open would be overwritten with both admins seeing "Saved" (wp10-r7-5).
//    So the read is inside the closure `run` repeats: it is asked again just before the repeated write, and a value that
//    moved stops the repeat. The only window left is the time between that last read and the PUT, until the API takes an
//    If-Match (api_requests).
// 2. The whole write is one pending state: the read, the dialog and the PUT. The fields and the button follow it
//    (`pending`), not `save.isPending`, which is still false while the read is in flight and while the dialog is open.
//    An edit typed in that time would be sent by nobody and then cleared by `saved()` as if it had been written
//    (wp10-r7-2). The form's `saved(sent)` takes the value that was sent, and the fields cannot change while it runs.

// 3. The focus comes back (wp10-r8-1). An admin submits with Enter in a field, so the field that holds the focus is disabled by
//    the pending state, the browser drops the focus to <body>, and React Aria cannot hand it back to a disabled field when the
//    fresh-code dialog closes. Nothing refocused it once the write ended, and the next Tab started at the skip link. So the
//    element that had the focus is remembered when the write starts and, once the write is over and the fields are enabled
//    again, given the focus back if it is still lost (restoreFocusLater leaves a focus that is somewhere else alone). The
//    alternative, not disabling the focused field, would still let an edit through while the write runs.
//    The control that had the focus can also be gone when the write ends: the Confirm of a draft block that closes on success, or a
//    Retry whose error cleared when the write started (wp10-r9-1). So the containers it sat in are remembered with it, and the
//    focus goes to the first field of the nearest one that is still in the page.

/** Thrown inside the repeated call when the server's value is no longer the one the admin saw. Never reaches a form. */
class StaleServerValue extends Error {
  constructor() {
    super("The server value moved while the admin was deciding.");
    this.name = "StaleServerValue";
  }
}

export type WriteGuard<Data, Value, Key extends QueryKey> = {
  /** The query that holds the value the write replaces. */
  options: FetchQueryOptions<Data, unknown, Data, Key>;
  /** Reads the form's value out of that query's data. */
  pick: (data: Data) => Value;
  /** The value the form last showed. */
  seen: Value;
  /** The form's own comparison: two spellings of one value are one value. */
  same: (a: Value, b: Value) => boolean;
};

export function useCheckedWrite() {
  const t = useTranslations("admin");
  const run = useFreshRecoverable();
  const check = useServerCheck();
  const [pending, setPending] = useState(false);
  const origin = useRef<FocusOrigin | null>(null);

  // After the render that enables the fields again, so the element can take the focus.
  useEffect(() => {
    if (pending) return;
    const remembered = origin.current;
    origin.current = null;
    restoreFocusAfter(remembered);
  }, [pending]);

  /**
   * Reads the server (when there is a guard), runs `call`, and repeats both after the fresh-TOTP dialog. `true` when `call` ran to the end. `false`
   * when the server's value had moved: nothing was sent, the fetch has put the new value in the query (so the form's draft
   * hook marks its conflicts) and the admin was told. Any other failure is thrown for the form to show.
   */
  const write = useCallback(
    async <Data, Value, Key extends QueryKey>(guard: WriteGuard<Data, Value, Key> | null, call: () => Promise<unknown>): Promise<boolean> => {
      origin.current = rememberFocus(focusedElement());
      setPending(true);
      try {
        await run(async () => {
          // No guard: a write of something no other admin edits (a credential is write-only, a test send changes nothing).
          if (guard && !(await check(guard.options, guard.pick, guard.seen, guard.same))) throw new StaleServerValue();
          return call();
        });
        return true;
      } catch (error) {
        if (!(error instanceof StaleServerValue)) throw error;
        toast.info(t("conflict.refreshed"));
        return false;
      } finally {
        setPending(false);
      }
    },
    [run, check, t],
  );

  /**
   * A write that needs the fresh TOTP window and has no server value to compare (a create, a revoke, an acknowledgement; every
   * state-changing admin call is `admin-fresh`, AUTH 10.5): the dialog opens on `totp_fresh_required` and the call is repeated once.
   * Returns what `call` returns. The same pending state and the same focus hand-back as `write`, so no form needs `useFreshRecoverable` itself (gate-r32-3).
   */
  const send = useCallback(
    async <T,>(call: () => Promise<T>): Promise<T> => {
      origin.current = rememberFocus(focusedElement());
      setPending(true);
      try {
        return await run(call);
      } finally {
        setPending(false);
      }
    },
    [run],
  );

  return {write, send, pending};
}
