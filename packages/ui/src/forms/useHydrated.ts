"use client";

import {useSyncExternalStore} from "react";

// False in the server render and in the first client render, true once React owns the page. A submit
// button is disabled until then: before hydration a form has no handler, and a click or an Enter key would
// submit it natively, which puts what was typed (a password) in the address bar of a GET.

const noopSubscribe = () => () => undefined;

export function useHydrated(): boolean {
  return useSyncExternalStore(
    noopSubscribe,
    () => true,
    () => false,
  );
}
