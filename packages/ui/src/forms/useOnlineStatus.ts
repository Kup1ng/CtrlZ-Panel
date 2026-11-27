"use client";

import {useSyncExternalStore} from "react";

// `navigator.onLine` is only a hint (it says "connected to a network", not "the server answers"), so
// it disables the submit button and shows the notice, and nothing else depends on it. The server
// snapshot is `true`, so the first paint never shows an offline notice that the browser then removes.

function subscribe(onChange: () => void) {
  window.addEventListener("online", onChange);
  window.addEventListener("offline", onChange);
  return () => {
    window.removeEventListener("online", onChange);
    window.removeEventListener("offline", onChange);
  };
}

export function useOnlineStatus(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => navigator.onLine,
    () => true,
  );
}
