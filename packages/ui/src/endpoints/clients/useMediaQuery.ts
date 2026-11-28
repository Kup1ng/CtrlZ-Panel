"use client";

import {useSyncExternalStore} from "react";

// Whether a media query matches, read from the browser and followed. The server render and the first client render say `false`, so the page
// hydrates to what it was sent, and the answer arrives with the first effect.

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (notify) => {
      const list = window.matchMedia(query);
      list.addEventListener("change", notify);
      return () => list.removeEventListener("change", notify);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}
