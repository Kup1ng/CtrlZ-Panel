"use client";

import {useEffect, useRef} from "react";

import {DIALOG_SELECTOR_BESIDE_NAV_SHEET} from "./dialogSelector.ts";

// Shortcuts bound by physical key, `event.code`, and not by the character. On a
// Persian layout the B key types "ذ", so a handler that reads `event.key` never
// fires there. The Sidebar's own mod+b parser is unconfirmed on this point
// (spec 8.3); see shell.spec.ts. When it is not enough, AppShell passes
// toggleShortcut={false} and the toggle comes through here.

export type ShellShortcutHandlers = {
  /** mod+b: collapse or open the sidebar. Leave undefined to let the Sidebar's own shortcut work. */
  toggleSidebar?: () => void;
  /** mod+k: the jump palette. */
  openPalette?: () => void;
};

// A dialog is open: the page behind it is inert, and the palette's pick and the mobile nav sheet's links are router pushes that no leave guard
// sees, so they would drop what the dialog holds (recovery codes, a one-time password or a call in flight, gate-r33-7, gate-r34-5). The key is
// still taken, so the browser's own Ctrl+K does not move focus out of the dialog. A toast is not a dialog, and neither is the nav sheet that
// Ctrl+B itself opened, which Ctrl+B has to be able to close again (see dialogSelector.ts, gate-r35-1).
function modalOpen(): boolean {
  return document.querySelector(DIALOG_SELECTOR_BESIDE_NAV_SHEET) !== null;
}

function isMod(e: KeyboardEvent): boolean {
  return (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey;
}

export function useShellShortcuts(handlers: ShellShortcutHandlers) {
  // The listener is attached once and reads the latest handlers.
  const ref = useRef(handlers);
  useEffect(() => {
    ref.current = handlers;
  });

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.defaultPrevented || e.isComposing || !isMod(e)) return;
      if (e.code === "KeyB" && ref.current.toggleSidebar) {
        e.preventDefault();
        // Below 48rem this opens the mobile nav sheet over the dialog, and a link there leaves the page with no confirm (gate-r34-5).
        if (!modalOpen()) ref.current.toggleSidebar();
      } else if (e.code === "KeyK" && ref.current.openPalette) {
        e.preventDefault();
        if (!modalOpen()) ref.current.openPalette();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);
}
