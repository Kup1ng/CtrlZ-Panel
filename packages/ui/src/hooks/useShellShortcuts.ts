"use client";

import {useEffect, useRef} from "react";

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
        ref.current.toggleSidebar();
      } else if (e.code === "KeyK" && ref.current.openPalette) {
        e.preventDefault();
        ref.current.openPalette();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);
}
