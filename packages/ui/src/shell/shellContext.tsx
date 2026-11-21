"use client";

import {createContext, useContext} from "react";

// What the sidebar and the mobile bar can ask the shell to open. The shell
// mounts each dialog once; the sidebar is rendered twice (desktop and the
// mobile sheet), so a dialog owned by it would exist twice.

export type ShellUi = {
  openLogout: () => void;
  openPalette: () => void;
};

const noop = () => undefined;
export const ShellUiContext = createContext<ShellUi>({openLogout: noop, openPalette: noop});

export function useShellUi(): ShellUi {
  return useContext(ShellUiContext);
}
