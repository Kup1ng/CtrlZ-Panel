"use client";

import type {AppId} from "@ctrlz/i18n/namespaces.ts";
import {createContext, useContext} from "react";

import {useApp} from "../providers/appContext.tsx";

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

/**
 * Which API the shell talks to. The two share one shell but not one client: admin has no refresh, no bell
 * and no feeds (spec 13). It is the app of AppProviders, never a prop of the shell, and there is no panel
 * default: a missing provider throws (wp4-r5-9).
 */
export function useShellApp(): AppId {
  return useApp();
}
