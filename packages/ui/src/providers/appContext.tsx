"use client";

import type {AppId} from "@ctrlz/i18n/namespaces.ts";
import {createContext, useContext} from "react";

// The one source of "which app is this" for everything below the root layout (wp4-r5-9). Each app's
// layout names it once, to RootDocument, and AppProviders puts it here. The shell, the gate, the bell
// and the banners read it from here: a second, optional prop with a "panel" default would let a
// forgotten prop start the panel client, refresh and channel on the admin host.

const AppContext = createContext<AppId | undefined>(undefined);

export const AppContextProvider = AppContext.Provider;

/** Throws without a provider instead of falling back to the panel: failing closed beats the panel's client on the admin host. */
export function useApp(): AppId {
  const app = useContext(AppContext);
  if (app === undefined) throw new Error("useApp needs AppProviders: the app comes from the root layout, not from a prop");
  return app;
}
