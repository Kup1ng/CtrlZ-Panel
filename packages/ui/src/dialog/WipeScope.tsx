"use client";

import {createContext, useContext, type ReactNode} from "react";

import {useWipeCopiedOnClose} from "./useWipeCopiedOnClose.ts";

// One clipboard wipe for a whole dialog. A secret row that mounts its own wipe empties the clipboard when the row goes away, and in a flow of
// steps (the setup wizard, the client picker of Resolvers, Back) a row goes away long before the dialog does: Next after Copy would empty the
// DoH URL before it is pasted. Inside a WipeScope the rows leave the wipe to the scope, which runs once when the dialog is gone
// (useWipeCopiedOnClose does nothing when nothing was copied). Outside one, a row keeps its own wipe, as on the account and admin screens.

const Scope = createContext(false);

export function WipeScope({children}: {children: ReactNode}) {
  useWipeCopiedOnClose();
  return <Scope.Provider value>{children}</Scope.Provider>;
}

/** True under a WipeScope: a secret row then mounts no wipe of its own. */
export const useInWipeScope = (): boolean => useContext(Scope);
