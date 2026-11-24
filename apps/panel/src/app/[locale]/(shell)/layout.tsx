import type {ReactNode} from "react";

import {PanelShell} from "./PanelShell.tsx";

export default function ShellLayout({children}: {children: ReactNode}) {
  return <PanelShell>{children}</PanelShell>;
}
