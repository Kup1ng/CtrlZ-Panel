import type {ReactNode} from "react";

import {AdminShell} from "./AdminShell.tsx";

export default function ShellLayout({children}: {children: ReactNode}) {
  return <AdminShell>{children}</AdminShell>;
}
