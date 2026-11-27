import {ShellCountsProvider} from "@ctrlz/ui/shell/useShellCounts.ts";
import {notFound} from "next/navigation";
import type {ReactNode} from "react";

import {PanelShell} from "../(shell)/PanelShell.tsx";

// Spec 6.3 and 8.10. The lab pages exist only where CTRLZ_LAB is "1", and that variable is absent
// from production Compose. The shell is the tenant shell, so a lab page shows the sidebar the
// owner will live in. The group holds the virtual-lab, the feedback-lab and the token-lab of spec 6.3.
// The theme lab that was here (D17, T-485) is gone.
//
// The sidebar counters of T-113 are drawn here with fixed numbers, because P2 and P3 have not built the
// lists they count (spec question 10). A number above 999 and one with a single digit show the chip at both ends.
export const dynamic = "force-dynamic";

const LAB_SHELL_COUNTS = {profiles: 3, endpoints: 1204};

export default function LabLayout({children}: {children: ReactNode}) {
  if (process.env.CTRLZ_LAB !== "1") notFound();
  return (
    <ShellCountsProvider value={LAB_SHELL_COUNTS}>
      <PanelShell>{children}</PanelShell>
    </ShellCountsProvider>
  );
}
