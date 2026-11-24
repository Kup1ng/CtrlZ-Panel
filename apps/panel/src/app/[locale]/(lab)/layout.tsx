import {notFound} from "next/navigation";
import type {ReactNode} from "react";

import {PanelShell} from "../(shell)/PanelShell.tsx";

// Spec 6.3 and 8.10. The lab pages exist only where CTRLZ_LAB is "1", and that variable is absent
// from production Compose. The shell is the tenant shell, so a lab page shows the sidebar the
// owner will live in. The group holds the virtual-lab, the feedback-lab and the token-lab of spec 6.3.
// The theme lab that was here (D17, T-485) is gone.
export const dynamic = "force-dynamic";

export default function LabLayout({children}: {children: ReactNode}) {
  if (process.env.CTRLZ_LAB !== "1") notFound();
  return <PanelShell>{children}</PanelShell>;
}
