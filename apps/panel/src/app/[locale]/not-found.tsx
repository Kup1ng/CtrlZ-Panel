import {PANEL_SESSION_COOKIES} from "@ctrlz/ui/proxy/prefixes.ts";
import {NotFoundView} from "@ctrlz/ui/shell/NotFoundView.tsx";
import {cookies} from "next/headers";

import {PanelShell} from "./(shell)/PanelShell.tsx";

// T-121. Inside the shell for a visitor who has a session cookie, alone
// otherwise. The cookie is a convenience here as in the proxy: the API decides
// what the visitor may see, and a 404 shows nothing of the account.
export default async function NotFound() {
  const store = await cookies();
  const hasSession = PANEL_SESSION_COOKIES.some((name) => (store.get(name)?.value ?? "") !== "");
  if (!hasSession) return <NotFoundView standalone />;
  return (
    <PanelShell>
      <NotFoundView />
    </PanelShell>
  );
}
