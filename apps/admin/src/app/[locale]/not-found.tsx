import {ADMIN_SESSION_COOKIES} from "@ctrlz/ui/proxy/prefixes.ts";
import {NotFoundView} from "@ctrlz/ui/shell/NotFoundView.tsx";
import {cookies} from "next/headers";

import {AdminShell} from "./(shell)/AdminShell.tsx";

// T-121. Inside the shell for a visitor who has an admin session cookie, alone otherwise. The cookie is a convenience
// here as in the proxy: the API decides what the visitor may see, and a 404 shows nothing of the account. The admin
// 404 is also the first page of this app that renders the root document without a session, so it is what the matrix
// harness can load (spec 17.1).
export default async function NotFound() {
  const store = await cookies();
  const hasSession = ADMIN_SESSION_COOKIES.some((name) => (store.get(name)?.value ?? "") !== "");
  if (!hasSession) return <NotFoundView standalone />;
  return (
    <AdminShell>
      <NotFoundView />
    </AdminShell>
  );
}
