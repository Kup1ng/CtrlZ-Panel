import {AuthLayout} from "@ctrlz/ui/auth/AuthLayout.tsx";
import type {ReactNode} from "react";

// Spec 11: the same column as the panel's auth pages (a centred card, the logo above it, the language and theme corner,
// no shell). The admin host is separate (T-321) and nothing here imports a panel route. The layout's session reset
// clears what a previous sign-in left in this tab, since the login page is where a new account begins.
export default function AuthGroupLayout({children}: {children: ReactNode}) {
  return <AuthLayout>{children}</AuthLayout>;
}
