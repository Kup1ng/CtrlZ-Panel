import {AuthLayout} from "@ctrlz/ui/auth/AuthLayout.tsx";
import type {ReactNode} from "react";

// Spec 10: the pages a visitor sees before a session, and the two a restricted or suspended session
// is sent to. A centred column, no shell. The layout mounts the language and theme corner and the
// session reset (a session that ended on its own must not leave its saved-language flag behind).
export default function AuthGroupLayout({children}: {children: ReactNode}) {
  return <AuthLayout>{children}</AuthLayout>;
}
