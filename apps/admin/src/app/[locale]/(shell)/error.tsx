"use client";

import {keepReset} from "@ctrlz/ui/admin/shared/restoreFocus.ts";
import {SectionError} from "@ctrlz/ui/feedback/SectionError.tsx";

// Spec 8.7. A page of the admin shell that throws while rendering lands here, inside the shell, so the
// sidebar stays and the visitor can go elsewhere. `reset` renders the segment again; keepReset gives the keyboard focus back
// once the error has left, because the Retry that held it leaves with the error (wp10-r16-2). The layout of
// [locale] is the root, so a failure there is `global-error.tsx`'s.
export default function ShellError({error, reset}: {error: Error & {digest?: string}; reset: () => void}) {
  return <SectionError error={error} onRetry={keepReset(reset)} className="p-6" />;
}
