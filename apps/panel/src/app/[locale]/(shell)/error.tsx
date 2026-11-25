"use client";

import {SectionError} from "@ctrlz/ui/feedback/SectionError.tsx";

// Spec 8.7. A page of the shell that throws while rendering lands here, inside the shell, so the
// sidebar stays and the visitor can go elsewhere. `reset` renders the segment again. The layout of
// [locale] is the root, so a failure there is `global-error.tsx`'s.
export default function ShellError({error, reset}: {error: Error & {digest?: string}; reset: () => void}) {
  return <SectionError error={error} onRetry={reset} className="p-6" />;
}
