import type {ReactNode} from "react";

// A section heading with room for the section's own controls at the inline end.
// The id lets the section name itself with aria-labelledby.
export function SectionTitle({id, title, children}: {id: string; title: string; children?: ReactNode}) {
  return (
    <div className="flex min-h-9 flex-wrap items-center justify-between gap-x-3 gap-y-2">
      <h2 id={id} className="text-base font-semibold">
        {title}
      </h2>
      {children ? <div className="flex items-center gap-2">{children}</div> : null}
    </div>
  );
}
