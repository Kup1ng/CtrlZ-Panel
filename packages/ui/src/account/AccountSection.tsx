import type {ReactNode} from "react";

// The three sections of the page (WF "Preferences": Details, Passkeys, Options): a title in sentence
// case (DESIGN.md: no all-caps) over full-width rows. The gap between rows is the one the lists use
// (spec 8.10).

export function AccountSection({id, title, children, busy = false}: {id: string; title: string; children: ReactNode; busy?: boolean}) {
  return (
    // data-row-id: a security notice links to `#passkeys` (the section is the place that undoes a passkey); useRowFragment moves to it
    // and puts the focus on the title below, the one place of a section that takes it.
    <section aria-labelledby={`${id}-title`} data-row-id={id} aria-busy={busy || undefined} className="flex flex-col gap-3">
      {/* tabIndex -1: not a stop of the Tab order, but a place to put the focus when what had it was removed (wp9-r1-5). */}
      <h2 id={`${id}-title`} tabIndex={-1} className="text-foreground text-base font-semibold outline-none">
        {title}
      </h2>
      <div className="flex flex-col gap-2">{children}</div>
    </section>
  );
}

/**
 * A row that is a setting, not an editor: what it is on the start side, the control on the end side
 * (design taste: switches and segments sit at the trailing end). Below sm the control drops under the
 * text, so a Segment never squeezes the label.
 */
export function SettingRow({
  label,
  description,
  control,
  children,
  id,
}: {
  label: ReactNode;
  description?: ReactNode;
  control?: ReactNode;
  /** Full-width content under the line (a combo box and its tags). */
  children?: ReactNode;
  id?: string;
}) {
  return (
    <div data-row-id={id} className="bg-surface flex flex-col gap-3 rounded-(--radius-box) px-4 py-3 shadow-surface">
      <div className="flex min-h-10 flex-wrap items-center justify-between gap-x-4 gap-y-2">
        <div className="flex min-w-0 flex-1 basis-48 flex-col gap-0.5">
          <h3 className="text-foreground text-sm font-medium">{label}</h3>
          {description ? <p className="text-muted text-xs">{description}</p> : null}
        </div>
        {control ? <div className="flex shrink-0 items-center">{control}</div> : null}
      </div>
      {children}
    </div>
  );
}
