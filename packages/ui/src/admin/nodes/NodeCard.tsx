"use client";

import {Card} from "@heroui/react";
import {useId, type ReactNode} from "react";

// The box of one section of the node page and of the enrolment page: a title, a line under it, and the content. The group is named by
// its title, so a screen reader moves between the sections of a long page by name.

export function NodeCard({title, description, children, testId, className}: {title: ReactNode; description?: ReactNode; children: ReactNode; testId?: string; className?: string}) {
  const id = useId();
  return (
    <Card role="group" aria-labelledby={id} data-testid={testId} className={["gap-4 p-6", className ?? ""].join(" ").trim()}>
      <Card.Header className="flex flex-col gap-1">
        <Card.Title id={id} className="text-base">
          {title}
        </Card.Title>
        {description ? <Card.Description>{description}</Card.Description> : null}
      </Card.Header>
      <Card.Content className="flex flex-col gap-4">{children}</Card.Content>
    </Card>
  );
}

/** Label and value pairs, two columns from the small breakpoint. A value that is not there is the caller's "not reported yet". */
export function Facts({rows}: {rows: {id: string; label: ReactNode; value: ReactNode}[]}) {
  return (
    <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
      {rows.map((r) => (
        <div key={r.id} className="flex min-w-0 flex-col gap-0.5" data-testid={`fact-${r.id}`}>
          <dt className="text-muted text-xs">{r.label}</dt>
          <dd className="min-w-0 text-sm [overflow-wrap:anywhere]">{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** What a page says for a value the hub does not send yet. */
export function NotReported({text}: {text: string}) {
  return (
    <span className="text-muted" data-testid="not-reported">
      {text}
    </span>
  );
}
