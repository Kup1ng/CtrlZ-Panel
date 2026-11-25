"use client";

import {Card} from "@heroui/react";
import {useEffect, useRef, type ReactNode} from "react";

// One step of an auth flow: the heading, a line under it, and the content. The heading is the page's
// h1 and can take the focus (`focusHeading`), for a step that has no field to focus (the passkey prompt,
// a result, a closed door), so a screen reader hears where it is. A step with a field puts the focus on
// the field instead, through the field's `autoFocus`.

export function AuthCard({
  title,
  description,
  children,
  focusHeading = false,
}: {
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  focusHeading?: boolean;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focusHeading) heading.current?.focus();
  }, [focusHeading]);

  return (
    <Card className="w-full gap-5 p-6">
      <div className="flex flex-col gap-1.5">
        <h1 ref={heading} tabIndex={-1} className="text-xl leading-7 font-semibold outline-none">
          {title}
        </h1>
        {description ? <div className="text-muted text-sm leading-6">{description}</div> : null}
      </div>
      {children}
    </Card>
  );
}
