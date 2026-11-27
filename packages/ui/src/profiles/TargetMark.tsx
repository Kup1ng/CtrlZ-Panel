"use client";

import type {Target} from "@ctrlz/api-client/hooks/services.ts";
import {Flag} from "@ctrlz/icons/Flag.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";

/** The mark of a destination: its country's flag, or a globe for Auto, Random, an address, a name and a place with no flag. Decoration; the words are beside it. */
export function TargetMark({target}: {target?: Target | null}) {
  const country = target?.kind === "location" ? target.location?.country : undefined;
  return country ? <Flag code={country} /> : <Icon name="globe" className="size-4 shrink-0" />;
}
