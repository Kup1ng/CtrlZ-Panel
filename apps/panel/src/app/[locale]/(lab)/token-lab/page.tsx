import type {Metadata} from "next";
import {notFound} from "next/navigation";

import {TokenLab} from "@ctrlz/ui/lab/TokenLab.tsx";

// Spec 6.3. One sample of every row of the radius table, for apps/panel/e2e/radius.spec.ts. A thin server entry
// for the same reason as virtual-lab: the components live in packages/ui. Closed unless CTRLZ_LAB is "1".
export const dynamic = "force-dynamic";
// The title is part of the answer even when the page is a 404 (Next puts the metadata of the matched page into the error document),
// so it is given only where the lab is on, as virtual-lab does (gate-r4-10, gate-r31-4).
export function generateMetadata(): Metadata {
  return process.env.CTRLZ_LAB === "1" ? {title: "Token lab"} : {};
}

export default function TokenLabPage() {
  if (process.env.CTRLZ_LAB !== "1") notFound();
  return <TokenLab />;
}
