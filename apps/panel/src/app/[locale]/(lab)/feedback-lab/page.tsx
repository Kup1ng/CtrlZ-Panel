import type {Metadata} from "next";
import {notFound} from "next/navigation";

import {FeedbackShowcase} from "@ctrlz/ui/data/FeedbackShowcase.tsx";

// WP7's samples of the feedback states, the URL dialog and the list rows, for the tests of
// apps/panel/e2e/dialogs.spec.ts, states.spec.ts and rows.spec.ts. A thin server entry for the
// same reason as virtual-lab: components live in packages/ui. Closed unless CTRLZ_LAB is "1".
export const dynamic = "force-dynamic";
// The title is part of the answer even when the page itself is a 404 (Next puts the metadata of the matched page into the error
// document), so it is given only where the lab is on: a production visitor must not learn that the page exists (gate-r4-10).
export function generateMetadata(): Metadata {
  return process.env.CTRLZ_LAB === "1" ? {title: "Feedback lab"} : {};
}

export default function FeedbackLabPage() {
  if (process.env.CTRLZ_LAB !== "1") notFound();
  return <FeedbackShowcase />;
}
