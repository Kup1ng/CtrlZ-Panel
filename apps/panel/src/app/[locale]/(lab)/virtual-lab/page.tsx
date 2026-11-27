import type {Metadata} from "next";
import {notFound} from "next/navigation";

import {VirtualLab} from "@ctrlz/ui/lab/VirtualLab.tsx";

// Spec 8.10. A thin server entry: the components live in packages/ui/src/lab because only
// `packages/ui` depends on @heroui/*, and an app that imported them would resolve a second
// instance of the Pro peers (spec 18, WP0 note).
export const dynamic = "force-dynamic";
// The title is part of the answer even when the page itself is a 404 (Next puts the metadata of the matched page into the error
// document), so it is given only where the lab is on: a production visitor must not learn that the page exists (gate-r4-10).
export function generateMetadata(): Metadata {
  return process.env.CTRLZ_LAB === "1" ? {title: "Virtual lists lab"} : {};
}

export default function VirtualLabPage() {
  if (process.env.CTRLZ_LAB !== "1") notFound();
  return <VirtualLab />;
}
