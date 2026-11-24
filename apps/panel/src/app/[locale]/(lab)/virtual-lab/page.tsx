import type {Metadata} from "next";
import {notFound} from "next/navigation";

import {VirtualLab} from "@ctrlz/ui/lab/VirtualLab.tsx";

// Spec 8.10. A thin server entry: the components live in packages/ui/src/lab because only
// `packages/ui` depends on @heroui/*, and an app that imported them would resolve a second
// instance of the Pro peers (spec 18, WP0 note).
export const dynamic = "force-dynamic";
export const metadata: Metadata = {title: "Virtual lists lab"};

export default function VirtualLabPage() {
  if (process.env.CTRLZ_LAB !== "1") notFound();
  return <VirtualLab />;
}
