import {notFound} from "next/navigation";

// Any unknown path under a valid locale lands on [locale]/not-found.tsx.
export default function CatchAll() {
  notFound();
}
