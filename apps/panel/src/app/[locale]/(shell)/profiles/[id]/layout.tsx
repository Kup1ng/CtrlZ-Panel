import {ProfileFrame} from "@ctrlz/ui/profiles/ProfileFrame.tsx";
import type {ReactNode} from "react";

// The frame of every page of a profile (header, switcher, tabs, lock banner, the 404 of an unknown id). The id is a path value, never a
// name; the frame asks the API for it and shows the section's 404 when it is not a profile of this tenant.
export default async function ProfileLayout({children, params}: {children: ReactNode; params: Promise<{id: string}>}) {
  const {id} = await params;
  return <ProfileFrame id={id}>{children}</ProfileFrame>;
}
