import {EndpointFrame} from "@ctrlz/ui/endpoints/EndpointFrame.tsx";
import type {ReactNode} from "react";

// The frame of every page of an Endpoint (header, Resolvers or Configure, Edit, tabs, the held notice, the 404 of an unknown id).
export default async function EndpointLayout({children, params}: {children: ReactNode; params: Promise<{id: string}>}) {
  const {id} = await params;
  return <EndpointFrame id={id}>{children}</EndpointFrame>;
}
