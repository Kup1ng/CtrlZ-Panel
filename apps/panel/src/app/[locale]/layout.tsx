import type {Metadata} from "next";
import type {ReactNode} from "react";

import "@ctrlz/ui/styles/globals.css";
import {RootDocument} from "@ctrlz/ui/providers/RootDocument.tsx";

export const metadata: Metadata = {
  title: {default: "Ctrl Z", template: "%s | Ctrl Z"},
};

export default async function RootLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{locale: string}>;
}) {
  const {locale} = await params;
  return (
    <RootDocument app="panel" locale={locale}>
      {children}
    </RootDocument>
  );
}
