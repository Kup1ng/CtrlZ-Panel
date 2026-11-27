import type {GeneralIconName} from "@ctrlz/icons/hugeicons.ts";

// The index of /docs (spec p3 10, Plan T-125): where a person is sent to learn how to use the product. Every destination is a page of the panel, so
// the index holds no external link by construction (a test reads the list). The guides in MDX (`content/{fa,en}/guide`) arrive with P7; each one
// becomes one more entry of a section here, with its own route, and the sections below do not change.
//
// `id` is the key of the texts in `api.docsPage.entries.<id>` (a title and a line), and of the Playwright cases.

export type GuideEntryId = "profiles" | "endpoints" | "apiDocs" | "apiTokens" | "status";
export type GuideEntry = {id: GuideEntryId; href: string; icon: GeneralIconName};
export type GuideSection = {id: "start" | "reference"; entries: GuideEntry[]};

export const GUIDE_SECTIONS: readonly GuideSection[] = [
  {
    id: "start",
    entries: [
      {id: "profiles", href: "/profiles", icon: "profiles"},
      {id: "endpoints", href: "/endpoints", icon: "endpoints"},
    ],
  },
  {
    id: "reference",
    entries: [
      {id: "apiDocs", href: "/docs/api", icon: "api"},
      {id: "apiTokens", href: "/preferences/api", icon: "key"},
      {id: "status", href: "/status", icon: "statistics"},
    ],
  },
];
