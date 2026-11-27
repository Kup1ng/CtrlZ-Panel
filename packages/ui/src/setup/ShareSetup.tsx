"use client";

import {Segment} from "@heroui-pro/react";
import type {ShareView} from "@ctrlz/api-client/hooks/setup.ts";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {WipeScope} from "../dialog/WipeScope.tsx";
import {ConfigureFlow} from "./ConfigureFlow.tsx";
import {ResolverSections} from "./ResolverSections.tsx";
import {SecretHoldScope} from "./SecretHold.tsx";
import type {SetupNav} from "./setupSource.ts";

// What the share page (`/s/[token]`, spec p3 7.2) shows once `openShare` has answered: the Resolvers of the Endpoint and the setup guide, the
// same components as the owner's dialogs, fed with the view that came with the link. The page has no session, so the guide offers no
// generator, no claim page and no Copy Setup Link, and the Apple profile is the one of the link itself (`POST /public/share/apple-profile`).
// The platform and the step are kept in state: the address of this page holds the link's value, which is never put in a query.
//
// `link` is the secret of the page. It goes to AppleBuilder (a request body) and nowhere else.

export function ShareSetup({link, share}: {link: string; share: ShareView}) {
  const t = useTranslations("setup");
  const [tab, setTab] = useState<"guide" | "resolvers">("guide");
  const [nav, setNav] = useState<SetupNav>({os: null, step: null});
  const source = {kind: "share", link, view: share.resolvers} as const;

  // One wipe for the page: a tab switch or a step changes the rows, and none of that should empty a clipboard before a value is pasted.
  // The guide stays mounted (hidden) while the other tab is on: its state holds an Apple profile link that is shown once, and a tab switch must not
  // drop it, or leave a call without a screen (S7-r2-2).
  return (
    <WipeScope>
      <SecretHoldScope>
        <div className="flex flex-col gap-4" data-testid="share-setup">
          <Segment aria-label={t("share.tabs")} selectedKey={tab} onSelectionChange={(key) => setTab(key === "resolvers" ? "resolvers" : "guide")} size="sm" className="self-start">
            <Segment.Item id="guide">{t("wizard.title")}</Segment.Item>
            <Segment.Item id="resolvers">{t("resolvers.title")}</Segment.Item>
          </Segment>
          <div className={tab === "guide" ? undefined : "hidden"}>
            <ConfigureFlow
              source={source}
              nav={nav}
              onNavigate={setNav}
              onSeeResolvers={() => setTab("resolvers")}
              onDone={() => setNav({os: null, step: null})}
            />
          </div>
          {tab === "resolvers" ? <ResolverSections view={share.resolvers} /> : null}
        </div>
      </SecretHoldScope>
    </WipeScope>
  );
}
