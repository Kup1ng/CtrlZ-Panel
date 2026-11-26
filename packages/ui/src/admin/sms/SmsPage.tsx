"use client";

import {Tabs} from "@heroui/react";
import {PageHeader} from "../../shell/PageHeader.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {GatewaysTab} from "./GatewaysTab.tsx";
import {LimitsTab} from "./LimitsTab.tsx";
import {RoutingTab} from "./RoutingTab.tsx";
import {SmsAlerts} from "./SmsAlerts.tsx";
import {StatsTab} from "./StatsTab.tsx";
import {TemplatesTab} from "./TemplatesTab.tsx";

// Spec 13.3, T-328. The SMS service in six tabs, with the unresolved SMS alerts above them. A tab's panel mounts only while
// it is the selected one (`Tabs.Panel` does that), so the page asks for the lists of the tab in front and nothing more.
// `noop` appears only if the API lists it (dev and test), because every list here is the API's own.

const TABS = ["gateways", "routing", "templates", "limits", "stats"] as const;
type TabId = (typeof TABS)[number];

export function SmsPage() {
  const t = useTranslations("admin");
  const [tab, setTab] = useState<TabId>("gateways");

  return (
    <>
      <PageHeader icon="sms" title={t("pages.sms.title")} subtitle={t("pages.sms.subtitle")} />
      <SmsAlerts />
      <Tabs selectedKey={tab} onSelectionChange={(key) => setTab(key as TabId)} className="w-full">
        <Tabs.ListContainer className="overflow-x-auto">
          <Tabs.List aria-label={t("sms.tabs.label")}>
            {TABS.map((id) => (
              <Tabs.Tab key={id} id={id}>
                {t(`sms.tabs.${id}`)}
                <Tabs.Indicator />
              </Tabs.Tab>
            ))}
          </Tabs.List>
        </Tabs.ListContainer>
        <Tabs.Panel id="gateways" className="pt-6">
          <GatewaysTab />
        </Tabs.Panel>
        <Tabs.Panel id="routing" className="pt-6">
          <RoutingTab />
        </Tabs.Panel>
        <Tabs.Panel id="templates" className="pt-6">
          <TemplatesTab />
        </Tabs.Panel>
        <Tabs.Panel id="limits" className="pt-6">
          <LimitsTab />
        </Tabs.Panel>
        <Tabs.Panel id="stats" className="pt-6">
          <StatsTab />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
