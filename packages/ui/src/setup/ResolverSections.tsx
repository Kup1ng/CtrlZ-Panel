"use client";

import {Accordion, Alert} from "@heroui/react";
import type {ResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {useTranslations} from "next-intl";

import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {SecretCopyNote} from "./SecretCopyNote.tsx";
import {bootstrapList, listedProtocols, stampGroups} from "./resolverModel.ts";

// WF "Endpoints", Resolvers: two collapsible sections, Legacy DNS (not encrypted) and Secure DNS (encrypted), with a Copy button on every
// value, and the DNS Stamps under their own heading. Spec p3 8.1 and Plan T-239, T-240, T-544: exactly the five protocols, the primary
// first wherever a list is given, the host name stamp before the address stamps and the sentence that says which one to take.
//
// It draws a Resolver view and nothing else, so the dialog of an Endpoint and the share page (which has no session) show the same thing.
// A value that carries the DoH token goes through the one writer of one-time secrets (TechCopyRow `secret`).

export function ResolverSections({view, legacyOff = false}: {view: ResolverView; legacyOff?: boolean}) {
  const t = useTranslations("setup");
  const protocols = listedProtocols(view);
  const stamps = stampGroups(view);
  const bootstrap = bootstrapList(view);
  const showLegacy = protocols.includes("plain") && view.legacy;
  // The rows that carry the DoH token (the URLs and the DoH stamps) are secrets: one note under the sections says what closing does to the clipboard.
  const hasSecret = (view.doh_url && (protocols.includes("doh") || protocols.includes("doh3"))) || stamps.some((g) => g.protocol === "doh");

  return (
    <>
      <Accordion allowsMultipleExpanded defaultExpandedKeys={["legacy", "secure"]} className="w-full" data-testid="resolver-sections">
        {showLegacy ? (
          <Accordion.Item id="legacy">
            <Accordion.Heading>
              <Accordion.Trigger>
                {t("resolvers.legacy.title")}
                <Accordion.Indicator />
              </Accordion.Trigger>
            </Accordion.Heading>
            <Accordion.Panel>
              <Accordion.Body className="flex flex-col gap-3">
                <p className="text-muted text-xs">{t("resolvers.legacy.hint")}</p>
                {legacyOff ? (
                  <Alert status="warning" role="status">
                    <Alert.Indicator />
                    <Alert.Content>
                      <Alert.Description>{t("resolvers.legacy.off")}</Alert.Description>
                    </Alert.Content>
                  </Alert>
                ) : null}
                <TechCopyRow label={t("resolvers.legacy.dns1")} value={view.legacy!.dns1} />
                <TechCopyRow label={t("resolvers.legacy.dns2")} value={view.legacy!.dns2} />
              </Accordion.Body>
            </Accordion.Panel>
          </Accordion.Item>
        ) : null}

        <Accordion.Item id="secure">
          <Accordion.Heading>
            <Accordion.Trigger>
              {t("resolvers.secure.title")}
              <Accordion.Indicator />
            </Accordion.Trigger>
          </Accordion.Heading>
          <Accordion.Panel>
            <Accordion.Body className="flex flex-col gap-3">
              <p className="text-muted text-xs">{t("resolvers.secure.hint")}</p>
              <TechCopyRow label={t("resolvers.resolverId")} value={view.resolver_id} />
              {protocols.includes("doh") && view.doh_url ? <TechCopyRow label={t("resolvers.rows.doh")} value={view.doh_url} secret /> : null}
              {protocols.includes("doh3") && view.doh_url ? (
                <TechCopyRow label={t("resolvers.rows.doh3")} value={view.doh_url} secret hint={t("resolvers.rows.doh3Hint")} />
              ) : null}
              {protocols.includes("dot") && view.host ? <TechCopyRow label={t("resolvers.rows.dot")} value={view.host} /> : null}
              {protocols.includes("doq") && view.host ? <TechCopyRow label={t("resolvers.rows.doq")} value={view.host} /> : null}
              {bootstrap.map((ip, index) => (
                <TechCopyRow key={ip} label={t(index === 0 ? "resolvers.bootstrap.first" : "resolvers.bootstrap.second")} value={ip} />
              ))}
            </Accordion.Body>
          </Accordion.Panel>
        </Accordion.Item>

        {stamps.length > 0 ? (
          <Accordion.Item id="stamps">
            <Accordion.Heading>
              <Accordion.Trigger>
                {t("resolvers.stamps.title")}
                <Accordion.Indicator />
              </Accordion.Trigger>
            </Accordion.Heading>
            <Accordion.Panel>
              <Accordion.Body className="flex flex-col gap-4">
                <p className="text-sm" data-testid="stamp-guide">
                  {t("resolvers.stamps.guide")}
                </p>
                {stamps.map((group) => {
                  const protocol = t(`resolvers.protocols.${group.protocol}`);
                  // The DoH stamp carries the token in its path, like the URL: a secret. DoT and DoQ stamps hold only the host.
                  const secret = group.protocol === "doh";
                  return (
                    <section key={group.protocol} aria-label={protocol} className="flex flex-col gap-3" data-testid={`stamps-${group.protocol}`}>
                      <h4 className="text-sm font-medium">{protocol}</h4>
                      <TechCopyRow label={t("resolvers.stamps.hostname", {protocol})} value={group.hostname} secret={secret} wrapLabel />
                      {group.addresses.length > 0 ? (
                        <>
                          <p className="text-muted text-xs">{t("resolvers.stamps.several")}</p>
                          {group.addresses.map((a) => (
                            <TechCopyRow key={a.ip} label={t("resolvers.stamps.address", {protocol, ip: a.ip})} value={a.stamp} secret={secret} wrapLabel />
                          ))}
                        </>
                      ) : null}
                    </section>
                  );
                })}
              </Accordion.Body>
            </Accordion.Panel>
          </Accordion.Item>
        ) : null}
      </Accordion>
      {hasSecret ? <SecretCopyNote /> : null}
    </>
  );
}
