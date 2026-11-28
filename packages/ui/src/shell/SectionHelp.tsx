"use client";

import {Button} from "@heroui/react";
import {catalogFiltersQueryOptions} from "@ctrlz/api-client/hooks/filters.ts";
import {catalogServicesQueryOptions} from "@ctrlz/api-client/hooks/services.ts";
import {useQuery} from "@tanstack/react-query";
import {useLocale, useTranslations} from "next-intl";
import type {ReactNode} from "react";

import {parseHelpTopic, type HelpTopic} from "../dialog/dialogValues.ts";
import {UrlModal} from "../dialog/UrlModal.tsx";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";

// T-120. Opens from the "?" in PageHeader, bound to `?helpPane=<key>`. Later
// phases replace the stub text in shell.help.<key>, and add keys with their page.
//
// Two kinds of value (spec p2 9.3, 9.7):
//   - a page key of HELP_KEYS: title and body are `shell.help.<key>`;
//   - a topic `filter.<id>`, `service.<slug>` or `option.<name>` (parseHelpTopic): the card's or the row's own explanation. Its text is
//     in the namespace of the screen that owns it, so no lane edits this file or shell.json: `profiles.filters.help.<id>.body`,
//     `services.help.<slug>.body` and `rules.options.help.<name>.{title,body}`. A filter's and a service's TITLE is its catalogue name.
//     A topic with no text yet shows `shell.help.topic.*`, so a link to it never opens nothing.
// An unknown value in a hand-typed URL (neither of the two kinds) opens nothing.

export const HELP_KEYS = ["account", "profiles", "endpoints", "statistics", "activityLog", "domainTest", "apiTokens", "docs", "status"] as const;
export type HelpKey = (typeof HELP_KEYS)[number];

export function isHelpKey(value: string | null): value is HelpKey {
  return value !== null && (HELP_KEYS as readonly string[]).includes(value);
}

export function SectionHelp() {
  const t = useTranslations("shell");
  const dialog = useUrlDialog("helpPane");
  const key = isHelpKey(dialog.value) ? dialog.value : null;
  const topic = key === null ? parseHelpTopic(dialog.value) : null;

  const footer = (
    <Button className="w-full" variant="secondary" onPress={dialog.close}>
      {t("help.close")}
    </Button>
  );

  if (topic) return <TopicHelp dialog={dialog} topic={topic} footer={footer} />;

  return (
    <UrlModal dialog={dialog} isOpen={key !== null} title={key ? t(`help.${key}.title`) : ""} footer={footer}>
      {key ? <p className="text-sm leading-relaxed">{t(`help.${key}.body`)}</p> : null}
    </UrlModal>
  );
}

function TopicHelp({dialog, topic, footer}: {dialog: ReturnType<typeof useUrlDialog>; topic: HelpTopic; footer: ReactNode}) {
  const shell = useTranslations("shell");
  const profiles = useTranslations("profiles");
  const services = useTranslations("services");
  const rules = useTranslations("rules");
  const locale = useLocale();
  // The catalogues are cached for ten minutes and the screen that opened this has them already; a cold deep link asks once.
  const filters = useQuery({...catalogFiltersQueryOptions(), enabled: topic.kind === "filter"});
  const catalogue = useQuery({...catalogServicesQueryOptions(), enabled: topic.kind === "service"});

  const pick = (item: {name_fa: string; name_en: string} | undefined) => (item ? (locale === "fa" ? item.name_fa : item.name_en) : undefined);
  const fallbackTitle = shell(`help.topic.${topic.kind}`);
  const fallbackBody = shell("help.topic.none");

  // `t.has` and the `as never` are for keys that come from data: the catalogue grows without a release of the web.
  let title: string;
  let body: string;
  if (topic.kind === "filter") {
    const key = `filters.help.${topic.id}.body`;
    title = pick(filters.data?.find((f) => f.id === topic.id)) ?? fallbackTitle;
    body = profiles.has(key as never) ? profiles(key as never) : fallbackBody;
  } else if (topic.kind === "service") {
    const key = `help.${topic.slug}.body`;
    title = pick(catalogue.data?.services.find((s) => s.slug === topic.slug)) ?? fallbackTitle;
    body = services.has(key as never) ? services(key as never) : fallbackBody;
  } else {
    const base = `options.help.${topic.name}`;
    title = rules.has(`${base}.title` as never) ? rules(`${base}.title` as never) : fallbackTitle;
    body = rules.has(`${base}.body` as never) ? rules(`${base}.body` as never) : fallbackBody;
  }

  return (
    <UrlModal dialog={dialog} isOpen title={title} footer={footer}>
      <p className="text-sm leading-relaxed">{body}</p>
    </UrlModal>
  );
}
