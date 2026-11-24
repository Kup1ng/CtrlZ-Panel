"use client";

import {Accordion, Button} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useRef} from "react";
import type {Key} from "react-aria-components";

import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {safeInternalPath, type BellEntry} from "./useBellData.ts";

// Body of the bell dialog (spec 8.5): an Accordion, one item per entry with the
// title, the relative date and an unread dot. Opening an item marks it read.

type Props = {
  entries: BellEntry[];
  onOpen: (entry: BellEntry) => void;
};

export function NotificationList({entries, onOpen}: Props) {
  const t = useTranslations("shell");
  const format = useAppFormat();
  const router = useRouter();
  // Opening is what marks an entry read, and the set that comes back holds every
  // open item, so only keys that were not in the last set count as newly opened.
  const open = useRef<Set<string>>(new Set());

  if (entries.length === 0) {
    return <SectionEmpty icon="bell" title={t("bell.empty.title")} description={t("bell.empty.text")} />;
  }

  const byKey = new Map(entries.map((e) => [e.key, e]));

  function textOf(entry: BellEntry): {title: string; body: string | undefined} {
    if (entry.source === "announcement") return {title: t("bell.announcement"), body: entry.body};
    // An unknown kind (an older client meets a newer server) gets a generic
    // title and the date, so it never breaks the list.
    const base = `bell.kinds.${entry.kind}`;
    if (entry.kind && t.has(`${base}.title` as never)) {
      return {title: t(`${base}.title` as never, entry.params as never), body: t(`${base}.text` as never, entry.params as never)};
    }
    return {title: t("bell.generic"), body: undefined};
  }

  return (
    <Accordion
      allowsMultipleExpanded
      onExpandedChange={(keys: Set<Key>) => {
        const next = new Set([...keys].map(String));
        for (const key of next) {
          const entry = byKey.get(key);
          if (!open.current.has(key) && entry && !entry.read) onOpen(entry);
        }
        open.current = next;
      }}
    >
      {entries.map((entry) => {
        const {title, body} = textOf(entry);
        const path = safeInternalPath(entry.link);
        return (
          <Accordion.Item key={entry.key} id={entry.key}>
            <Accordion.Heading>
              <Accordion.Trigger>
                <span className="flex min-w-0 flex-1 items-center gap-2">
                  {entry.severity === "critical" || entry.severity === "warning" ? (
                    <span
                      className={
                        entry.severity === "critical" ? "text-danger-soft-foreground" : "text-warning-soft-foreground"
                      }
                    >
                      <Icon name={entry.severity === "critical" ? "error" : "warning"} className="size-4 shrink-0" />
                      <span className="sr-only">{t(`bell.severity.${entry.severity}`)}</span>
                    </span>
                  ) : null}
                  {/* A dot alone is colour alone; the text is for readers and the dot for sighted users. */}
                  {!entry.read ? (
                    <span className="bg-accent size-2 shrink-0 rounded-full" aria-hidden="true" />
                  ) : null}
                  {!entry.read ? <span className="sr-only">{t("bell.unreadMark")}</span> : null}
                  <span className="min-w-0 flex-1 truncate text-start text-sm">{title}</span>
                  <span className="text-muted shrink-0 text-xs">{format.relative(entry.createdAt)}</span>
                </span>
                <Accordion.Indicator />
              </Accordion.Trigger>
            </Accordion.Heading>
            <Accordion.Panel>
              <Accordion.Body>
                {body ? (
                  // Announcements are written by an admin in either language and have no language column.
                  <p className="text-muted text-sm whitespace-pre-wrap [overflow-wrap:anywhere]" dir={entry.source === "announcement" ? "auto" : undefined}>
                    {body}
                  </p>
                ) : null}
                {path ? (
                  <Button className="mt-2" size="sm" variant="outline" onPress={() => router.push(path)}>
                    {t("bell.open")}
                  </Button>
                ) : null}
              </Accordion.Body>
            </Accordion.Panel>
          </Accordion.Item>
        );
      })}
    </Accordion>
  );
}
