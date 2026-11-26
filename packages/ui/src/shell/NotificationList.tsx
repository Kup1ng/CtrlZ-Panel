"use client";

import {Accordion, Alert, Button, buttonVariants} from "@heroui/react";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useId, useRef} from "react";
import type {Key} from "react-aria-components";

import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {useNoticeText} from "./noticeText.ts";
import {announceRowLink, securityActions} from "./securityNotice.ts";
import {safeInternalPath, type BellEntry} from "./useBellData.ts";

// Body of the bell dialog (spec 8.5). The unread security notices of Question 19 stand in their own block above the
// list, one per kind with a count, each with its links and, when this session may clear it, a Mark as read button; they are
// never inside the accordion. The list is an Accordion, one item per entry with the title, the relative date and an unread dot. Opening
// an ordinary item marks it read. Opening a security item never does: clearing one is a decision, taken with the button,
// and the API refuses it to a session that existed when the notice was made.

type Props = {
  entries: BellEntry[];
  /** The unread security notices shown apart. */
  security: BellEntry[];
  /** Opening an ordinary item reads it. */
  onOpen: (entry: BellEntry) => void;
  /** The Mark as read button of a security notice. */
  onMark: (entry: BellEntry) => void;
  /** Older notices are on a page that is not loaded: a button asks for it. */
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  /** The panel stopped paging by itself with unread notices still unloaded (webi-r2-6): the list says so and points to the button. */
  moreUnread?: boolean;
};

export function NotificationList({entries, security, onOpen, onMark, hasMore = false, loadingMore = false, onLoadMore, moreUnread = false}: Props) {
  const t = useTranslations("shell");
  const format = useAppFormat();
  const router = useRouter();
  const textOf = useNoticeText();
  // Opening is what marks an entry read, and the set that comes back holds every
  // open item, so only keys that were not in the last set count as newly opened.
  const open = useRef<Set<string>>(new Set());

  if (entries.length === 0 && security.length === 0 && !hasMore) {
    return <SectionEmpty icon="bell" title={t("bell.empty.title")} description={t("bell.empty.text")} />;
  }

  const byKey = new Map(entries.map((e) => [e.key, e]));

  return (
    <div className="flex flex-col gap-4">
      {security.length > 0 ? <SecurityBlock security={security} onMark={onMark} moreUnread={moreUnread} /> : null}
      {entries.length > 0 ? (
        <Accordion
          allowsMultipleExpanded
          onExpandedChange={(keys: Set<Key>) => {
            const next = new Set([...keys].map(String));
            for (const key of next) {
              const entry = byKey.get(key);
              // A security notice is not read by being opened (Question 19).
              if (!open.current.has(key) && entry && !entry.read && !entry.security) onOpen(entry);
            }
            open.current = next;
          }}
        >
          {entries.map((entry) => {
            const {title, body} = entry.source === "announcement" ? {title: t("bell.announcement"), body: entry.body} : textOf(entry);
            const path = safeInternalPath(entry.link);
            return (
              <Accordion.Item key={entry.key} id={entry.key}>
                <Accordion.Heading>
                  {/* min-w-0: a trigger is a flex item of the heading and its automatic minimum is its content, so a long title pushed the date and the
                      chevron out of the dialog at 375px (design critique T-464); with the minimum gone the title is the part that is cut. */}
                  <Accordion.Trigger className="min-w-0">
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
                      {/* A dot alone is colour alone (T-118): the mark is one element whose name, "Unread", is read by a screen reader
                          and whose dot is for sighted users. It sits before the title, so the row is announced "Unread, <title>, <when>". */}
                      {!entry.read ? (
                        <span data-testid="unread-mark" className="inline-flex shrink-0 items-center">
                          <span className="bg-accent size-2 rounded-full" aria-hidden="true" />
                          <span className="sr-only">{t("bell.unreadMark")}</span>
                        </span>
                      ) : (
                        // The slot of the dot stays on a read row, so the titles of read and unread rows start at the same place.
                        <span className="size-2 shrink-0" aria-hidden="true" />
                      )}
                      <span className="min-w-0 flex-1 truncate text-start text-sm">{title}</span>
                      {/* A real <time>: the relative text is what is shown, the machine value and the full date are behind it. */}
                      <time dateTime={entry.createdAt} title={format.dateTime(entry.createdAt)} data-testid="notice-time" className="text-muted shrink-0 text-xs">
                        {format.relative(entry.createdAt)}
                      </time>
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
      ) : null}
      {/* The panel loads the newest 50 and, by itself, the pages that hold an unread notice; the rest waits for this button. */}
      {hasMore && onLoadMore ? (
        <div className="flex flex-col items-center gap-1">
          {moreUnread && security.length === 0 ? <p className="text-muted text-center text-xs">{t("bell.moreUnread")}</p> : null}
          <Button size="sm" variant="ghost" isPending={loadingMore} onPress={onLoadMore}>
            {t("bell.showOlder")}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

/** The block above the list: one warning per unread security notice, newest first. */
function SecurityBlock({security, onMark, moreUnread}: {security: BellEntry[]; onMark: (entry: BellEntry) => void; moreUnread: boolean}) {
  const t = useTranslations("shell");
  const format = useAppFormat();
  const textOf = useNoticeText();
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} data-testid="security-notices" className="flex flex-col gap-2">
      <h3 id={headingId} className="text-sm font-semibold">
        {t("bell.security.title")}
      </h3>
      {moreUnread ? (
        <p className="text-sm" data-testid="more-unread">
          {t("bell.moreUnread")}
        </p>
      ) : null}
      <ul className="flex flex-col gap-2">
        {security.map((entry) => {
          const {title, body} = textOf(entry);
          return (
            <li key={entry.key} data-notice={entry.id}>
              <Alert status="warning">
                <Alert.Indicator />
                <Alert.Content className="min-w-0">
                  <Alert.Title className="[overflow-wrap:anywhere]">{title}</Alert.Title>
                  {body ? <Alert.Description className="[overflow-wrap:anywhere]">{body}</Alert.Description> : null}
                  <p className="text-muted mt-1 text-xs">
                    <time dateTime={entry.createdAt} title={format.dateTime(entry.createdAt)}>
                      {format.relative(entry.createdAt)}
                    </time>
                    {entry.count > 1 ? ` · ${t("bell.security.several", {count: entry.count, first: format.dateTime(entry.oldestAt)})}` : ""}
                  </p>
                  <SecurityControls entry={entry} title={title} onMark={onMark} />
                </Alert.Content>
              </Alert>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/**
 * What a person can do with an unread security notice: the links to the places that undo it (they depend on the kind), and either the button that
 * clears it or the line that says why it cannot be cleared from this session. The API's `markable` decides, not the kind.
 */
function SecurityControls({entry, title, onMark}: {entry: BellEntry; title: string; onMark: (entry: BellEntry) => void}) {
  const t = useTranslations("shell");
  return (
    <div className="mt-2 flex flex-col gap-2">
      {entry.markable ? null : (
        <p className="text-sm" data-testid="not-markable">
          {t("bell.security.notMarkable")}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        {securityActions(entry.kind).map((action) => (
          <Link key={action.id} href={action.href} className={buttonVariants({size: "sm", variant: "outline"})} onClick={() => announceRowLink(action.id)}>
            {t(`bell.security.${action.label}`)}
          </Link>
        ))}
        {entry.markable ? (
          <Button size="sm" variant="tertiary" aria-label={t("bell.security.markReadAria", {title})} onPress={() => onMark(entry)}>
            {t("bell.security.markRead")}
          </Button>
        ) : null}
      </div>
    </div>
  );
}
