"use client";

import {Alert, Button, buttonVariants, CloseButton} from "@heroui/react";
import {isAnnouncementLive, useAnnouncementFeed, useAnnouncementNow, useMarkAnnouncementRead} from "@ctrlz/api-client/hooks/announcements.ts";
import {usePublicConfig} from "@ctrlz/api-client/hooks/config.ts";
import {useSession} from "@ctrlz/api-client/hooks/me.ts";
import {useMarkNotificationRead, useNotificationFeed} from "@ctrlz/api-client/hooks/notifications.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState, useSyncExternalStore} from "react";

import {useNoticeText} from "./noticeText.ts";
import {announceRowLink, securityActions, type SecurityActionId} from "./securityNotice.ts";
import {useAdminBanners} from "./useAdminBanners.ts";
import {useShellApp} from "./shellContext.tsx";
import {useMarkNoticeGroup} from "./useMarkNoticeGroup.ts";
import {bellModel} from "./useBellData.ts";

// T-122, spec 8.8. Global notices above the whole app, at most two at once and
// the rest behind "n more". Priority:
//   1 client conditions (offline)
//   2 unread security notices (Question 19), then unread critical notifications
//   3 unread announcements inside their window
//   4 "set a password" when SMS is off and the user has none
// 1 is local. 2 to 4 come from the API through useServerBanners().

export type ShellBanner = {
  id: string;
  status: "accent" | "warning" | "danger" | "success";
  title: string;
  text?: string;
  /** The text is written by a person in an unknown language (announcements), so it picks its own direction. */
  textAuto?: boolean;
  /** Absent means the banner cannot be dismissed (offline goes by itself). */
  onDismiss?: () => void;
  /** Internal links under the text (a security notice sends the person to the password and the sessions). Addresses are checked before they get here. */
  actions?: {id: string; label: string; href: string; row?: SecurityActionId}[];
  /** Spoken at once when the banner appears (a security notice). Every other banner is a static notice of the page. */
  urgent?: boolean;
};

const MAX_SHOWN = 2;

function subscribeOnline(cb: () => void) {
  window.addEventListener("online", cb);
  window.addEventListener("offline", cb);
  return () => {
    window.removeEventListener("online", cb);
    window.removeEventListener("offline", cb);
  };
}

/**
 * Banners that come from the API, priority 2 to 4 and already in order (spec 8.8):
 * unread security notices, then unread critical notifications, then unread announcements inside their window,
 * then "set a password" when SMS is off and the user has none. Dismissing marks the
 * item read through the same route as the bell, so the two never disagree.
 */
function useServerBanners(): ShellBanner[] {
  const t = useTranslations("shell");
  const e = useTranslations("errors");
  const {status, me} = useSession();
  // This is the one place that loads further pages by itself (see useNotificationFeed): a flood of notices must not hide an unread security notice on a page nobody asks for, up to the cap (past it the banners say that more is unread).
  const notifications = useNotificationFeed({autoPage: true});
  const announcements = useAnnouncementFeed();
  // A timer moves `now` at each start and end, so the window is judged again without a render from elsewhere.
  const now = useAnnouncementNow(announcements.items);
  const textOf = useNoticeText();
  const format = useAppFormat();
  const markGroup = useMarkNoticeGroup();
  const {mutate: readNotification} = useMarkNotificationRead();
  const {mutate: readAnnouncement} = useMarkAnnouncementRead();
  const noPassword = status === "ready" && me?.user.has_password === false;
  const config = usePublicConfig({enabled: noPassword});

  if (status !== "ready") return [];
  const out: ShellBanner[] = [];

  // The unread security notices, one banner per kind, newest first (Question 19, spec 8.5): two recovery-code notices and a
  // passkey notice are two banners, so the passkey one is not behind "n more" (webi-r1-7). A warning, not a dialog: it stays
  // until it is cleared. The button is there only when this session may clear every notice of the kind (`markable`); otherwise
  // the text says the notice can be cleared after signing in again, and the banner stays, so a thief's session cannot hide it
  // from the owner.
  for (const n of bellModel({items: notifications.items, securityItems: notifications.securityItems}, []).security) {
    const {title, body, known} = textOf(n);
    out.push({
      id: n.key,
      status: "warning",
      title,
      text:
        [
          known ? body : undefined,
          n.count > 1 ? t("bell.security.several", {count: n.count, first: format.dateTime(n.oldestAt)}) : undefined,
          n.markable ? undefined : t("bell.security.notMarkable"),
          // The panel loads a bounded number of pages by itself: past that, a notice (a passkey) could still be unread behind them (webi-r2-6).
          notifications.moreUnread ? t("bell.moreUnread") : undefined,
        ]
          .filter(Boolean)
          .join(" ") || undefined,
      // One id after another and in a bounded number, so a group of hundreds is not sent at once (webi-r2-3, webi-r2-8).
      onDismiss: n.markable ? () => markGroup(n.memberIds) : undefined,
      actions: securityActions(n.kind).map((a) => ({id: a.id, row: a.id, href: a.href, label: t(`bell.security.${a.label}`)})),
      urgent: true,
    });
  }

  for (const n of notifications.items) {
    // An unread security notice is already a banner above, one per kind.
    if (n.severity !== "critical" || n.read_at !== undefined || n.security) continue;
    // An unknown kind gets the generic title, so an older client never breaks.
    const {title, body, known} = textOf({kind: n.kind, params: n.params, createdAt: n.created_at});
    out.push({id: `n:${n.id}`, status: "danger", title, text: known ? body : undefined, onDismiss: () => readNotification(n.id)});
  }

  const live = announcements.items
    .filter((a) => !a.read && isAnnouncementLive(a, now))
    .sort((a, b) => Date.parse(b.starts_at) - Date.parse(a.starts_at));
  for (const a of live) {
    out.push({id: `a:${a.id}`, status: "accent", title: t("bell.announcement"), text: a.body, textAuto: true, onDismiss: () => readAnnouncement(a.id)});
  }

  if (noPassword && config.data?.sms_available === false) {
    out.push({id: "set-password", status: "warning", title: e("banners.setPassword.title"), text: e("banners.setPassword.text")});
  }
  return out;
}

/** Priority 1, local: the browser is offline. The server snapshot is `true`, so the first paint has no banner and hydration matches. */
function useOfflineBanner(): ShellBanner[] {
  const t = useTranslations("shell");
  const online = useSyncExternalStore(subscribeOnline, () => navigator.onLine, () => true);
  return online ? [] : [{id: "offline", status: "warning", title: t("banners.offline.title"), text: t("banners.offline.text")}];
}

/**
 * The panel reads the panel API's banners and the admin the admin API's (notices and alerts, spec 13.6). Each app mounts only
 * its own hooks: a panel hook on the admin host would ask the panel `/me` and refresh against the wrong API.
 */
export function BannerStack() {
  return useShellApp() === "admin" ? <AdminBannerStack /> : <PanelBannerStack />;
}

function PanelBannerStack() {
  const offline = useOfflineBanner();
  const server = useServerBanners();
  return <BannerList banners={[...offline, ...server]} />;
}

function AdminBannerStack() {
  const offline = useOfflineBanner();
  const server = useAdminBanners();
  return <BannerList banners={[...offline, ...server]} />;
}

function BannerList({banners}: {banners: ShellBanner[]}) {
  const t = useTranslations("shell");
  const [expanded, setExpanded] = useState(false);
  const region = useRef<HTMLElement>(null);
  // The "n more" button leaves with the press (nothing is hidden any more), and the focus would fall to <body>. Once the extra
  // banners are in the page the focus goes to the first one that was revealed (wp10-r14-1). A ref, not state: it is a note for
  // the next effect, not something to render.
  const revealed = useRef(false);
  useEffect(() => {
    if (!expanded || !revealed.current) return;
    revealed.current = false;
    const first = region.current?.querySelectorAll<HTMLElement>(".banner-stack__item")[MAX_SHOWN];
    // A banner with no close button (offline) cannot take the focus, so the region itself is the place.
    (first?.querySelector<HTMLElement>("button") ?? region.current)?.focus();
  }, [expanded]);
  if (banners.length === 0) return null;

  const shown = expanded ? banners : banners.slice(0, MAX_SHOWN);
  const hidden = banners.length - shown.length;

  return (
    <section ref={region} tabIndex={-1} aria-label={t("banners.region")} className="banner-stack focus:outline-none">
      {shown.map((b) => (
        <Alert key={b.id} status={b.status} className="banner-stack__item" role={b.urgent ? "alert" : undefined}>
          <Alert.Indicator />
          {/* min-w-0: a flex item cannot shrink below its content, and an announcement can hold a URL with no break in it. */}
          <Alert.Content className="min-w-0">
            <Alert.Title className="[overflow-wrap:anywhere]">{b.title}</Alert.Title>
            {b.text ? (
              <Alert.Description
                dir={b.textAuto ? "auto" : undefined}
                className={b.textAuto ? "whitespace-pre-wrap [overflow-wrap:anywhere]" : "[overflow-wrap:anywhere]"}
              >
                {b.text}
              </Alert.Description>
            ) : null}
            {b.actions?.length ? (
              <div className="mt-2 flex flex-wrap gap-2">
                {b.actions.map((a) => (
                  <Link key={a.id} href={a.href} className={buttonVariants({size: "sm", variant: "outline"})} onClick={() => a.row && announceRowLink(a.row)}>
                    {a.label}
                  </Link>
                ))}
              </div>
            ) : null}
          </Alert.Content>
          {b.onDismiss ? <CloseButton aria-label={t("banners.dismiss")} onPress={b.onDismiss} /> : null}
        </Alert>
      ))}
      {hidden > 0 ? (
        <Button
          size="sm"
          variant="ghost"
          onPress={() => {
            revealed.current = true;
            setExpanded(true);
          }}
        >
          {t("banners.more", {count: hidden})}
        </Button>
      ) : null}
    </section>
  );
}
