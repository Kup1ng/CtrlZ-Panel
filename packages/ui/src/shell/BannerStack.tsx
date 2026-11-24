"use client";

import {Alert, Button, CloseButton} from "@heroui/react";
import {isAnnouncementLive, useAnnouncementFeed, useAnnouncementNow, useMarkAnnouncementRead} from "@ctrlz/api-client/hooks/announcements.ts";
import {usePublicConfig} from "@ctrlz/api-client/hooks/config.ts";
import {useSession} from "@ctrlz/api-client/hooks/me.ts";
import {useMarkNotificationRead, useNotificationFeed} from "@ctrlz/api-client/hooks/notifications.ts";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState, useSyncExternalStore} from "react";

import {useAdminBanners} from "./useAdminBanners.ts";
import {useShellApp} from "./shellContext.tsx";

// T-122, spec 8.8. Global notices above the whole app, at most two at once and
// the rest behind "n more". Priority:
//   1 client conditions (offline)
//   2 unread critical notifications
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
 * unread critical notifications, then unread announcements inside their window,
 * then "set a password" when SMS is off and the user has none. Dismissing marks the
 * item read through the same route as the bell, so the two never disagree.
 */
function useServerBanners(): ShellBanner[] {
  const t = useTranslations("shell");
  const e = useTranslations("errors");
  const {status, me} = useSession();
  const notifications = useNotificationFeed();
  const announcements = useAnnouncementFeed();
  // A timer moves `now` at each start and end, so the window is judged again without a render from elsewhere.
  const now = useAnnouncementNow(announcements.items);
  const {mutate: readNotification} = useMarkNotificationRead();
  const {mutate: readAnnouncement} = useMarkAnnouncementRead();
  const noPassword = status === "ready" && me?.user.has_password === false;
  const config = usePublicConfig({enabled: noPassword});

  if (status !== "ready") return [];
  const out: ShellBanner[] = [];

  for (const n of notifications.items) {
    if (n.severity !== "critical" || n.read_at !== undefined) continue;
    const base = `bell.kinds.${n.kind}`;
    // An unknown kind gets the generic title, so an older client never breaks.
    const known = t.has(`${base}.title` as never);
    out.push({
      id: `n:${n.id}`,
      status: "danger",
      title: known ? t(`${base}.title` as never, n.params as never) : t("bell.generic"),
      text: known ? t(`${base}.text` as never, n.params as never) : undefined,
      onDismiss: () => readNotification(n.id),
    });
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
        <Alert key={b.id} status={b.status} className="banner-stack__item">
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
