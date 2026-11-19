"use client";

import {Alert, Button, CloseButton} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState, useSyncExternalStore} from "react";

// T-122, spec 8.8. Global notices above the whole app, at most two at once and
// the rest behind "n more". Priority:
//   1 client conditions (offline)
//   2 unread critical notifications
//   3 unread announcements inside their window
//   4 "set a password" when SMS is off and the user has none
// Only (1) exists in P1. 2 to 4 need WP4's hooks and arrive through
// useServerBanners(), which returns nothing for now.

export type ShellBanner = {
  id: string;
  status: "accent" | "warning" | "danger" | "success";
  title: string;
  text?: string;
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

/** Banners that come from the API. Priority 2 to 4, already in order. */
function useServerBanners(): ShellBanner[] {
  return [];
}

export function BannerStack() {
  const t = useTranslations("shell");
  // The server snapshot is `true`, so the first paint has no offline banner and
  // hydration matches.
  const online = useSyncExternalStore(subscribeOnline, () => navigator.onLine, () => true);
  const server = useServerBanners();
  const [expanded, setExpanded] = useState(false);

  const banners: ShellBanner[] = [
    ...(online ? [] : [{id: "offline", status: "warning" as const, title: t("banners.offline.title"), text: t("banners.offline.text")}]),
    ...server,
  ];
  if (banners.length === 0) return null;

  const shown = expanded ? banners : banners.slice(0, MAX_SHOWN);
  const hidden = banners.length - shown.length;

  return (
    <section aria-label={t("banners.region")} className="banner-stack">
      {shown.map((b) => (
        <Alert key={b.id} status={b.status} className="banner-stack__item">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{b.title}</Alert.Title>
            {b.text ? <Alert.Description>{b.text}</Alert.Description> : null}
          </Alert.Content>
          {b.onDismiss ? <CloseButton aria-label={t("banners.dismiss")} onPress={b.onDismiss} /> : null}
        </Alert>
      ))}
      {hidden > 0 ? (
        <Button size="sm" variant="ghost" onPress={() => setExpanded(true)}>
          {t("banners.more", {count: hidden})}
        </Button>
      ) : null}
    </section>
  );
}
