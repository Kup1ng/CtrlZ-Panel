"use client";

import {Badge, Button, Tooltip} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";

import {badgePlacement, useDirection} from "../hooks/useLogicalEdge.ts";
import {UrlModal} from "../dialog/UrlModal.tsx";
import {NotificationList} from "./NotificationList.tsx";
import {useShellApp} from "./shellContext.tsx";
import {useBellData} from "./useBellData.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";

// T-118. The button sits in the sidebar header and the mobile bar. The dialog is
// mounted once, in AppShell, so two buttons do not make two dialogs.

/** Admin has no bell (spec 13), and the feeds behind it are panel routes: nothing of it mounts there. */
export function BellButton() {
  return useShellApp() === "admin" ? null : <PanelBellButton />;
}

function PanelBellButton() {
  const t = useTranslations("shell");
  const dir = useDirection();
  // Persian digits in fa (spec 4.4), the same as the spoken label built from the ICU `#`.
  const format = useAppFormat();
  const {unread} = useBellData();
  const dialog = useUrlDialog("notificationsDialog");

  const label = unread > 0 ? `${t("bell.label")}, ${t("bell.unread", {count: unread})}` : t("bell.label");

  return (
    <Badge.Anchor className="shell-bell">
      <Tooltip delay={400} isDisabled={dialog.isOpen}>
        <Button isIconOnly aria-label={label} variant="ghost" onPress={() => dialog.open()}>
          <Icon name="bell" className="size-5" />
        </Button>
        <Tooltip.Content>{t("bell.label")}</Tooltip.Content>
      </Tooltip>
      {unread > 0 ? (
        <Badge color="accent" size="sm" placement={badgePlacement("top", "end", dir)}>
          {unread > 99 ? `${format.number(99)}+` : format.number(unread)}
        </Badge>
      ) : null}
    </Badge.Anchor>
  );
}

export function BellDialog() {
  return useShellApp() === "admin" ? null : <PanelBellDialog />;
}

function PanelBellDialog() {
  const t = useTranslations("shell");
  const {entries, markRead} = useBellData();
  const dialog = useUrlDialog("notificationsDialog");

  return (
    <UrlModal dialog={dialog} title={t("bell.title")}>
      <NotificationList entries={entries} onOpen={markRead} />
    </UrlModal>
  );
}
