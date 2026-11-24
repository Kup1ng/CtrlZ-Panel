"use client";

import {Badge, Button, Tooltip} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {badgePlacement, useDirection} from "../hooks/useLogicalEdge.ts";
import {NotificationList} from "./NotificationList.tsx";
import {ShellModal} from "./ShellModal.tsx";
import {useBellData} from "./useBellData.ts";
import {useShellDialog} from "./useShellDialog.ts";

// T-118. The button sits in the sidebar header and the mobile bar. The dialog is
// mounted once, in AppShell, so two buttons do not make two dialogs.

export function BellButton() {
  const t = useTranslations("shell");
  const dir = useDirection();
  const {unread} = useBellData();
  const dialog = useShellDialog("notificationsDialog");

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
          {unread > 99 ? "99+" : unread}
        </Badge>
      ) : null}
    </Badge.Anchor>
  );
}

export function BellDialog() {
  const t = useTranslations("shell");
  const {entries, markRead} = useBellData();
  const dialog = useShellDialog("notificationsDialog");

  return (
    <ShellModal isOpen={dialog.isOpen} onClose={dialog.close} title={t("bell.title")}>
      <NotificationList entries={entries} onOpen={markRead} />
    </ShellModal>
  );
}
