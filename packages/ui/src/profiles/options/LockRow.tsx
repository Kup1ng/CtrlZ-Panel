"use client";

import {Switch} from "@heroui/react";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";

import {useProfileFrame} from "../ProfileFrameContext.tsx";
import {OptionRow} from "./OptionRow.tsx";
import type {OptionRow as RowName} from "./optionModel.ts";

// Lock Profile (T-139, T-141, spec p2 7). The switch does not change anything by itself: it opens the state-only dialog of the frame, the
// lock dialog (password and message) or the unlock dialog (password), and it follows the profile, so it turns when the dialog has
// succeeded and not before. It is the one control of the page that a locked profile leaves enabled, since it is the way out.
//
// The message sits in the lock dialog and not in this row, because the message and the password are one request (`POST /lock
// {password, message}`) and the password must stay in a dialog that holds no URL, no query key and no storage. A locked row shows the
// message back, as the banner does.

export function LockRow({onLearnMore}: {onLearnMore: (name: RowName) => void}) {
  const t = useTranslations("rules");
  const {profile, locked, openLock, openUnlock} = useProfileFrame();
  const title = t("options.rows.lock.name");
  return (
    <OptionRow
      name="lock"
      title={title}
      description={t("options.rows.lock.description")}
      onLearnMore={onLearnMore}
      control={
        <>
          <span data-testid="lock-state" className="text-muted flex items-center gap-1 text-xs">
            <Icon name={locked ? "lock" : "unlock"} className="size-3.5" />
            {locked ? t("options.lock.locked") : t("options.lock.unlocked")}
          </span>
          <Switch isSelected={locked} aria-label={title} onChange={() => (locked ? openUnlock() : openLock())}>
            <Switch.Content>
              <Switch.Control>
                <Switch.Thumb />
              </Switch.Control>
            </Switch.Content>
          </Switch>
        </>
      }
    >
      {locked ? (
        <p className="text-sm [overflow-wrap:anywhere]" data-testid="lock-message">
          {profile.lock_message ? <bdi>{t("options.lock.message", {message: profile.lock_message})}</bdi> : t("options.lock.noMessage")}
        </p>
      ) : null}
    </OptionRow>
  );
}
