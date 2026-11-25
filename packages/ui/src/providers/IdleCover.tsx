"use client";

import {Button} from "@heroui/react";
import {getIdleState, subscribeIdleState, uncoverPage} from "@ctrlz/api-client/activity.ts";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useSyncExternalStore} from "react";

import {useApp} from "./appContext.tsx";

// What AppProviders shows instead of the page once the session's idle limit has passed with no input
// (activity.ts, wp4-r6-3). It holds no account data and sends no request. Plain text on the page
// background, so it reads the same in both themes and both directions.
//
// The page comes back only through the Continue button (wp4-r7-1), not through any input: a mouse that
// jitters or an alt-tab must not bring an account back for a passer-by. The button takes focus when the
// cover appears, so a keyboard or screen-reader user lands on the one thing to do, and "activate" on a
// phone (TalkBack, VoiceOver) has a target, which "move the mouse" never had.
export function IdleCover() {
  const t = useTranslations("errors");
  const app = useApp();
  const {ending} = useSyncExternalStore(subscribeIdleState, getIdleState, getIdleState);
  // The admin console does not come back from a cover: the guard has ended the session and is loading
  // the login page, so there is nothing to continue (wp4-r8-4). Only a status line shows until then.
  // Except when another admin tab is still in use (wp4-r9-3): the guard ended nothing, the session is
  // alive, and this tab gets the same Continue as the panel.
  const showContinue = app !== "admin" || !ending;
  const button = useRef<HTMLButtonElement>(null);
  const main = useRef<HTMLElement>(null);
  // Not the autoFocus prop (jsx-a11y/no-autofocus): the page that held the focus has just been unmounted,
  // so the focus is on <body>, and this is the one control left. Keyed on `showContinue` because the
  // cover can change under a keyboard user: an admin tab covered while another tab was in use shows
  // Continue, and when the recheck ends the session (wp4-r10-1) that button unmounts. Focus would fall
  // to <body>, so it moves to the status line's container instead (wp4-r11-2).
  useEffect(() => (showContinue ? button.current : main.current)?.focus(), [showContinue]);
  if (!showContinue) {
    return (
      <main ref={main} id="main-content" tabIndex={-1} className="grid min-h-dvh place-items-center p-6 text-center">
        <p role="status" className="max-w-sm text-muted">
          {t("idle.adminText")}
        </p>
      </main>
    );
  }
  return (
    <main ref={main} id="main-content" tabIndex={-1} className="grid min-h-dvh place-items-center p-6 text-center">
      <div role="alertdialog" aria-labelledby="idle-title" aria-describedby="idle-text" className="flex max-w-sm flex-col items-center gap-3">
        <h1 id="idle-title" className="text-lg font-semibold">
          {t("idle.title")}
        </h1>
        <p id="idle-text" className="text-muted">
          {t("idle.text")}
        </p>
        <Button ref={button} onPress={uncoverPage}>
          {t("idle.continue")}
        </Button>
      </div>
    </main>
  );
}
