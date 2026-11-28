"use client";

import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";
import {useCallback} from "react";

import type {BellEntry} from "./useBellData.ts";

// The words of a notification, one place for the bell and the banners (spec 8.5, 8.8): `shell.bell.kinds.<kind>.title|text`.
// `when` is added to the params of every notice: the date of the notice, formatted in the person's language and calendar,
// for the texts that say when something happened (the two security notices). A text that does not use it ignores it.

export type NoticeText = {title: string; body: string | undefined; known: boolean};

export function useNoticeText(): (entry: Pick<BellEntry, "kind" | "params" | "createdAt">) => NoticeText {
  const t = useTranslations("shell");
  const format = useAppFormat();
  return useCallback(
    (entry) => {
      const base = `bell.kinds.${entry.kind}`;
      // An unknown kind (an older client meets a newer server) gets a generic title and no text, so it never breaks the list.
      if (entry.kind && t.has(`${base}.title` as never)) {
        const params = {...entry.params, when: format.dateTime(entry.createdAt)};
        return {title: t(`${base}.title` as never, params as never), body: t(`${base}.text` as never, params as never), known: true};
      }
      return {title: t("bell.generic"), body: undefined, known: false};
    },
    [t, format],
  );
}
