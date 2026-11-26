"use client";

import {Button} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef, type ReactNode} from "react";

import {keepFocus} from "./restoreFocus.ts";

// Under a field the admin edited and another admin then changed (wp10-r5-3, useServerForm `conflicts`). The write has no
// version or If-Match, so saving would replace the other admin's newer value with this admin's older intent, and both would
// see "Saved". It is role="alert" because it appears already holding its text, often after a background refetch with no toast, and a
// polite status region inserted with its text is not reliably spoken (wp10-r20-2, as RefreshFailed). The note says what the server holds now and asks for one deliberate answer; Save waits for it.
//
// Answering removes the note, and with it the button that had the focus. The focus goes back to the field the note sits under, or
// to the nearest container that is still there, so the keyboard does not start again from the skip link (wp10-r9-1).

// A Button is one line (nowrap, fixed height), and the note sits in one cell of a grid: at 768 the Limits form has two columns and the cell is about
// 176px wide, so "Use the server's value" (161px) was wider than the 152px inside the note's padding and touched its edge. The answers may wrap, and
// grow to two lines, and never be wider than the note.
const ANSWER = "h-auto md:h-auto min-h-(--control-h) max-w-full py-1.5 text-center whitespace-normal";

export function ConflictNote({name, value, onKeep, onUseServer}: {name: string; value: ReactNode; onKeep: () => void; onUseServer: () => void}) {
  const t = useTranslations("admin");
  const root = useRef<HTMLDivElement>(null);
  return (
    <div ref={root} role="alert" className="bg-surface-secondary flex flex-col gap-2 rounded-(--radius-box) p-3 text-sm" data-testid={`conflict-${name}`}>
      <span>{t("conflict.text")}</span>
      <span className="font-medium [overflow-wrap:anywhere]" data-testid={`conflict-${name}-value`}>
        {value === "" || value === null || value === undefined ? t("conflict.empty") : value}
      </span>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="tertiary" className={ANSWER} onPress={() => keepFocus(onKeep, root.current)}>
          {t("conflict.keep")}
        </Button>
        <Button size="sm" variant="tertiary" className={ANSWER} onPress={() => keepFocus(onUseServer, root.current)}>
          {t("conflict.useServer")}
        </Button>
      </div>
    </div>
  );
}
