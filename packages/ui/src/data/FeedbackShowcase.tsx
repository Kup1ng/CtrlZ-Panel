"use client";

import {Button, Switch} from "@heroui/react";
import {ApiError} from "@ctrlz/api-client/errors.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {UrlModal} from "../dialog/UrlModal.tsx";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {DenseRow} from "./DenseRow.tsx";
import {ListRow, RowList} from "./ListRow.tsx";
import {RowCounters} from "./RowCounters.tsx";
import {Tech} from "./Tech.tsx";

// WP7's samples, for the pages under the lab group (closed unless CTRLZ_LAB is "1") and for the
// tests of dialogs.spec.ts, states.spec.ts and rows.spec.ts: the empty state, the section error
// with its request id, the URL dialog with a body tall enough to scroll, and both kinds of row.
// Nothing here is a screen. The request id is a constant, not a message: it is not wording.

const REQUEST_ID = "req-7f3a91c2";
const LINES = 24;

export function FeedbackShowcase() {
  const t = useTranslations("feedback.showcase");
  const dialog = useUrlDialog("ruleDialog");
  const [selected, setSelected] = useState(false);
  const [retries, setRetries] = useState(0);
  // A state-only frame that Escape and an outside click must not close (the reauth and TOTP steps of WP8).
  const [locked, setLocked] = useState(false);
  const error = new ApiError(503, "service_unavailable", REQUEST_ID);
  const counters = (["filters", "services", "rules", "options"] as const).map((id, i) => ({
    id,
    label: t(`counters.${id}`),
    value: [12, 3, 1204, 7][i]!,
    href: `/profiles?tab=${id}`,
  }));

  return (
    <>
      <PageHeader icon="profiles" title={t("title")} subtitle={t("subtitle")} />
      <div className="flex flex-col gap-8 pb-10">
        <section aria-labelledby="fb-empty" className="flex flex-col gap-2">
          <h2 id="fb-empty" className="text-muted text-sm font-medium">
            {t("empty")}
          </h2>
          <div data-testid="sample-empty">
            <SectionEmpty
              icon="filters"
              action={
                <Button variant="secondary" onPress={() => dialog.open("new")}>
                  {t("emptyAction")}
                </Button>
              }
            />
          </div>
        </section>

        <section aria-labelledby="fb-error" className="flex flex-col gap-2">
          <h2 id="fb-error" className="text-muted text-sm font-medium">
            {t("error")}
          </h2>
          <div data-testid="sample-error" data-retries={retries}>
            <SectionError error={error} onRetry={() => setRetries((n) => n + 1)} />
          </div>
        </section>

        <section aria-labelledby="fb-rows" className="flex flex-col gap-2">
          <h2 id="fb-rows" className="text-muted text-sm font-medium">
            {t("rows")}
          </h2>
          <RowList>
            <ListRow
              isHighlighted
              icon={<Icon name="profiles" />}
              title={t("profileNew")}
              subtitle={t("endpointLine")}
              href="/profiles"
              counters={<RowCounters items={counters} />}
            />
            <ListRow
              icon={<Icon name="profiles" />}
              title={t("profileOne")}
              subtitle={<Tech>home.example.org</Tech>}
              href="/profiles"
              counters={<RowCounters items={counters} />}
            />
            <ListRow icon={<Icon name="profiles" />} title={t("profileTwo")} subtitle={t("endpointLine")} counters={<RowCounters items={counters} />} />
          </RowList>
        </section>

        <section aria-labelledby="fb-dense" className="flex flex-col gap-2">
          <h2 id="fb-dense" className="text-muted text-sm font-medium">
            {t("dense")}
          </h2>
          <RowList>
            <DenseRow
              leading={<Icon name="shield" />}
              title={<Tech>ads.example.org</Tech>}
              tags={<span className="text-muted text-xs">{t("ruleBlocked")}</span>}
              hoverActions={
                <>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={t("copy")}>
                    <Icon name="copy" className="size-4" />
                  </Button>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={t("edit")}>
                    <Icon name="edit" className="size-4" />
                  </Button>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={t("remove")}>
                    <Icon name="trash" className="size-4" />
                  </Button>
                </>
              }
              trailing={
                <Switch aria-label={t("switchLabel")} defaultSelected>
                  <Switch.Content>
                    <Switch.Control>
                      <Switch.Thumb />
                    </Switch.Control>
                  </Switch.Content>
                </Switch>
              }
              onPress={() => setSelected((v) => !v)}
              selection={{isSelected: selected, onChange: setSelected, label: t("select")}}
            />
            <DenseRow leading={<Icon name="check" />} title={<Tech>cdn.example.org</Tech>} tags={<span className="text-muted text-xs">{t("ruleAllowed")}</span>} />
          </RowList>
        </section>

        <section aria-labelledby="fb-dialog" className="flex flex-col gap-2">
          <h2 id="fb-dialog" className="text-muted text-sm font-medium">
            {t("dialog")}
          </h2>
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onPress={() => dialog.open("tall")}>
              {t("openDialog")}
            </Button>
            <Button variant="secondary" onPress={() => setLocked(true)}>
              {t("openLocked")}
            </Button>
          </div>
        </section>
      </div>

      <UrlModal
        dialog={dialog}
        title={t("dialogTitle")}
        footer={
          <Button className="w-full" onPress={dialog.close}>
            {t("dialogDone")}
          </Button>
        }
      >
        <div className="flex flex-col gap-3 text-sm" data-testid="dialog-value" data-value={dialog.value ?? ""}>
          <div>
            <Button size="sm" variant="outline" onPress={() => dialog.open("second")}>
              {t("dialogSwitch")}
            </Button>
          </div>
          {Array.from({length: LINES}, (_, i) => (
            <p key={i}>{t("dialogLine")}</p>
          ))}
        </div>
      </UrlModal>

      <DialogFrame
        isOpen={locked}
        onClose={() => setLocked(false)}
        isDismissable={false}
        title={t("lockedTitle")}
        footer={
          <Button className="w-full" onPress={() => setLocked(false)}>
            {t("dialogDone")}
          </Button>
        }
      >
        <p className="text-sm">{t("lockedLine")}</p>
      </DialogFrame>
    </>
  );
}
