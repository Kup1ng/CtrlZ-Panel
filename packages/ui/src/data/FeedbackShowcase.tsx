"use client";

import {Button, Switch} from "@heroui/react";
import {ApiError} from "@ctrlz/api-client/errors.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {ConfirmFrame} from "../dialog/ConfirmFrame.tsx";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {UrlModal} from "../dialog/UrlModal.tsx";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {OnboardingCard} from "../shell/OnboardingCard.tsx";
import {PageHeader, type HeaderAction} from "../shell/PageHeader.tsx";
import {ProfileSwitcher, type ProfileOption} from "../shell/ProfileSwitcher.tsx";
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

// T-119, T-123: facts that are true, so the card draws a done step before P2 has a profile to count. Two steps are done, one is not.
const DONE_FACTS = {createProfile: true, enableFilter: true, addEndpoint: false, configureEndpoint: false};
// T-123: the switcher becomes a jump list above this many entries (JUMP_THRESHOLD of ProfileSwitcher.tsx).
const MANY = 12;

export function FeedbackShowcase() {
  const t = useTranslations("feedback.showcase");
  const dialog = useUrlDialog("ruleDialog");
  const [selected, setSelected] = useState(false);
  const [retries, setRetries] = useState(0);
  // A state-only frame that Escape and an outside click must not close (the reauth and TOTP steps of WP8).
  const [locked, setLocked] = useState(false);
  // The confirmation frame of T-486 with a body tall enough to scroll inside it.
  const [confirming, setConfirming] = useState(false);
  const error = new ApiError(503, "service_unavailable", REQUEST_ID);
  // T-115, T-116, T-123: the header of this page carries every control of spec 8.4, so the browser cases of the three rows have a page that
  // has them (the stubs of P1 have none). The echo is data for the test, not wording.
  const [query, setQuery] = useState("");
  const [lastAction, setLastAction] = useState("");
  const [created, setCreated] = useState(0);
  const few: ProfileOption[] = [
    {id: "home", name: t("profileOne")},
    {id: "office", name: t("profileTwo")},
    {id: "new", name: t("profileNew")},
  ];
  const many: ProfileOption[] = Array.from({length: MANY}, (_, i) => ({id: `p${i + 1}`, name: t("profileNumbered", {n: i + 1})}));
  const [fewValue, setFewValue] = useState("home");
  const [manyValue, setManyValue] = useState("p1");
  const actions: HeaderAction[] = [
    {id: "copy", label: t("copy"), icon: "copy", onAction: () => setLastAction("copy")},
    {id: "remove", label: t("remove"), icon: "trash", variant: "danger", onAction: () => setLastAction("remove")},
  ];
  const counters = (["filters", "services", "rules", "options"] as const).map((id, i) => ({
    id,
    label: t(`counters.${id}`),
    value: [12, 3, 1204, 7][i]!,
    href: `/profiles?tab=${id}`,
  }));

  return (
    <>
      <PageHeader
        icon="profiles"
        title={t("title")}
        subtitle={t("subtitle")}
        helpKey="profiles"
        leading={<ProfileSwitcher profiles={few} value={fewValue} onChange={setFewValue} />}
        onSearch={setQuery}
        actions={actions}
        onCreate={() => setCreated((n) => n + 1)}
        createLabel={t("createSample")}
      />
      <div className="flex flex-col gap-8 pb-10">
        <div hidden data-testid="header-echo" data-query={query} data-action={lastAction} data-created={created} data-profile={fewValue} />
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
            <Button variant="secondary" onPress={() => setConfirming(true)}>
              {t("openConfirm")}
            </Button>
          </div>
        </section>

        {/* Last, on purpose: the card appears when /me has answered, and anything above it would move the rows that rows.spec.ts measures before it clicks. */}
        <section aria-labelledby="fb-switcher" className="flex flex-col gap-2">
          <h2 id="fb-switcher" className="text-muted text-sm font-medium">
            {t("switcher")}
          </h2>
          <div className="flex flex-wrap items-center gap-3" data-testid="switcher-many" data-value={manyValue}>
            <ProfileSwitcher profiles={many} value={manyValue} onChange={setManyValue} />
          </div>
        </section>

        <section aria-labelledby="fb-onboarding" className="flex flex-col gap-2">
          <h2 id="fb-onboarding" className="text-muted text-sm font-medium">
            {t("onboarding")}
          </h2>
          <div data-testid="sample-onboarding">
            <OnboardingCard facts={DONE_FACTS} />
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

      <ConfirmFrame
        isOpen={confirming}
        onOpenChange={setConfirming}
        status="warning"
        title={t("confirmTitle")}
        footer={
          <Button slot="close" variant="tertiary">
            {t("confirmKeep")}
          </Button>
        }
      >
        <div className="flex flex-col gap-3" data-testid="confirm-body">
          {Array.from({length: LINES}, (_, i) => (
            <p key={i}>{t("dialogLine")}</p>
          ))}
        </div>
      </ConfirmFrame>

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
