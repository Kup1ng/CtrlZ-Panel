"use client";

import {domainQueryOptions, TRANSITION_DAYS_DEFAULT, TRANSITION_DAYS_MAX, TRANSITION_DAYS_MIN, useDomainImpact, useSaveDomain, type DomainSettings} from "@ctrlz/api-client/admin/hooks/domain.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Card, Skeleton, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {IpField} from "../nodes/IpField.tsx";
import {ConflictNote} from "../shared/ConflictNote.tsx";
import {IntegerField} from "../shared/IntegerField.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {formProblems, liveZones, ltr, normaliseName, PLACEHOLDER, sameDomainDraft, startsTransition, transitionRunning, ZONE_PREFIX, type DomainValues, type NameProblem} from "./domainParts.ts";

// T-344, p4-nodes 10.4. The three values of the domain, with a placeholder for the shape of each: the DNS zone (`dns.` and a domain of the
// owner), the panel host and the admin host. Changing the zone from one to another starts a transition in which the nodes serve both
// zones for `transition_days`; the page shows what that touches (the Endpoints and the Apple profiles already made) before the admin
// saves, and says that the web tier changes only when the apply step is run on the server. A first set and a change of a host alone start
// no transition. The form is a draft of a server value: another admin's change made while this one is typing is a conflict, and the write
// reads the settings again, also after the fresh-code dialog (`useCheckedWrite`). An empty host asks for no host (the route clears the
// requested one and the host the server runs with keeps serving).

type Draft = DomainValues & {transition_days: number | undefined};
const draftOf = (s: Pick<DomainSettings, "dns_zone" | "panel_host" | "admin_host">): Draft => ({
  dns_zone: s.dns_zone ?? "",
  panel_host: s.panel_host ?? "",
  admin_host: s.admin_host ?? "",
  transition_days: TRANSITION_DAYS_DEFAULT,
});
const NAME_FIELDS = ["dns_zone", "panel_host", "admin_host"] as const;
type NameField = (typeof NAME_FIELDS)[number];

export function DomainForm({current}: {current: DomainSettings}) {
  const t = useTranslations("nodes");
  const a = useTranslations("admin");
  const format = useAppFormat();
  const save = useSaveDomain();
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  const {draft, edit, dirty, reset, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm<Draft>(draftOf(current), sameDomainDraft);
  const conflicted = conflicts.length > 0;
  const busy = useRef(false);

  const running = transitionRunning(current);
  const zoneNow = current.dns_zone;
  const changesZone = startsTransition(zoneNow, draft.dns_zone) && draft.dns_zone.trim() !== "";
  // The problems are read for the impact too: the numbers are asked for a zone that could be sent, not for one half typed.
  const problems = formProblems(draft, liveZones(current));
  const askImpact = changesZone && !problems.dns_zone && !running;
  const days = draft.transition_days;

  const problemText = (field: NameField, problem: NameProblem) => t(`domain.form.problem.${problem}`, {zone: ltr(normaliseName(draft.dns_zone) || zoneNow || PLACEHOLDER.dns_zone), field: t(`domain.form.${field}`), prefix: ltr(ZONE_PREFIX), example: ltr(PLACEHOLDER.dns_zone)});
  const message = (field: NameField): string | undefined => {
    const set = form.fieldMessage(field);
    if (set) return set;
    // A problem is said under the field once the admin has typed in it; an untouched field is not red.
    const p = problems[field];
    return p && normaliseName(draft[field]) !== normaliseName(serverValue[field]) ? problemText(field, p) : undefined;
  };

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    const zone = normaliseName(draft.dns_zone);
    if (zone === "") return form.setFieldError("dns_zone", t("domain.form.zoneRequired"));
    // One field message at a time: the first field that is wrong is the one said.
    const bad = NAME_FIELDS.find((field) => problems[field]);
    if (bad) return form.setFieldError(bad, problemText(bad, problems[bad]!));
    const range = t("domain.form.days.range", {min: format.number(TRANSITION_DAYS_MIN, {useGrouping: false}), max: format.number(TRANSITION_DAYS_MAX, {useGrouping: false})});
    if (changesZone && (days === undefined || !Number.isInteger(days) || days < TRANSITION_DAYS_MIN || days > TRANSITION_DAYS_MAX)) return form.setFieldError("transition_days", range);
    const panel = normaliseName(draft.panel_host);
    const admin = normaliseName(draft.admin_host);
    const body = {dns_zone: zone, ...(panel ? {panel_host: panel} : {}), ...(admin ? {admin_host: admin} : {}), transition_days: days ?? TRANSITION_DAYS_DEFAULT};
    busy.current = true;
    form.clear();
    try {
      const written = await write({options: domainQueryOptions(), pick: draftOf, seen: draftOf(current), same: sameDomainDraft}, () => save.mutateAsync(body));
      if (!written) return;
      saved({dns_zone: zone, panel_host: panel, admin_host: admin, transition_days: TRANSITION_DAYS_DEFAULT});
      toast.success(t("domain.form.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  const label = (field: NameField) => t(`domain.form.${field}`);
  return (
    <Card className="max-w-3xl gap-4 p-6" data-testid="domain-form">
      <Card.Header className="flex flex-col gap-1">
        <Card.Title className="text-base">{t("domain.form.title")}</Card.Title>
        <Card.Description>{t("domain.form.text")}</Card.Description>
      </Card.Header>
      <Card.Content className="flex flex-col gap-5">
        <AuthForm form={form} onSubmit={() => void submit()}>
          {NAME_FIELDS.map((field) => (
            <div key={field} className="flex flex-col gap-2">
              <IpField
                name={field}
                label={label(field)}
                description={t(`domain.form.hint.${field}`, {prefix: ltr(ZONE_PREFIX)})}
                placeholder={PLACEHOLDER[field]}
                value={draft[field]}
                onChange={(value) => {
                  edit({[field]: value} as Partial<Draft>);
                  form.clearField(field);
                }}
                isDisabled={pending || (field === "dns_zone" && running)}
                error={message(field)}
              />
              {conflicts.includes(field) ? (
                <ConflictNote
                  name={field}
                  value={serverValue[field]}
                  onKeep={() => keepMine(field)}
                  onUseServer={() => {
                    takeServer(field);
                    form.clearField(field);
                  }}
                />
              ) : null}
            </div>
          ))}
          {running ? (
            <p className="text-muted flex items-start gap-2 text-sm" data-testid="domain-transition-running">
              <Icon name="info" className="mt-0.5 size-4 shrink-0" />
              <span>{t("domain.form.running", {until: current.transition_until ? format.dateTime(current.transition_until) : ""})}</span>
            </p>
          ) : null}
          {changesZone && !running ? (
            <>
              <IntegerField
                name="transition_days"
                label={t("domain.form.days.label")}
                description={t("domain.form.days.hint", {min: format.number(TRANSITION_DAYS_MIN, {useGrouping: false}), max: format.number(TRANSITION_DAYS_MAX, {useGrouping: false})})}
                value={days}
                onChange={(value) => {
                  edit({transition_days: value});
                  form.clearField("transition_days");
                }}
                min={TRANSITION_DAYS_MIN}
                max={TRANSITION_DAYS_MAX}
                isDisabled={pending}
                error={form.fieldMessage("transition_days")}
                invalidMessage={t("domain.form.days.range", {min: format.number(TRANSITION_DAYS_MIN, {useGrouping: false}), max: format.number(TRANSITION_DAYS_MAX, {useGrouping: false})})}
                className="max-w-64"
              />
              <Impact enabled={askImpact} days={days} />
            </>
          ) : null}
          <p className="text-muted flex items-start gap-2 text-sm" data-testid="domain-apply-note">
            <Icon name="info" className="mt-0.5 size-4 shrink-0" />
            <span>{t("domain.form.applyNote")}</span>
          </p>
          <FormError error={form.formError} onRetry={() => keepFocus(() => submit())} />
          <OfflineNotice />
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              variant="tertiary"
              isDisabled={!dirty || pending}
              onPress={() => {
                form.clear();
                reset();
              }}
            >
              {a("settings.cancel")}
            </Button>
            <PrimaryButton type="submit" isPending={pending} isDisabled={!dirty || conflicted || form.retryIn > 0}>
              {form.retryIn > 0 ? a("settings.retryIn", {seconds: form.retryIn}) : t("domain.form.submit")}
            </PrimaryButton>
          </div>
        </AuthForm>
      </Card.Content>
    </Card>
  );
}

/** What a change of zone touches, asked fresh from the server when the zone typed could be sent. */
function Impact({enabled, days}: {enabled: boolean; days: number | undefined}) {
  const t = useTranslations("nodes");
  const format = useAppFormat();
  const impact = useDomainImpact(enabled);
  if (!enabled) return null;
  return (
    <section aria-labelledby="domain-impact-title" className="bg-surface-secondary flex flex-col gap-2 rounded-(--radius-box) p-4" data-testid="domain-impact">
      <h3 id="domain-impact-title" className="text-sm font-medium">
        {t("domain.impact.title")}
      </h3>
      {impact.isPending ? (
        <Skeleton className="h-10 w-full rounded-(--radius-box)" />
      ) : impact.data ? (
        <>
          <p className="text-sm">
            {t("domain.impact.counts", {endpoints: format.number(impact.data.endpoints), profiles: format.number(impact.data.apple_profiles)})}
          </p>
          <p className="text-muted text-sm">{t("domain.impact.text", {days: days === undefined ? "" : format.number(days)})}</p>
        </>
      ) : (
        <div role="alert" className="flex flex-col items-start gap-2 text-sm" data-testid="domain-impact-failed">
          <span>{t("domain.impact.failed")}</span>
          <Button size="sm" variant="tertiary" onPress={() => void impact.refetch()}>
            {t("domain.impact.retry")}
          </Button>
        </div>
      )}
    </section>
  );
}
