"use client";

import {Accordion, Alert, buttonVariants, Description, Label, ListBox, Select, Switch} from "@heroui/react";
import {Segment} from "@heroui-pro/react";
import {useFolders} from "@ctrlz/api-client/hooks/rules.ts";
import {useCreateAppleProfile, useCreateShareAppleProfile, type AppleLink} from "@ctrlz/api-client/hooks/setup.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {useLockDialogWhile} from "../dialog/DialogLock.tsx";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {FormError} from "../forms/FormError.tsx";
import {
  EMPTY_APPLE_DRAFT,
  MAX_DOMAINS,
  MAX_SSIDS,
  domainProblem,
  draftKey,
  normalizeDomain,
  requestOf,
  shareParamsOf,
  ssidProblem,
  type AppleDraft,
} from "./appleModel.ts";
import {ClientPicker} from "./ClientPicker.tsx";
import {SecretCopyNote} from "./SecretCopyNote.tsx";
import {useReportSecretHold} from "./SecretHold.tsx";
import {SetupQr} from "./SetupQr.tsx";
import {TagListField} from "./TagListField.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// WF "Endpoints", the Apple profile: Advanced settings (Client ID, Exclude Wi-Fi, Exclude Domains or a folder, Exclude common domains,
// Prevent Disablement), then Download and a QR code (spec p3 7.3, T-245, T-246, T-250, T-251).
//
// The profile is not built here: `POST /endpoints/{id}/apple-profile` stores the request and answers a link that lives 15 minutes and
// serves 3 downloads. The link goes to the QR code and to the Download button, from this component's state alone: it is a secret of the
// screen (the profile it makes holds the DoH token) and is gone when the form changes or the dialog closes.
//
// The profile is unsigned (D27, T-251): the warning is on the screen before the link is made, not after, so nobody meets iOS's own
// "not signed" notice first. Prevent Disablement (`ProhibitDisablement`) is the profile's own key and is for supervised devices; it has
// nothing to do with D8's Prevent Deactivation (T-250).

export type AppleBuilderProps =
  /** `stale`: the Endpoint says a profile was downloaded and the resolver ID or the pair changed since (T-248): the person is told to build it again. */
  | {mode: "owner"; endpointId: string; profileId: string; client?: string; stale?: boolean}
  /** The share page: no session, so no client list and no folder. The link's own client (if it has one) is the profile's. */
  | {mode: "share"; link: string; client?: string};

/**
 * What keeps the page where it is when the link answers with an error. A plain navigation to `/p/<value>` that answers JSON (409, 404, 429, 503) would
 * unload the panel with the link in its state, and put a URL that may still be live in the history (S7-r2-8). `download` makes the browser save the
 * response, or fail the download, without leaving. An Apple touch device is the exception: there the answer is handled by its MIME type and is how a
 * profile reaches Settings, which a download attribute could turn into a file in Files, so it opens in a tab of its own and the panel stays.
 */
function downloadAttributes(): {download: string; rel: string} | {target: string; rel: string} {
  const touch =
    typeof navigator !== "undefined" && (/iP(hone|ad|od)/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1));
  return touch ? {target: "_blank", rel: "noreferrer"} : {download: "", rel: "noreferrer"};
}

export function AppleBuilder(props: AppleBuilderProps) {
  const t = useTranslations("setup");
  const format = useAppFormat();
  const owner = props.mode === "owner";
  const [draft, setDraft] = useState<AppleDraft>({...EMPTY_APPLE_DRAFT, client: props.client ?? ""});
  const [result, setResult] = useState<{link: AppleLink; key: string} | null>(null);
  const ownerCreate = useCreateAppleProfile();
  const shareCreate = useCreateShareAppleProfile();
  const folders = useFolders(owner ? props.profileId : undefined);
  const pending = ownerCreate.isPending || shareCreate.isPending;
  // The answer is a link that carries the DoH token: the dialog stays open until it lands (wp9-r1-2).
  useLockDialogWhile(pending);
  const error = (owner ? ownerCreate.error : shareCreate.error) as unknown;

  // A link made for an earlier form is not the one for this form: it is dropped the moment anything changes.
  const live = result && result.key === draftKey(draft) ? result.link : null;
  const change = (patch: Partial<AppleDraft>) => setDraft((d) => ({...d, ...patch}));
  // The flow around the builder does not leave while the call runs, and asks before it leaves with the link on screen (S7-r2-2, S7-r2-9).
  useReportSecretHold(pending, live !== null);

  async function create() {
    const key = draftKey(draft);
    try {
      const link = props.mode === "owner"
        ? await ownerCreate.mutateAsync({endpointId: props.endpointId, ...requestOf(draft)})
        : await shareCreate.mutateAsync({link: props.link, params: shareParamsOf(draft, props.client)});
      setResult({link, key});
    } catch {
      // The error is on the mutation and is drawn below.
    }
  }

  return (
    <div className="flex flex-col gap-4" data-testid="apple-builder">
      {props.mode === "owner" && props.stale ? (
        <Alert status="warning" role="note" data-testid="apple-stale">
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t("apple.staleTitle")}</Alert.Title>
            <Alert.Description>{t("apple.staleText")}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      <Segment
        aria-label={t("apple.protocol")}
        selectedKey={draft.protocol}
        onSelectionChange={(key) => change({protocol: key === "dot" ? "dot" : "doh"})}
        size="sm"
      >
        <Segment.Item id="doh">{t("resolvers.protocols.doh")}</Segment.Item>
        <Segment.Item id="dot">{t("resolvers.protocols.dot")}</Segment.Item>
      </Segment>

      <Accordion className="w-full" data-testid="apple-advanced">
        <Accordion.Item id="advanced">
          <Accordion.Heading>
            <Accordion.Trigger>
              {t("apple.advanced")}
              <Accordion.Indicator />
            </Accordion.Trigger>
          </Accordion.Heading>
          <Accordion.Panel>
            <Accordion.Body className="flex flex-col gap-4">
              {props.mode === "owner" ? (
                <ClientPicker endpointId={props.endpointId} value={draft.client} onChange={(client) => change({client})} label={t("apple.client")} />
              ) : null}
              <TagListField
                label={t("apple.ssids")}
                description={t("apple.ssidsHint")}
                items={draft.ssids}
                onChange={(ssids) => change({ssids})}
                max={MAX_SSIDS}
                check={(typed, list) => ({value: typed, problem: ssidProblem(typed, list)})}
              />
              <TagListField
                label={t("apple.domains")}
                description={t("apple.domainsHint")}
                items={draft.domains}
                onChange={(domains) => change({domains})}
                max={MAX_DOMAINS}
                tech
                check={(typed, list) => {
                  const value = normalizeDomain(typed);
                  return {value, problem: domainProblem(value, list)};
                }}
              />
              {props.mode === "owner" && folders.data && folders.data.length > 0 ? (
                <Select
                  variant="secondary"
                  fullWidth
                  value={draft.folderId || "none"}
                  onChange={(key) => change({folderId: key === "none" || typeof key !== "string" ? "" : key})}
                >
                  <Label>{t("apple.folder")}</Label>
                  <Select.Trigger>
                    <Select.Value />
                    <Select.Indicator />
                  </Select.Trigger>
                  <Description>{t("apple.folderHint")}</Description>
                  <Select.Popover>
                    <ListBox>
                      <ListBox.Item id="none" textValue={t("apple.folderNone")}>
                        {t("apple.folderNone")}
                        <ListBox.ItemIndicator />
                      </ListBox.Item>
                      {folders.data.map((f) => (
                        <ListBox.Item key={f.id} id={f.id} textValue={f.name}>
                          {f.name}
                          <ListBox.ItemIndicator />
                        </ListBox.Item>
                      ))}
                    </ListBox>
                  </Select.Popover>
                </Select>
              ) : null}
              <Switch isSelected={draft.excludeCommon} onChange={(on) => change({excludeCommon: on})}>
                <Switch.Content>
                  <Switch.Control>
                    <Switch.Thumb />
                  </Switch.Control>
                  <span className="flex flex-col">
                    <Label>{t("apple.common")}</Label>
                    <Description>{t("apple.commonHint")}</Description>
                  </span>
                </Switch.Content>
              </Switch>
              <Switch isSelected={draft.prohibitDisablement} onChange={(on) => change({prohibitDisablement: on})}>
                <Switch.Content>
                  <Switch.Control>
                    <Switch.Thumb />
                  </Switch.Control>
                  <span className="flex flex-col">
                    <Label>{t("apple.prohibit")}</Label>
                    <Description>{t("apple.prohibitHint")}</Description>
                  </span>
                </Switch.Content>
              </Switch>
            </Accordion.Body>
          </Accordion.Panel>
        </Accordion.Item>
      </Accordion>

      <Alert status="warning" role="note" data-testid="apple-unsigned">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>{t("apple.unsignedTitle")}</Alert.Title>
          <Alert.Description>{t("apple.unsignedText")}</Alert.Description>
        </Alert.Content>
      </Alert>

      <FormError error={error} onRetry={() => void create()} />
      <CapacityNotice error={error} />

      {live ? (
        <div className="flex flex-col items-center gap-3 text-center" data-testid="apple-result">
          <SetupQr value={live.url} title={t("apple.qrTitle")} />
          <p className="text-muted text-xs">{t("apple.qrHint")}</p>
          <a href={live.url} {...downloadAttributes()} className={buttonVariants({variant: "primary", fullWidth: true})} data-testid="apple-download">
            <Icon name="download" className="size-4" />
            {t("apple.download")}
          </a>
          <div className="w-full text-start">
            <TechCopyRow label={t("apple.linkLabel")} value={live.url} secret hint={t("apple.expires", {when: format.dateTime(live.expires_at)})} />
          </div>
          <SecretCopyNote />
        </div>
      ) : (
        <PrimaryButton fullWidth isPending={pending} onPress={() => void create()}>
          <Icon name="qr" className="size-4" />
          {t("apple.create")}
        </PrimaryButton>
      )}
    </div>
  );
}
