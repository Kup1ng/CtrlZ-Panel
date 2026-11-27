"use client";

import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {tooManyLockPasswords} from "@ctrlz/api-client/hooks/lockPasswords.ts";
import {
  useCreateEndpoints,
  useCreateGroup,
  useEndpointTypes,
  useGroups,
  usePatchEndpoint,
  useRotateResolver,
  type AnalyticsLevel,
  type Endpoint,
  type EndpointCreate,
  type EndpointPatch,
} from "@ctrlz/api-client/hooks/endpoints.ts";
import {useProfiles} from "@ctrlz/api-client/hooks/profiles.ts";
import {newIdempotencyKey} from "@ctrlz/api-client/hooks/support.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {Link} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Alert, Button, buttonVariants, ComboBox, Description, Disclosure, FieldError, Input, Label, ListBox, TextArea, TextField, ToggleButton, ToggleButtonGroup, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useMemo, useRef, useState} from "react";

import {useDeviceDialog} from "../dialog/useDeviceDialog.ts";
import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanProse, nameLength} from "../forms/invisible.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {useOnlineStatus} from "../forms/useOnlineStatus.ts";
import {
  adminStateOf,
  checkNames,
  commentLength,
  emptiesStack,
  isDisabling,
  MAX_COMMENT_LENGTH,
  MAX_NAME_LENGTH,
  MAX_NAMES,
  parseNames,
  statusWord,
  turnsRequireOn,
  type StatusWord,
} from "./endpointModel.ts";
import {endpointHref} from "./endpointRoutes.ts";
import {EndpointTypeIcon, useTypeName} from "./EndpointTypeIcon.tsx";
import {SelectField, SwitchRow, type Choice} from "./fields.tsx";
import {Cancelled, useGuardedWrite} from "./useGuardedWrite.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";
import {FreeDnsLegacyOff} from "../freeDns/FreeDnsNotices.tsx";

// Spec p3 10, WF "Endpoints": the dialog that adds and edits an Endpoint (`deviceDialog=add`, `deviceDialog=edit` + `deviceId`).
//
//   Type (a menu with search)  Names (several, on add) or Name (edit)  Profile, with + for Profile 2  Analytics  Comment with a counter
//   Group with New group  [Advanced: Legacy DNS, Secure DNS, Dynamic DNS, Expose IP, and on edit Require Authorized IPs]
//   Edit also has: Status, the hold notice (D34), the Schedule clock, a new Resolver ID (Rotate) and Delete.
//
// A change that takes a locked profile off a device asks for its lock password in a state-only dialog, and one that makes destinations
// unavailable asks to confirm (useGuardedWrite). Prevent Deactivation is not drawn (T-495): the API keeps it, the screen has none.
// A created Endpoint opens its Resolvers dialog at once (T-218). The form is mounted only while the dialog is open, so it always
// starts from the Endpoint as it is.

const NEW_GROUP = "__new__";
const NO_GROUP = "__none__";
const OTHER_TYPE = "other_endpoint";

type Mode = {kind: "add"; defaultProfileId?: string} | {kind: "edit"; endpoint: Endpoint};

export function EndpointFormDialog({mode, onClose}: {mode: Mode; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const online = useOnlineStatus();
  const devices = useDeviceDialog();
  const edit = mode.kind === "edit" ? mode.endpoint : null;
  // The Endpoint as the person first saw it. The fields below start from it, so the diff of the PATCH and the status choices read it too: a
  // refetch (the first query turns Pending into Active, another tab renames it) must neither empty the Status select nor turn a field the
  // person never touched into a change of theirs (S5-r3-5). `edit` stays the live one for the held notice, the id and the lock ask.
  const [firstEdit] = useState(edit);
  const types = useEndpointTypes();
  const groups = useGroups();
  const profiles = useProfiles();
  const typeName = useTypeName(types.data);
  const create = useCreateEndpoints();
  const patch = usePatchEndpoint();
  const rotate = useRotateResolver();
  const createGroup = useCreateGroup();
  const guarded = useGuardedWrite();
  const form = useApiForm({focus: edit ? "name" : "names", fieldNamespace: "profiles"});
  // The rotation has its own form: its failure is shown in its own dialog and its Retry rotates, so it never reaches the Edit form's Retry (S5-r2-9).
  const rotateForm = useApiForm({fieldNamespace: "profiles"});
  const rotateBusy = useRef(false);
  const busy = useRef(false);
  // `confirmed`: the person already confirmed the lost destinations of this request, so a retry sends the confirmation with the first try and the
  // body is the one the server stored under the key (S5-r2-11).
  const lastCreate = useRef<{body: string; key: string; confirmed: boolean} | null>(null);

  const typeList = useMemo(() => [...(types.data ?? [])].sort((a, b) => a.position - b.position), [types.data]);
  const [typeKey, setTypeKey] = useState<string | null>(edit?.type ?? null);
  const [namesText, setNamesText] = useState("");
  const [name, setName] = useState(edit?.name ?? "");
  const [profileId, setProfileId] = useState<string | null>(edit?.profile_id ?? (mode.kind === "add" ? (mode.defaultProfileId ?? null) : null));
  const [profile2Id, setProfile2Id] = useState<string | null>(edit?.profile2_id ?? null);
  const [analytics, setAnalytics] = useState<AnalyticsLevel>(edit?.analytics_level ?? "full");
  const [comment, setComment] = useState(edit?.comment ?? "");
  const [groupId, setGroupId] = useState<string>(edit?.group_id ?? NO_GROUP);
  const [newGroupName, setNewGroupName] = useState("");
  const [status, setStatus] = useState<StatusWord>(edit ? statusWord(edit) : "pending");
  const [legacy, setLegacy] = useState(edit?.legacy_dns ?? false);
  const [secureDns, setSecureDns] = useState(edit?.authorize_secure_dns ?? false);
  const [ddns, setDdns] = useState(edit?.authorize_ddns ?? false);
  const [exposeIp, setExposeIp] = useState(edit?.expose_ip ?? false);
  const [requireIps, setRequireIps] = useState(edit?.require_authorized_ips ?? false);
  const [addingGroup, setAddingGroup] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [pending, setPending] = useState(false);

  // What shows before the person chooses: the catalogue's own "other" type (migration 0076 names it other_endpoint), else the first. A person who
  // has not touched the field sees the same value that is sent.
  const effectiveType = typeKey ?? (firstEdit ? firstEdit.type : (typeList.find((x) => x.key === OTHER_TYPE) ?? typeList[0])?.key ?? null);
  const effectiveProfile = profileId ?? (firstEdit ? firstEdit.profile_id : (profiles.data?.[0]?.id ?? null));
  const names = parseNames(namesText);

  const profileChoices: Choice[] = (profiles.data ?? []).map((p) => ({
    id: p.id,
    textValue: p.name,
    label: p.locked ? t("dialogs.fields.profileLocked", {name: p.name}) : p.name,
  }));
  const groupChoices: Choice[] = [
    {id: NO_GROUP, textValue: t("dialogs.fields.noGroup"), label: t("dialogs.fields.noGroup")},
    ...(groups.data ?? []).map((g) => ({id: g.id, textValue: g.name, label: g.name})),
    {id: NEW_GROUP, textValue: t("dialogs.fields.newGroup"), label: t("dialogs.fields.newGroup")},
  ];

  const typeItems = typeList.map((x) => ({id: x.key, name: typeName(x.key), icon: x.icon}));

  function fail(error: unknown) {
    if (error instanceof Cancelled) return;
    // A pointer of the server is a field of this form under another name (/names/3 is the names box).
    const rename: Record<string, string> = {
      "/names": "names",
      "/name": "name",
      "/type": "type",
      "/profile_id": "profile",
      "/profile2_id": "profile2",
      "/comment": "comment",
      "/group_id": "group",
      "/admin_state": "status",
      "/require_authorized_ips": "requireIps",
    };
    for (let i = 0; i < MAX_NAMES; i++) rename[`/names/${i}`] = "names";
    form.fail(error, {rename});
  }

  async function submit() {
    if (busy.current || form.blocked) return;
    const chosenType = effectiveType;
    if (!chosenType) return form.setFieldError("type", e("fields.required"));
    if (!effectiveProfile) return form.setFieldError("profile", e("fields.required"));
    const cleanComment = cleanProse(comment);
    if (commentLength(cleanComment) > MAX_COMMENT_LENGTH) return form.setFieldError("comment", e("fields.too_long"));
    if (profile2Id && profile2Id === effectiveProfile) return form.setFieldError("profile2", e("fields.same_profile"));
    if (groupId === NEW_GROUP) return form.setFieldError("group", e("fields.required"));

    if (edit) {
      const cleanName = cleanProse(name);
      if (cleanName === "") return form.setFieldError("name", e("fields.required"));
      if (nameLength(cleanName) > MAX_NAME_LENGTH) return form.setFieldError("name", e("fields.too_long"));
      const was = firstEdit ?? edit;
      const body: EndpointPatch = {};
      const clear: NonNullable<EndpointPatch["clear"]> = [];
      if (cleanName !== was.name) body.name = cleanName;
      if (chosenType !== was.type) body.type = chosenType;
      if (effectiveProfile !== was.profile_id) body.profile_id = effectiveProfile;
      if (profile2Id !== (was.profile2_id ?? null)) {
        if (profile2Id) body.profile2_id = profile2Id;
        else clear.push("profile2_id");
      }
      if (analytics !== was.analytics_level) body.analytics_level = analytics;
      if (cleanComment !== (was.comment ?? "")) {
        if (cleanComment) body.comment = cleanComment;
        else clear.push("comment");
      }
      if (groupId !== (was.group_id ?? NO_GROUP)) {
        if (groupId !== NO_GROUP) body.group_id = groupId;
        else clear.push("group_id");
      }
      const nextState = adminStateOf(status);
      if (nextState !== was.admin_state) body.admin_state = nextState;
      if (legacy !== was.legacy_dns) body.legacy_dns = legacy;
      if (secureDns !== was.authorize_secure_dns) body.authorize_secure_dns = secureDns;
      if (ddns !== was.authorize_ddns) body.authorize_ddns = ddns;
      if (exposeIp !== was.expose_ip) body.expose_ip = exposeIp;
      if (requireIps !== was.require_authorized_ips) body.require_authorized_ips = requireIps;
      if (clear.length > 0) body.clear = clear;
      if (Object.keys(body).length === 0) return onClose();
      busy.current = true;
      setPending(true);
      form.clear();
      try {
        await guarded.run((extra) => patch.mutateAsync({id: edit.id, ...body, ...extra}), [edit], {
          // What the write does to the stack is read from the live Endpoint and what is sent, not from the first copy.
          takesAll: emptiesStack(edit, {admin_state: body.admin_state ?? edit.admin_state, require_authorized_ips: body.require_authorized_ips ?? edit.require_authorized_ips}),
          reset: patch.reset,
        });
        toast.success(t("dialogs.edit.saved"));
        onClose();
      } catch (error) {
        fail(error);
      } finally {
        busy.current = false;
        setPending(false);
      }
      return;
    }

    const problem = checkNames(names);
    if (problem) return form.setFieldError("names", e(`fields.${problem}`));
    const body: EndpointCreate = {
      type: chosenType,
      names,
      profile_id: effectiveProfile,
      ...(profile2Id ? {profile2_id: profile2Id} : {}),
      ...(groupId !== NO_GROUP ? {group_id: groupId} : {}),
      analytics_level: analytics,
      ...(cleanComment ? {comment: cleanComment} : {}),
      legacy_dns: legacy,
      authorize_secure_dns: secureDns,
      authorize_ddns: ddns,
      expose_ip: exposeIp,
    };
    // One key for one action: a retry of the same request replays it, and a request that changed gets a key of its own.
    const signature = JSON.stringify(body);
    const same = lastCreate.current?.body === signature ? lastCreate.current : null;
    const key = same ? same.key : newIdempotencyKey();
    const mine = {body: signature, key, confirmed: same?.confirmed ?? false};
    lastCreate.current = mine;
    busy.current = true;
    setPending(true);
    form.clear();
    try {
      const made = await guarded.run((extra) => {
        if (extra.confirm_destinations) mine.confirmed = true;
        return create.mutateAsync({key, ...body, ...extra, ...(mine.confirmed ? {confirm_destinations: true} : {})});
      }, [], {reset: create.reset});
      toast.success(made.length > 1 ? t("dialogs.add.createdMany", {count: made.length}) : t("dialogs.add.created"));
      // T-218: the Resolvers dialog of the first one opens by itself, in the place of this one.
      if (made[0]) devices.open("resolvers", made[0].id);
      else onClose();
    } catch (error) {
      fail(error);
    } finally {
      busy.current = false;
      setPending(false);
    }
  }

  async function makeGroup() {
    const clean = cleanProse(newGroupName);
    if (clean === "") return form.setFieldError("group", e("fields.required"));
    if (nameLength(clean) > MAX_NAME_LENGTH) return form.setFieldError("group", e("fields.too_long"));
    try {
      const group = await createGroup.mutateAsync({name: clean});
      setGroupId(group.id);
      setAddingGroup(false);
      setNewGroupName("");
    } catch (error) {
      fail(error);
    }
  }

  function closeRotate() {
    rotateForm.clear();
    setRotateOpen(false);
  }

  async function rotateNow() {
    if (!edit || rotateBusy.current || rotateForm.blocked) return;
    rotateBusy.current = true;
    rotateForm.clear();
    try {
      await guarded.run((extra) => rotate.mutateAsync({id: edit.id, ...(extra.lock_passwords ? {lockPasswords: extra.lock_passwords} : {})}), [edit], {takesAll: true, reset: rotate.reset});
      closeRotate();
      toast.success(t("dialogs.edit.rotate.done"));
    } catch (error) {
      // Cancel on a password or a confirmation ends the rotation. Any other failure stays in this dialog, with a Retry that rotates.
      if (error instanceof Cancelled) closeRotate();
      else rotateForm.fail(error);
    } finally {
      rotateBusy.current = false;
    }
  }

  const heldHere = edit?.admin_hold === true;
  const statusChoices: Choice[] = firstEdit
    ? [
        {id: firstEdit.status === "pending" ? "pending" : "active", textValue: t(`status.${firstEdit.status}`), label: t(`status.${firstEdit.status}`)},
        {id: "soft_disabled", textValue: t("state.soft_disabled"), label: t("state.soft_disabled")},
        {id: "hard_disabled", textValue: t("state.hard_disabled"), label: t("state.hard_disabled")},
      ]
    : [];
  // The warnings of a write that empties the stack of every identity (p3 3.3): a move into Soft or Hard Disabled from any other state,
  // and Require Authorized IPs turned on. The same rule decides the lock ask above.
  const disabling = firstEdit ? isDisabling(firstEdit.admin_state, adminStateOf(status)) : false;
  const requireOn = firstEdit ? turnsRequireOn(firstEdit.require_authorized_ips, requireIps) : false;
  const tooMany = form.formError !== null && tooManyLockPasswords(form.formError);
  const capped = form.formError !== null && exceededCap(form.formError) !== null;
  const title = edit ? t("dialogs.edit.title", {name: edit.name}) : t("dialogs.add.title");

  return (
    <>
      <DialogFrame
        isOpen
        onClose={onClose}
        isLocked={pending}
        title={title}
        className="sm:max-w-[480px]"
        footer={
          <div className="flex w-full flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {edit ? (
                <Button
                  variant="danger-soft"
                  isDisabled={pending || heldHere}
                  aria-label={t("dialogs.edit.deleteAria", {name: edit.name})}
                  onPress={() => devices.open("delete", edit.id)}
                >
                  <Icon name="trash" className="size-4" />
                  {c("delete")}
                </Button>
              ) : null}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="tertiary" isDisabled={pending} onPress={onClose}>
                {c("cancel")}
              </Button>
              <PrimaryButton
                isPending={pending}
                isDisabled={!online || form.retryIn > 0}
                onPress={() => void submit()}
              >
                {edit ? t("dialogs.edit.submit") : t("dialogs.add.submit")}
              </PrimaryButton>
            </div>
          </div>
        }
      >
        <AuthForm form={form} onSubmit={() => void submit()}>
          {heldHere ? (
            <Alert status="warning" role="status">
              <Alert.Indicator />
              <Alert.Content>
                <Alert.Description>{t("dialogs.edit.held")}</Alert.Description>
              </Alert.Content>
            </Alert>
          ) : null}
          <ComboBox
            aria-label={t("dialogs.fields.type")}
            variant="secondary"
            fullWidth
            name="type"
            isDisabled={pending}
            isInvalid={form.fieldMessage("type") !== undefined}
            defaultItems={typeItems}
            selectedKey={effectiveType}
            onSelectionChange={(key) => {
              if (key !== null) form.bind("type", setTypeKey).onChange(String(key));
            }}
            defaultFilter={(text, input) => normalizeFaSearch(text).toLowerCase().includes(normalizeFaSearch(input.trim()).toLowerCase())}
            menuTrigger="focus"
          >
            <Label>{t("dialogs.fields.type")}</Label>
            <ComboBox.InputGroup>
              <Input placeholder={t("dialogs.fields.typePlaceholder")} />
              <ComboBox.Trigger />
            </ComboBox.InputGroup>
            <FieldError>{form.fieldMessage("type")}</FieldError>
            <ComboBox.Popover>
              <ListBox renderEmptyState={() => <p className="text-muted p-3 text-sm">{t("dialogs.fields.typeEmpty")}</p>}>
                {(item: {id: string; name: string; icon: string}) => (
                  <ListBox.Item id={item.id} textValue={item.name}>
                    <EndpointTypeIcon icon={item.icon} className="size-5 shrink-0" />
                    {item.name}
                    <ListBox.ItemIndicator />
                  </ListBox.Item>
                )}
              </ListBox>
            </ComboBox.Popover>
          </ComboBox>

          {edit ? (
            <TextField
              fullWidth
              name="name"
              isDisabled={pending}
              isInvalid={form.fieldMessage("name") !== undefined}
              value={name}
              onChange={(v) => form.bind("name", setName).onChange(v)}
            >
              <Label>{t("dialogs.fields.name")}</Label>
              <Input autoComplete="off" />
              <FieldError>{form.fieldMessage("name")}</FieldError>
            </TextField>
          ) : (
            <TextField
              fullWidth
              name="names"
              isDisabled={pending}
              isInvalid={form.fieldMessage("names") !== undefined}
              value={namesText}
              onChange={(v) => form.bind("names", setNamesText).onChange(v)}
            >
              <Label>{t("dialogs.fields.names")}</Label>
              <TextArea rows={2} autoComplete="off" />
              <Description>
                {t("dialogs.fields.namesHint")} {names.length > 1 || names.length > MAX_NAMES ? t(names.length > MAX_NAMES ? "dialogs.fields.namesTooMany" : "dialogs.fields.namesCount", {count: names.length}) : ""}
              </Description>
              <FieldError>{form.fieldMessage("names")}</FieldError>
            </TextField>
          )}

          <div className="flex flex-col gap-2">
            <SelectField
              name="profile"
              label={t("dialogs.fields.profile")}
              placeholder={t("dialogs.fields.profilePlaceholder")}
              options={profileChoices}
              value={effectiveProfile}
              isDisabled={pending || profileChoices.length === 0}
              error={form.fieldMessage("profile")}
              description={profileChoices.length === 0 && !profiles.isPending ? t("dialogs.fields.noProfiles") : undefined}
              onChange={(v) => form.bind("profile", setProfileId).onChange(v)}
            />
            {profile2Id === null ? (
              <Button
                variant="tertiary"
                size="sm"
                className="self-start"
                isDisabled={pending || profileChoices.length < 2}
                onPress={() => setProfile2Id(profileChoices.find((p) => p.id !== effectiveProfile)?.id ?? null)}
              >
                <Icon name="plus" className="size-4" />
                {t("dialogs.fields.addProfileTwo")}
              </Button>
            ) : (
              <div className="flex flex-col gap-1">
                <SelectField
                  name="profile2"
                  label={t("dialogs.fields.profileTwo")}
                  options={profileChoices.filter((p) => p.id !== effectiveProfile)}
                  value={profile2Id}
                  isDisabled={pending}
                  error={form.fieldMessage("profile2")}
                  description={t("dialogs.fields.profileTwoHint")}
                  onChange={(v) => form.bind("profile2", setProfile2Id).onChange(v)}
                />
                <Button variant="tertiary" size="sm" className="self-start" isDisabled={pending} onPress={() => setProfile2Id(null)}>
                  <Icon name="close" className="size-4" />
                  {t("dialogs.fields.removeProfileTwo")}
                </Button>
              </div>
            )}
          </div>

          <div className="flex flex-col gap-2">
            <span className="text-sm font-medium" id="analytics-label">
              {t("dialogs.fields.analytics")}
            </span>
            <ToggleButtonGroup
              aria-labelledby="analytics-label"
              selectionMode="single"
              disallowEmptySelection
              isDisabled={pending}
              selectedKeys={[analytics]}
              onSelectionChange={(keys) => {
                const next = [...keys][0];
                if (typeof next === "string") setAnalytics(next as AnalyticsLevel);
              }}
            >
              {(["none", "some", "full"] as const).map((level, index) => (
                <ToggleButton key={level} id={level} className="min-w-0 flex-1">
                  {index > 0 ? <ToggleButtonGroup.Separator /> : null}
                  {t(`dialogs.fields.analytics${level === "none" ? "None" : level === "some" ? "Some" : "Full"}`)}
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
            <p className="text-muted text-xs">{t(`dialogs.fields.analyticsHint.${analytics}`)}</p>
          </div>

          <TextField
            fullWidth
            name="comment"
            isDisabled={pending}
            isInvalid={form.fieldMessage("comment") !== undefined}
            value={comment}
            onChange={(v) => form.bind("comment", setComment).onChange(v)}
          >
            <Label>
              {t("dialogs.fields.comment")} <span className="text-muted font-normal">({c("optional")})</span>
            </Label>
            <TextArea rows={2} autoComplete="off" />
            <Description className={commentLength(comment) > MAX_COMMENT_LENGTH ? "text-danger-soft-foreground" : undefined}>
              {t("dialogs.fields.commentCount", {count: commentLength(comment), max: MAX_COMMENT_LENGTH})}
            </Description>
            <FieldError>{form.fieldMessage("comment")}</FieldError>
          </TextField>

          <div className="flex flex-col gap-2">
            <SelectField
              name="group"
              label={t("dialogs.fields.group")}
              options={groupChoices}
              value={groupId}
              isDisabled={pending}
              error={form.fieldMessage("group")}
              onChange={(v) => {
                form.clearField("group");
                setGroupId(v);
                setAddingGroup(v === NEW_GROUP);
              }}
            />
            {addingGroup ? (
              <div className="bg-default flex flex-col gap-2 rounded-(--radius-box) p-3">
                <TextField fullWidth name="new-group" value={newGroupName} onChange={setNewGroupName} isDisabled={createGroup.isPending}>
                  <Label>{t("dialogs.fields.newGroupName")}</Label>
                  <Input autoComplete="off" />
                </TextField>
                <div className="flex flex-wrap items-center gap-2">
                  <Button size="sm" variant="secondary" isPending={createGroup.isPending} onPress={() => void makeGroup()}>
                    {t("dialogs.fields.newGroupCreate")}
                  </Button>
                  <Button
                    size="sm"
                    variant="tertiary"
                    onPress={() => {
                      setAddingGroup(false);
                      setGroupId(edit?.group_id ?? NO_GROUP);
                    }}
                  >
                    {t("dialogs.fields.newGroupCancel")}
                  </Button>
                </div>
              </div>
            ) : null}
          </div>

          {edit ? (
            <SelectField
              name="status"
              label={t("dialogs.fields.status")}
              options={statusChoices}
              value={status}
              isDisabled={pending}
              error={form.fieldMessage("status")}
              description={t(`dialogs.fields.statusHint.${status}`)}
              onChange={(v) => setStatus(v as StatusWord)}
            />
          ) : null}
          {disabling || requireOn ? (
            <Alert status="warning">
              <Alert.Indicator />
              <Alert.Content>
                {disabling ? <Alert.Description>{t(`dialogs.fields.statusHint.${status}`)}</Alert.Description> : null}
                {requireOn ? <Alert.Description>{t("dialogs.fields.requireIpsWarning")}</Alert.Description> : null}
              </Alert.Content>
            </Alert>
          ) : null}

          <Disclosure isExpanded={advancedOpen} onExpandedChange={setAdvancedOpen}>
            <Disclosure.Heading>
              <Button slot="trigger" variant="tertiary" size="sm" className="w-full justify-between">
                {t("dialogs.fields.advanced")}
                <Disclosure.Indicator />
              </Button>
            </Disclosure.Heading>
            <Disclosure.Content>
              <Disclosure.Body className="flex flex-col gap-4 pt-3">
                <SwitchRow label={t("dialogs.fields.legacy")} description={t("dialogs.fields.legacyHint")} isSelected={legacy} onChange={setLegacy} isDisabled={pending} />
                {edit?.legacy_dns && !legacy ? <FreeDnsLegacyOff /> : null}
                <SwitchRow label={t("dialogs.fields.secureDns")} description={t("dialogs.fields.secureDnsHint")} isSelected={secureDns} onChange={setSecureDns} isDisabled={pending} />
                <SwitchRow label={t("dialogs.fields.ddns")} description={t("dialogs.fields.ddnsHint")} isSelected={ddns} onChange={setDdns} isDisabled={pending} />
                <SwitchRow label={t("dialogs.fields.exposeIp")} description={t("dialogs.fields.exposeIpHint")} isSelected={exposeIp} onChange={setExposeIp} isDisabled={pending} />
                {edit ? (
                  <SwitchRow
                    label={t("dialogs.fields.requireIps")}
                    description={t("dialogs.fields.requireIpsHint")}
                    isSelected={requireIps}
                    onChange={(v) => form.bind("requireIps", setRequireIps).onChange(v)}
                    isDisabled={pending}
                    error={form.fieldMessage("requireIps")}
                  />
                ) : null}
              </Disclosure.Body>
            </Disclosure.Content>
          </Disclosure>

          {edit ? (
            <div className="flex flex-col gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Link
                  href={endpointHref(edit.id, "schedule")}
                  aria-label={t("dialogs.edit.scheduleAria", {name: edit.name})}
                  className={`${buttonVariants({variant: "tertiary", size: "sm"})} inline-flex items-center gap-1.5`}
                >
                  <Icon name="calendar" className="size-4" />
                  {t("dialogs.edit.schedule")}
                </Link>
                <Button size="sm" variant="tertiary" isDisabled={pending} aria-label={t("dialogs.edit.rotate.buttonAria", {name: edit.name})} onPress={() => setRotateOpen(true)}>
                  <Icon name="key" className="size-4" />
                  {t("dialogs.edit.rotate.button")}
                </Button>
              </div>
            </div>
          ) : null}

          <CapacityNotice error={form.formError} />
          <FormError error={capped ? null : form.formError} message={tooMany ? t("dialogs.locks.tooMany") : undefined} form={form} onRetry={() => void submit()} />
        </AuthForm>
      </DialogFrame>

      {edit ? (
        <DialogFrame
          isOpen={rotateOpen}
          onClose={closeRotate}
          isLocked={rotate.isPending}
          title={t("dialogs.edit.rotate.confirmTitle", {name: edit.name})}
          footer={
            <>
              <Button variant="tertiary" isDisabled={rotate.isPending} onPress={closeRotate}>
                {c("cancel")}
              </Button>
              <Button variant="danger" isPending={rotate.isPending} isDisabled={rotateForm.retryIn > 0 || !online} onPress={() => void rotateNow()}>
                {t("dialogs.edit.rotate.confirm")}
              </Button>
            </>
          }
        >
          <p className="text-sm">{t("dialogs.edit.rotate.confirmText")}</p>
          <FormError
            error={rotateForm.formError}
            message={rotateForm.formError !== null && tooManyLockPasswords(rotateForm.formError) ? t("dialogs.locks.tooMany") : undefined}
            form={rotateForm}
            onRetry={() => void rotateNow()}
          />
        </DialogFrame>
      ) : null}
      {guarded.dialogs}
    </>
  );
}
