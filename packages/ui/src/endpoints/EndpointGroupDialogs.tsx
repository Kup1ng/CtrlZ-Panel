"use client";

import {useCreateGroup, useDeleteGroup, useGroups, useRenameGroup} from "@ctrlz/api-client/hooks/endpoints.ts";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Checkbox, Description, FieldError, Input, Label, SearchField, TextField} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useMemo, useRef, useState} from "react";

import {DialogFrame} from "../dialog/DialogFrame.tsx";
import {parseEndpointGroupDialog} from "../dialog/dialogValues.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {AuthForm} from "../forms/AuthForm.tsx";
import {FormError} from "../forms/FormError.tsx";
import {cleanProse, nameLength} from "../forms/invisible.ts";
import {useApiForm} from "../forms/useApiForm.ts";
import {exceededCap} from "@ctrlz/api-client/hooks/limits.ts";
import {MAX_BATCH_IDS, MAX_NAME_LENGTH} from "./endpointModel.ts";
import {PartialListNotice} from "./PartialListNotice.tsx";
import {useAllEndpoints} from "./useAllEndpoints.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Spec p3 10 (T-229) and WF "Create Group": `endpointGroupDialog=create`, `=rename:<id>`, `=delete:<id>`. Create takes a name, a search box and
// a checklist of the Endpoints with the count of what is ticked; the ticked ones join the group in the same request. Delete keeps the
// Endpoints (they lose the group). The value is parsed (dialog/dialogValues.ts): one that is not one of the three opens nothing.

export function EndpointGroupDialogs() {
  const dialog = useUrlDialog("endpointGroupDialog");
  const parsed = parseEndpointGroupDialog(dialog.value);
  if (!parsed) return null;
  if (parsed.kind === "create") return <CreateGroupDialog onClose={dialog.close} />;
  return <GroupByIdDialog kind={parsed.kind} groupId={parsed.groupId} onClose={dialog.close} />;
}

function CreateGroupDialog({onClose}: {onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const create = useCreateGroup();
  const endpoints = useAllEndpoints();
  const form = useApiForm({focus: "name", fieldNamespace: "profiles"});
  const [name, setName] = useState("");
  const [query, setQuery] = useState("");
  const [ticked, setTicked] = useState<ReadonlySet<string>>(new Set());
  const busy = useRef(false);
  const rows = endpoints.endpoints;
  const shown = useMemo(() => {
    const needle = normalizeFaSearch(query.trim()).toLowerCase();
    return needle === "" ? rows : rows.filter((row) => normalizeFaSearch(row.name).toLowerCase().includes(needle));
  }, [rows, query]);

  async function submit() {
    if (busy.current || form.blocked) return;
    const clean = cleanProse(name);
    if (clean === "") return form.setFieldError("name", e("fields.required"));
    if (nameLength(clean) > MAX_NAME_LENGTH) return form.setFieldError("name", e("fields.too_long"));
    busy.current = true;
    form.clear();
    try {
      await create.mutateAsync({name: clean, ...(ticked.size > 0 ? {endpoint_ids: [...ticked]} : {})});
      onClose();
    } catch (error) {
      form.fail(error, {rename: {"/name": "name"}});
    } finally {
      busy.current = false;
    }
  }

  // `endpoint_ids` of a new group holds at most 500 (the API's maxItems), so the 501st tick is not taken and the box says why (S5-r3-7).
  const full = ticked.size >= MAX_BATCH_IDS;
  const toggle = (id: string, on: boolean) =>
    setTicked((prev) => {
      const next = new Set(prev);
      if (on && next.size < MAX_BATCH_IDS) next.add(id);
      else if (!on) next.delete(id);
      return next;
    });

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={create.isPending}
      title={t("dialogs.group.createTitle")}
      footer={
        <>
          <Button variant="tertiary" isDisabled={create.isPending} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={create.isPending} isDisabled={form.retryIn > 0} onPress={() => void submit()}>
            {t("dialogs.group.create")}
          </PrimaryButton>
        </>
      }
    >
      <AuthForm form={form} onSubmit={() => void submit()}>
        <TextField fullWidth name="name" value={name} isDisabled={create.isPending} isInvalid={form.fieldMessage("name") !== undefined} onChange={(v) => form.bind("name", setName).onChange(v)}>
          <Label>{t("dialogs.group.name")}</Label>
          <Input autoComplete="off" />
          <FieldError>{form.fieldMessage("name")}</FieldError>
        </TextField>
        <fieldset className="flex min-w-0 flex-col gap-2" disabled={create.isPending}>
          <legend className="text-sm font-medium">{t("dialogs.group.pick")}</legend>
          {endpoints.failed ? <PartialListNotice error={endpoints.error} onRetry={endpoints.retry} /> : null}
          <p className="text-muted text-xs">{t("dialogs.group.pickHint")}</p>
          {rows.length > 6 ? (
            <SearchField aria-label={t("dialogs.group.search")} value={query} onChange={setQuery}>
              <SearchField.Group>
                <SearchField.SearchIcon>
                  <Icon name="search" className="size-4" />
                </SearchField.SearchIcon>
                <SearchField.Input placeholder={t("dialogs.group.search")} />
                <SearchField.ClearButton />
              </SearchField.Group>
            </SearchField>
          ) : null}
          <ul className="bg-default max-h-56 overflow-y-auto rounded-(--radius-box) p-1">
            {shown.map((row) => (
              <li key={row.id}>
                <Checkbox
                  isSelected={ticked.has(row.id)}
                  onChange={(on) => toggle(row.id, on)}
                  name={`endpoint-${row.id}`}
                  isDisabled={full && !ticked.has(row.id)}
                  className="hover:bg-surface w-full rounded-(--radius-box) px-2 py-2"
                >
                  <Checkbox.Content>
                    <Checkbox.Control>
                      <Checkbox.Indicator />
                    </Checkbox.Control>
                    <span className="min-w-0 flex-1 truncate text-sm">{row.name}</span>
                  </Checkbox.Content>
                </Checkbox>
              </li>
            ))}
            {shown.length === 0 ? (
              <li className="text-muted p-3 text-sm">{rows.length === 0 ? t("dialogs.group.noEndpoints") : t("dialogs.group.noMatch")}</li>
            ) : null}
          </ul>
          <Description aria-live="polite">
            {t("dialogs.group.selected", {count: ticked.size})}
            {full ? ` ${t("dialogs.group.limit", {max: MAX_BATCH_IDS})}` : ""}
          </Description>
        </fieldset>
        <CapacityNotice error={form.formError} />
        <FormError error={form.formError !== null && exceededCap(form.formError) ? null : form.formError} form={form} onRetry={() => void submit()} />
      </AuthForm>
    </DialogFrame>
  );
}

function GroupByIdDialog({kind, groupId, onClose}: {kind: "rename" | "delete"; groupId: string; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const groups = useGroups();
  const group = groups.data?.find((g) => g.id === groupId);
  // A group that is not (or no longer) the tenant's: say so and let the person close it, instead of an empty dialog.
  if (groups.isPending) return null;
  // A groups list that failed to load says nothing about this group: the failure is shown, with Retry, and "gone" only when the list is read (S5-r3-4).
  if (!group && groups.isError) {
    return (
      <DialogFrame
        isOpen
        onClose={onClose}
        title={kind === "rename" ? t("dialogs.group.renameTitle") : t("list.groups.delete")}
        footer={
          <Button variant="tertiary" onPress={onClose}>
            {c("close")}
          </Button>
        }
      >
        <SectionError error={groups.error} onRetry={() => void groups.refetch()} />
      </DialogFrame>
    );
  }
  if (!group) {
    return (
      <DialogFrame
        isOpen
        onClose={onClose}
        title={kind === "rename" ? t("dialogs.group.renameTitle") : t("list.groups.delete")}
        footer={
          <PrimaryButton onPress={onClose}>
            {c("close")}
          </PrimaryButton>
        }
      >
        <p className="text-sm">{t("dialogs.group.gone")}</p>
      </DialogFrame>
    );
  }
  return kind === "rename" ? <RenameGroupDialog id={group.id} current={group.name} onClose={onClose} /> : <DeleteGroupDialog id={group.id} name={group.name} count={group.endpoint_count} onClose={onClose} />;
}

function RenameGroupDialog({id, current, onClose}: {id: string; current: string; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const rename = useRenameGroup();
  const form = useApiForm({focus: "name", fieldNamespace: "profiles"});
  const [name, setName] = useState(current);
  const busy = useRef(false);

  async function submit() {
    if (busy.current || form.blocked) return;
    const clean = cleanProse(name);
    if (clean === "") return form.setFieldError("name", e("fields.required"));
    if (nameLength(clean) > MAX_NAME_LENGTH) return form.setFieldError("name", e("fields.too_long"));
    if (clean === current) return onClose();
    busy.current = true;
    form.clear();
    try {
      await rename.mutateAsync({gid: id, name: clean});
      onClose();
    } catch (error) {
      form.fail(error, {rename: {"/name": "name"}});
    } finally {
      busy.current = false;
    }
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={rename.isPending}
      title={t("dialogs.group.renameTitle")}
      footer={
        <>
          <Button variant="tertiary" isDisabled={rename.isPending} onPress={onClose}>
            {c("cancel")}
          </Button>
          <PrimaryButton isPending={rename.isPending} isDisabled={form.retryIn > 0} onPress={() => void submit()}>
            {t("dialogs.group.rename")}
          </PrimaryButton>
        </>
      }
    >
      <AuthForm form={form} onSubmit={() => void submit()}>
        <TextField fullWidth name="name" value={name} isDisabled={rename.isPending} isInvalid={form.fieldMessage("name") !== undefined} onChange={(v) => form.bind("name", setName).onChange(v)}>
          <Label>{t("dialogs.group.name")}</Label>
          <Input autoComplete="off" />
          <FieldError>{form.fieldMessage("name")}</FieldError>
        </TextField>
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
      </AuthForm>
    </DialogFrame>
  );
}

function DeleteGroupDialog({id, name, count, onClose}: {id: string; name: string; count: number; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const c = useTranslations("common");
  const del = useDeleteGroup();
  const form = useApiForm({fieldNamespace: "profiles"});
  const busy = useRef(false);

  async function submit() {
    if (busy.current) return;
    busy.current = true;
    form.clear();
    try {
      await del.mutateAsync(id);
      onClose();
    } catch (error) {
      form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      isLocked={del.isPending}
      title={t("dialogs.group.deleteTitle", {name})}
      footer={
        <>
          <Button variant="tertiary" isDisabled={del.isPending} onPress={onClose}>
            {c("cancel")}
          </Button>
          <Button variant="danger" isPending={del.isPending} onPress={() => void submit()}>
            {t("dialogs.group.deleteConfirm")}
          </Button>
        </>
      }
    >
      <AuthForm form={form} onSubmit={() => void submit()}>
        <p className="text-sm">{t("dialogs.group.deleteText")}</p>
        <p className="text-muted text-xs">{t("list.groups.count", {count})}</p>
        <FormError error={form.formError} form={form} onRetry={() => void submit()} />
      </AuthForm>
    </DialogFrame>
  );
}
