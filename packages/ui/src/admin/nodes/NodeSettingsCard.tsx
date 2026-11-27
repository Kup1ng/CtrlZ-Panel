"use client";

import {nodeQueryOptions, usePatchNode, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {Button, Description, FieldError, Input, Label, Switch, TextField, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {cleanName, nameLength} from "../../forms/invisible.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {ConflictNote} from "../shared/ConflictNote.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {NodeCard} from "./NodeCard.tsx";

// `PATCH /nodes/{id}` (p4-nodes 9.2): the name and the proxy block. Both are `admin-fresh`, judge no table, and are one draft of a server
// value, so a name another admin changed meanwhile is a conflict (the switch is a boolean: a value both admins moved is the same value).

type Draft = {name: string; proxy_blocked: boolean};
const draftOf = (n: Pick<NodeView, "name" | "proxy_blocked">): Draft => ({name: n.name, proxy_blocked: n.proxy_blocked});
const sameDraft = (a: Draft, b: Draft) => a.name.trim() === b.name.trim() && a.proxy_blocked === b.proxy_blocked;
const NAME_MAX = 64;

export function NodeSettingsCard({node}: {node: NodeView}) {
  const t = useTranslations("nodes");
  const a = useTranslations("admin");
  const save = usePatchNode();
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  const {draft, edit, dirty, reset, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm<Draft>(draftOf(node), sameDraft);
  const conflicted = conflicts.length > 0;
  const busy = useRef(false);

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    const name = cleanName(draft.name);
    if (name === "" || nameLength(name) > NAME_MAX) return form.setFieldError("name", t("node.settings.nameRequired"));
    busy.current = true;
    form.clear();
    try {
      const next = {name, proxy_blocked: draft.proxy_blocked};
      const written = await write({options: nodeQueryOptions(node.id), pick: draftOf, seen: draftOf(node), same: sameDraft}, () => save.mutateAsync({id: node.id, ...next}));
      if (!written) return;
      saved(next);
      toast.success(t("node.settings.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <NodeCard title={t("node.settings.title")} testId="node-settings">
      <AuthForm form={form} onSubmit={() => void submit()}>
        <TextField
          name="name"
          variant="secondary"
          fullWidth
          autoComplete="off"
          isDisabled={pending}
          isInvalid={form.fieldMessage("name") !== undefined}
          value={draft.name}
          onChange={(value) => {
            edit({name: value});
            form.clearField("name");
          }}
        >
          <Label>{t("node.settings.name")}</Label>
          <Input maxLength={NAME_MAX} />
          <Description>{t("node.settings.nameHint")}</Description>
          <FieldError>{form.fieldMessage("name")}</FieldError>
        </TextField>
        {conflicts.includes("name") ? (
          <ConflictNote
            name="name"
            value={serverValue.name}
            onKeep={() => keepMine("name")}
            onUseServer={() => {
              takeServer("name");
              form.clearField("name");
            }}
          />
        ) : null}
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 flex-col">
            <span className="text-sm font-medium">{t("node.settings.proxyBlocked")}</span>
            <span className="text-muted text-xs">{t("node.settings.proxyBlockedHint")}</span>
          </div>
          <Switch name="proxy_blocked" aria-label={t("node.settings.proxyBlocked")} isSelected={draft.proxy_blocked} isDisabled={pending} onChange={(value) => edit({proxy_blocked: value})}>
            <Switch.Content>
              <Switch.Control>
                <Switch.Thumb />
              </Switch.Control>
            </Switch.Content>
          </Switch>
        </div>
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
            {form.retryIn > 0 ? a("settings.retryIn", {seconds: form.retryIn}) : t("node.settings.submit")}
          </PrimaryButton>
        </div>
      </AuthForm>
    </NodeCard>
  );
}
