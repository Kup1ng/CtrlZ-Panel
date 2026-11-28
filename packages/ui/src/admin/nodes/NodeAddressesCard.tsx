"use client";

import {nodeQueryOptions, usePutNodeAddresses, type NodeView} from "@ctrlz/api-client/admin/hooks/nodes.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useRef} from "react";

import {Tech} from "../../data/Tech.tsx";
import {isHandledError} from "../../feedback/handleApiError.ts";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError, OfflineNotice} from "../../forms/FormError.tsx";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";
import {ConflictNote} from "../shared/ConflictNote.tsx";
import {keepFocus} from "../shared/restoreFocus.ts";
import {useAdminForm} from "../shared/useAdminForm.ts";
import {useCheckedWrite} from "../shared/useCheckedWrite.ts";
import {useServerForm} from "../shared/useServerDraft.ts";
import {IpField} from "./IpField.tsx";
import {Facts, NodeCard} from "./NodeCard.tsx";
import {looksLikeIp} from "./nodeParts.ts";

// p4-nodes 4.5 and 9.2, `PUT /nodes/{id}/addresses`: the two advertised addresses of one node. The bind addresses were fixed at
// enrolment and are shown, not edited. The old address becomes an address given up (SC 8a.4) and a node in a pair queues a pair change,
// and the card says both before the admin saves. The pair of fields is one draft of a server value: another admin's edit made while this
// one is typing is a conflict, and the write reads the node again, also after the fresh-code dialog (`useCheckedWrite`).

type Draft = {dns_advertised_ip: string; proxy_advertised_ip: string};
const draftOf = (n: Pick<NodeView, "dns_advertised_ip" | "proxy_advertised_ip">): Draft => ({dns_advertised_ip: n.dns_advertised_ip ?? "", proxy_advertised_ip: n.proxy_advertised_ip ?? ""});
const sameDraft = (a: Draft, b: Draft) => a.dns_advertised_ip.trim() === b.dns_advertised_ip.trim() && a.proxy_advertised_ip.trim() === b.proxy_advertised_ip.trim();
const FIELDS = ["dns_advertised_ip", "proxy_advertised_ip"] as const;

export function NodeAddressesCard({node, inGlobalPair = false}: {node: NodeView; /** The node is in the global pair: free DNS users have set its address (SC 8a.4, Addresses given up). */ inGlobalPair?: boolean}) {
  const t = useTranslations("nodes");
  const a = useTranslations("admin");
  const save = usePutNodeAddresses();
  const {write, pending} = useCheckedWrite();
  const form = useAdminForm();
  const {draft, edit, dirty, reset, saved, conflicts, serverValue, keepMine, takeServer} = useServerForm<Draft>(draftOf(node), sameDraft);
  const conflicted = conflicts.length > 0;
  const busy = useRef(false);
  const revoked = node.status === "revoked";

  async function submit() {
    if (busy.current || form.blocked || !dirty || conflicted) return;
    const next = {dns_advertised_ip: draft.dns_advertised_ip.trim(), proxy_advertised_ip: draft.proxy_advertised_ip.trim()};
    // One field message at a time (setFieldError replaces the last): the first address that is wrong is the one said.
    const bad = FIELDS.find((f) => !looksLikeIp(next[f]));
    if (bad) return form.setFieldError(bad, t("node.addresses.invalid"));
    busy.current = true;
    form.clear();
    try {
      const written = await write({options: nodeQueryOptions(node.id), pick: draftOf, seen: draftOf(node), same: sameDraft}, () => save.mutateAsync({id: node.id, ...next}));
      if (!written) return;
      saved(next);
      toast.success(t("node.addresses.saved"));
    } catch (error) {
      if (!isHandledError(error)) form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  return (
    <NodeCard title={t("node.addresses.title")} description={t("node.addresses.text")} testId="node-addresses">
      {revoked ? (
        <p className="text-muted text-sm">{t("node.addresses.revoked")}</p>
      ) : (
        <AuthForm form={form} onSubmit={() => void submit()}>
          <Facts
            rows={[
              {id: "bind-dns", label: t("node.addresses.bindDns"), value: node.dns_bind_ip ? <Tech>{node.dns_bind_ip}</Tech> : t("nodes.noAddress")},
              {id: "bind-proxy", label: t("node.addresses.bindProxy"), value: node.proxy_bind_ip ? <Tech>{node.proxy_bind_ip}</Tech> : t("nodes.noAddress")},
            ]}
          />
          {FIELDS.map((field) => (
            <div key={field} className="flex flex-col gap-2">
              <IpField
                name={field}
                label={t(field === "dns_advertised_ip" ? "node.addresses.dns" : "node.addresses.proxy")}
                value={draft[field]}
                onChange={(value) => {
                  edit({[field]: value});
                  form.clearField(field);
                }}
                isDisabled={pending}
                error={form.fieldMessage(field)}
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
          <p className="text-muted flex items-start gap-2 text-sm" data-testid="addresses-note">
            <Icon name="info" className="mt-0.5 size-4 shrink-0" />
            <span>
              {node.pair_peer_id ? t("node.addresses.pairedNote") : t("node.addresses.freeNote")}
              {inGlobalPair ? <span className="block" data-testid="addresses-free-note">{t("node.addresses.globalNote")}</span> : null}
            </span>
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
              {form.retryIn > 0 ? a("settings.retryIn", {seconds: form.retryIn}) : t("node.addresses.submit")}
            </PrimaryButton>
          </div>
        </AuthForm>
      )}
    </NodeCard>
  );
}
