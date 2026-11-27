"use client";

import {Button} from "@heroui/react";
import {Segment} from "@heroui-pro/react";
import {isShareLive, useCreateShareLink, useRevokeShareLink, useShareLinks} from "@ctrlz/api-client/hooks/setup.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {useLockDialogWhile} from "../dialog/DialogLock.tsx";
import {CapacityNotice} from "../feedback/CapacityNotice.tsx";
import {FormError} from "../forms/FormError.tsx";
import {ClientPicker} from "./ClientPicker.tsx";
import {SecretCopyNote} from "./SecretCopyNote.tsx";
import {useReportSecretHold} from "./SecretHold.tsx";
import {SetupQr} from "./SetupQr.tsx";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

// Help Me Configure, "Copy Setup Link" (spec p3 7.2, T-241, T-244): a link to the setup of this Endpoint that works with no account, for a
// person who sets up a device that is not yours to sign in on. It lives 24 hours by default, spends one use per opening, and ends when
// the Endpoint's resolver is rotated or the link is revoked here.
//
// The URL is shown once: it comes back from the create call, stays in this component's state and in nothing else (not the address, not
// a cache, not storage), and goes with the dialog. The list under it holds no value, only when each link ends and how often it was
// used, which is all the API gives back later.
//
// Because the URL cannot be had again, the form is locked while a link is shown and while one is being made: a change of the client or the
// lifetime would otherwise hide the only copy of a link that stays live and counts toward the cap, or show a link under a client it was not
// made for. "Make another link" is the deliberate way to a new one. The dialog is held open while the create runs (wp9-r1-2), since its answer
// is a one-time secret, and a link that is revoked from the list below is taken off the screen with it. The Back button of the flow is held too
// (SecretHold.tsx), and asks before it drops a link that is shown.

const TTLS = [
  {id: "1", hours: 1},
  {id: "24", hours: 24},
  {id: "168", hours: 168},
] as const;

export function ShareLinkPanel({endpointId, endpointName, initialClient = ""}: {endpointId: string; endpointName: string; initialClient?: string}) {
  const t = useTranslations("setup");
  const format = useAppFormat();
  const [client, setClient] = useState(initialClient);
  const [ttl, setTtl] = useState<string>("24");
  const [created, setCreated] = useState<{url: string; expiresAt: string; id: string; key: string} | null>(null);
  const create = useCreateShareLink();
  const revoke = useRevokeShareLink();
  const links = useShareLinks(endpointId);
  // The time the dialog opened: a link that ends while it is open is still listed until the list is read again, and Revoke then answers it.
  const [openedAt] = useState(() => Date.now());
  useLockDialogWhile(create.isPending);
  const live = (links.data ?? []).filter((l) => isShareLive(l, openedAt));

  async function make() {
    try {
      const key = `${client}|${ttl}`;
      const result = await create.mutateAsync({endpointId, client: client || undefined, ttlHours: Number(ttl)});
      setCreated({url: result.url, expiresAt: result.link.expires_at, id: result.link.id, key});
    } catch {
      // Drawn from `create.error` below.
    }
  }

  // The link on screen is the one for the client and lifetime selected now (the form is locked while it is shown, so this is a guard).
  const shown = created && created.key === `${client}|${ttl}` ? created : null;
  const locked = create.isPending || shown !== null;
  // The flow around this panel does not leave while the call runs, and asks before it leaves with the link on screen (S7-r2-2, S7-r2-9).
  useReportSecretHold(create.isPending, shown !== null);

  return (
    <div className="flex flex-col gap-4" data-testid="share-link-panel">
      <p className="text-muted text-sm">{t("link.intro")}</p>
      <ClientPicker endpointId={endpointId} value={client} onChange={setClient} label={t("link.client")} isDisabled={locked} />
      <div className="flex flex-col gap-1">
        <span className="text-sm font-medium">{t("link.lifetime")}</span>
        <Segment aria-label={t("link.lifetime")} selectedKey={ttl} onSelectionChange={(key) => setTtl(String(key))} size="sm" isDisabled={locked}>
          {TTLS.map((x) => (
            <Segment.Item key={x.id} id={x.id}>
              {t(`link.ttl.${x.id}`)}
            </Segment.Item>
          ))}
        </Segment>
      </div>

      <FormError error={create.error as unknown} onRetry={() => void make()} />
      <CapacityNotice error={create.error as unknown} />

      {shown ? (
        <div className="flex flex-col items-center gap-3" data-testid="share-link-result">
          <SetupQr value={shown.url} title={t("link.qrTitle")} />
          <div className="w-full text-start">
            <TechCopyRow label={t("link.copyLabel")} value={shown.url} secret hint={t("link.expires", {when: format.dateTime(shown.expiresAt)})} />
          </div>
          <p className="text-muted text-xs">{t("link.once")}</p>
          <SecretCopyNote />
          <Button variant="secondary" size="sm" onPress={() => setCreated(null)}>
            {t("link.another")}
          </Button>
        </div>
      ) : (
        <PrimaryButton fullWidth isPending={create.isPending} onPress={() => void make()}>
          <Icon name="link" className="size-4" />
          {t("link.create")}
        </PrimaryButton>
      )}

      <section aria-label={t("link.activeTitle")} className="flex flex-col gap-2">
        <h3 className="text-sm font-medium">{t("link.activeTitle")}</h3>
        {live.length === 0 ? (
          <p className="text-muted text-xs">{t("link.none")}</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {live.map((link) => (
              <li key={link.id} className="bg-default flex items-center justify-between gap-2 rounded-(--radius-box) px-3 py-2">
                <span className="flex min-w-0 flex-col text-xs">
                  <span>{t("link.expires", {when: format.dateTime(link.expires_at)})}</span>
                  <span className="text-muted">{t("link.uses", {uses: format.number(link.uses), max: format.number(link.max_uses)})}</span>
                </span>
                <Button
                  size="sm"
                  variant="tertiary"
                  isPending={revoke.isPending && revoke.variables?.shareId === link.id}
                  aria-label={t("link.revokeAria", {name: endpointName, when: format.dateTime(link.expires_at)})}
                  onPress={() =>
                    revoke.mutate(
                      {endpointId, shareId: link.id},
                      {onSuccess: () => setCreated((current) => (current?.id === link.id ? null : current))},
                    )
                  }
                >
                  {t("link.revoke")}
                </Button>
              </li>
            ))}
          </ul>
        )}
        <FormError error={revoke.error as unknown} />
      </section>
    </div>
  );
}
