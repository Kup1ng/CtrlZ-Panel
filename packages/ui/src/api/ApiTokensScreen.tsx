"use client";

// /preferences/api (spec p3 6.4, 10, WF "Preferences", Plan T-315, T-320): the tokens of the account as rows (name, type, Allowed IPs, created, last use,
// and Copy, Edit, Delete), a "+" that makes one, and the link to the API documentation. Create and Edit need a live reauth, so the page sits inside
// a ReauthProvider; Delete is a confirmation. The value of a token is shown once, in the state-only dialog of TokenDialogs.tsx, and never again:
// the list holds the six-character prefix only, which is what Copy writes (it names the token in a log or a support message, and is not a secret).

import {capOf, useLimits} from "@ctrlz/api-client/hooks/limits.ts";
import {tokenState, useApiTokens, type ApiToken, type TokenState} from "@ctrlz/api-client/hooks/apiTokens.ts";
import {copyPlainText} from "@ctrlz/api-client/clipboard.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Link, useRouter} from "@ctrlz/i18n/navigation.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {Button, Chip, Skeleton, toast} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useState, type ReactNode} from "react";

import {ReauthProvider} from "../auth/ReauthDialog.tsx";
import {Tech} from "../data/Tech.tsx";
import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {PageHeader} from "../shell/PageHeader.tsx";
import {CreateTokenDialog, DeleteTokenDialog, EditTokenDialog} from "./TokenDialogs.tsx";
import {ALLOWED_SHOWN} from "./tokenModel.ts";
import {PrimaryButton} from "../forms/PrimaryButton.tsx";

const STATE_CHIP: Record<TokenState, {color: "success" | "warning" | "danger"; icon: "check" | "warning" | "error"}> = {
  live: {color: "success", icon: "check"},
  expired: {color: "warning", icon: "warning"},
  ended: {color: "danger", icon: "error"},
};

export function ApiTokensScreen() {
  const t = useTranslations("api");
  const router = useRouter();
  const tokens = useApiTokens();
  const limits = useLimits();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<ApiToken | null>(null);
  const [deleting, setDeleting] = useState<ApiToken | null>(null);
  const cap = capOf(limits.data, "max_api_tokens");

  return (
    <div data-screen="api-tokens">
      <PageHeader
        icon="api"
        title={t("title")}
        subtitle={t("subtitle")}
        helpKey="apiTokens"
        onCreate={() => setCreating(true)}
        createLabel={t("create.open")}
        actions={[{id: "docs", label: t("docs"), icon: "help", onAction: () => router.push("/docs/api")}]}
      />
      <ReauthProvider>
        <div className="flex w-full max-w-4xl flex-col gap-4 pb-8">
          <p className="text-muted text-sm">
            {t.rich("intro", {
              bearer: (chunks) => <Tech>{chunks}</Tech>,
              docs: (chunks) => (
                <Link href="/docs/api" className="text-foreground font-medium underline underline-offset-2">
                  {chunks}
                </Link>
              ),
            })}
          </p>
          {tokens.isPending ? (
            <div role="status" aria-busy="true" className="flex flex-col gap-2">
              <span className="sr-only">{t("loading")}</span>
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} aria-hidden className="h-24 w-full rounded-(--radius-box)" />
              ))}
            </div>
          ) : tokens.isError ? (
            <SectionError error={tokens.error} onRetry={() => void tokens.refetch()} />
          ) : tokens.data.length === 0 ? (
            <SectionEmpty
              size="md"
              icon="api"
              title={t("tokens.emptyTitle")}
              description={t("tokens.empty")}
              action={
                <PrimaryButton onPress={() => setCreating(true)}>
                  {t("create.open")}
                </PrimaryButton>
              }
            />
          ) : (
            <>
              <p className="text-muted text-xs" data-testid="token-count">
                {cap === undefined ? t("tokens.count", {count: tokens.data.length}) : t("tokens.countCap", {count: tokens.data.length, max: cap})}
              </p>
              <ul aria-label={t("tokens.list")} className="@container flex flex-col gap-2">
                {tokens.data.map((token) => (
                  <TokenRow key={token.id} token={token} onEdit={() => setEditing(token)} onDelete={() => setDeleting(token)} />
                ))}
              </ul>
            </>
          )}
        </div>
        <CreateTokenDialog isOpen={creating} onClose={() => setCreating(false)} />
        <EditTokenDialog token={editing} onClose={() => setEditing(null)} />
        <DeleteTokenDialog token={deleting} onClose={() => setDeleting(null)} />
      </ReauthProvider>
    </div>
  );
}

function Fact({label, children, testId}: {label: string; children: ReactNode; testId?: string}) {
  return (
    <div className="flex min-w-0 flex-row flex-wrap items-baseline gap-x-1.5 @5xl:flex-col @5xl:gap-0.5" data-testid={testId}>
      <dt className="text-muted text-xs">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

function TokenRow({token, onEdit, onDelete}: {token: ApiToken; onEdit: () => void; onDelete: () => void}) {
  const t = useTranslations("api");
  const c = useTranslations("common");
  const f = useAppFormat();
  // The row is drawn when the list is read: a token that crosses its day while the page is open shows as live until the next read, which is
  // the same moment the server's own answer would change.
  const [now] = useState(() => Date.now());
  const state = tokenState(token, now);
  const chip = STATE_CHIP[state];
  const shown = token.allowed_ips.slice(0, ALLOWED_SHOWN);
  const more = token.allowed_ips.length - shown.length;

  async function copyPrefix() {
    try {
      await copyPlainText(token.token_prefix);
      toast.success(c("copied"));
    } catch {
      toast.danger(c("copyFailed"));
    }
  }

  return (
    <li data-token={token.id} data-state={state} className="bg-surface grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-3 rounded-(--radius-box) px-4 py-3 @5xl:grid-cols-[auto_minmax(0,1fr)_auto_auto] @5xl:gap-x-4">
      <span aria-hidden="true" className="tile-11 bg-default text-foreground grid size-11 shrink-0 place-items-center text-xl">
        <Icon name="key" className="size-5" />
      </span>
      <div className="flex min-w-0 flex-col gap-1">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span dir="auto" className="min-w-0 truncate text-sm font-medium">
            {token.name}
          </span>
          <Chip size="sm" color={chip.color} variant="soft" data-testid="token-state">
            <Icon name={chip.icon} className="size-3.5" />
            {t(`state.${state}`)}
          </Chip>
        </div>
        <p className="text-muted truncate text-xs">
          <Tech>{`ctz_…${token.token_prefix}…`}</Tech>
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-0.5 @5xl:col-start-4 @5xl:row-start-1">
        <Button isIconOnly size="sm" variant="tertiary" aria-label={t("row.copy", {name: token.name})} onPress={() => void copyPrefix()}>
          <Icon name="copy" className="size-4" />
        </Button>
        <Button isIconOnly size="sm" variant="tertiary" aria-label={t("row.edit", {name: token.name})} onPress={onEdit}>
          <Icon name="edit" className="size-4" />
        </Button>
        <Button isIconOnly size="sm" variant="tertiary" aria-label={t("row.delete", {name: token.name})} onPress={onDelete}>
          <Icon name="trash" className="size-4" />
        </Button>
      </div>
      <dl className="col-span-3 flex flex-wrap gap-x-4 gap-y-1 @5xl:col-span-1 @5xl:col-start-3 @5xl:row-start-1 @5xl:grid @5xl:grid-cols-[repeat(5,minmax(6rem,auto))] @5xl:gap-y-2">
        <Fact label={t("row.type")} testId="token-kind">
          {t(`kind.${token.kind}`)}
        </Fact>
        <Fact label={t("row.allowed")} testId="token-allowed">
          {token.allowed_ips.length === 0 ? (
            t("row.anyAddress")
          ) : (
            <span title={token.allowed_ips.join(", ")} className="flex flex-wrap gap-x-1.5">
              {shown.map((entry) => (
                <Tech key={entry}>{entry}</Tech>
              ))}
              {more > 0 ? <span className="text-muted">{t("row.more", {count: more})}</span> : null}
            </span>
          )}
        </Fact>
        <Fact label={t("row.created")}>{f.dateTime(token.created_at)}</Fact>
        <Fact label={t("row.expires")} testId="token-expires">
          {f.dateTime(token.expires_at)}
        </Fact>
        <Fact label={t("row.lastUse")} testId="token-last-use">
          {token.last_used_at ? f.relative(token.last_used_at) : t("row.never")}
        </Fact>
      </dl>
    </li>
  );
}
