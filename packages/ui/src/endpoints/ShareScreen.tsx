"use client";

import {hasCode, isApiError} from "@ctrlz/api-client/errors.ts";
import {openShare, type ShareView} from "@ctrlz/api-client/hooks/setup.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Logo} from "@ctrlz/icons/generated/brand/Logo.tsx";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {SubIcon} from "@ctrlz/icons/SubIcon.tsx";
import {Button, Card, Skeleton} from "@heroui/react";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useRef, useState, type ReactNode} from "react";

import {SectionEmpty} from "../feedback/SectionEmpty.tsx";
import {SectionError} from "../feedback/SectionError.tsx";
import {ShareSetup} from "../setup/ShareSetup.tsx";
import {ShareCorner} from "./ShareCorner.tsx";
import {isKnownShareType, shareTypeIcon} from "./shareTypes.ts";

// /s/[token] (spec p3 7.2, 10, Plan T-244): the setup page that a share link opens, with no shell, no session and no way to anything else of the
// account. The link's value is the last segment of the address, which this page reads once and sends in the BODY of `POST /public/share`
// (never in a query, a header of ours or a key); the page's own address is the only place it is ever written, and the document says
// `noindex` and `no-referrer` (the page file), so it leaves no trace in another site's log.
//
// Opening spends one use of the link, so it is asked ONCE per page load: no refetch on focus, no automatic retry, no second call from a
// remount (a ref holds it, and React's development double effect cannot spend two). A button asks again after a failure, which is the
// visitor's own act. A link that does not screen is shown the same "does not work" without a request, since the server would answer the same
// 404 and charge nothing (spec 7.1).
//
// The server gives one 404 for every dead link (unknown, expired, revoked, used up, the Endpoint gone, the account not active), so that a
// visitor cannot probe which; the page says all the reasons in one sentence and cannot tell them apart either. A 409 `setup_unavailable`
// spends no use and has its own words. Anything else (a busy server, a dropped connection) is a plain error with Retry.

const SHAPE = /^[A-Za-z0-9_-]{64}$/;

type State = {kind: "loading"} | {kind: "ready"; share: ShareView} | {kind: "gone"} | {kind: "unavailable"} | {kind: "error"; error: unknown};

/** `token` is the last segment of the address: the share link's value, a secret. Do not log it, store it, or put it in a query key. */
export function ShareScreen({token}: {token: string}) {
  const t = useTranslations("setup");
  const c = useTranslations("common");
  const [state, setState] = useState<State>(() => (SHAPE.test(token) ? {kind: "loading"} : {kind: "gone"}));
  const asked = useRef(false);

  const open = useCallback(async () => {
    try {
      setState({kind: "ready", share: await openShare(token)});
    } catch (error) {
      if (hasCode(error, "not_found")) setState({kind: "gone"});
      else if (hasCode(error, "setup_unavailable")) setState({kind: "unavailable"});
      else setState({kind: "error", error});
    }
  }, [token]);

  const again = () => {
    setState({kind: "loading"});
    void open();
  };

  useEffect(() => {
    if (asked.current || !SHAPE.test(token)) return;
    asked.current = true;
    void open();
  }, [open, token]);

  return (
    <main data-screen="share" id="main-content" tabIndex={-1} className="mx-auto flex min-h-dvh w-full max-w-xl flex-col gap-5 px-4 pt-4 pb-10 outline-none">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Logo aria-hidden className="size-8" />
          <span className="text-base font-semibold">{c("appName")}</span>
        </div>
        <ShareCorner />
      </div>
      {state.kind === "loading" ? <Loading /> : null}
      {state.kind === "ready" ? <Ready link={token} share={state.share} /> : null}
      {state.kind === "gone" ? (
        <Notice>
          <SectionEmpty size="md" icon="link" title={t("share.notFoundTitle")} description={t("share.notFoundText")} />
        </Notice>
      ) : null}
      {state.kind === "unavailable" ? (
        <Notice>
          <SectionEmpty
            size="md"
            icon="warning"
            title={t("share.notReadyTitle")}
            description={t("share.notReadyText")}
            action={
              <Button variant="secondary" onPress={again}>
                {c("retry")}
              </Button>
            }
          />
        </Notice>
      ) : null}
      {state.kind === "error" ? (
        <Notice>
          <SectionError error={isApiError(state.error) ? state.error : new TypeError("share")} onRetry={again} />
        </Notice>
      ) : null}
    </main>
  );
}

/** A state with no Endpoint to show: the page still has its heading, which names the page and not the Endpoint. */
function Notice({children}: {children: ReactNode}) {
  const t = useTranslations("setup");
  return (
    <Card className="gap-4 p-6">
      <h1 className="sr-only">{t("share.title")}</h1>
      {children}
    </Card>
  );
}

function Loading() {
  const t = useTranslations("setup");
  const c = useTranslations("common");
  return (
    <div role="status" aria-busy="true" className="flex flex-col gap-4">
      <h1 className="sr-only">{t("share.title")}</h1>
      <span className="sr-only">{c("loading")}</span>
      <Skeleton aria-hidden className="h-20 w-full rounded-(--radius-box)" />
      <Skeleton aria-hidden className="h-64 w-full rounded-(--radius-box)" />
    </div>
  );
}

function Ready({link, share}: {link: string; share: ShareView}) {
  const t = useTranslations("setup");
  const f = useAppFormat();
  const type = share.endpoint.type;
  return (
    <>
      <Card className="gap-4 p-4">
        <div className="flex items-center gap-3">
          <span aria-hidden="true" className="tile-11 bg-default text-foreground grid size-11 shrink-0 place-items-center text-xl">
            <SubIcon group="setup" name={shareTypeIcon(type)} className="size-6" />
          </span>
          <div className="flex min-w-0 flex-1 flex-col gap-0.5">
            <h1 className="truncate text-lg leading-6 font-semibold">
              {/* A name is the owner's own text and may be in the other script: isolated, so it does not reorder the line around it. */}
              <bdi>{share.endpoint.name}</bdi>
            </h1>
            <p className="text-muted truncate text-xs">{isKnownShareType(type) ? t(`share.types.${type}`) : type}</p>
          </div>
        </div>
        <p className="text-muted flex items-center gap-2 text-xs" data-testid="share-expiry">
          <Icon name="calendar" className="size-4 shrink-0" />
          {t("share.expires", {date: f.dateTime(share.expires_at)})}
        </p>
      </Card>
      <ShareSetup link={link} share={share} />
    </>
  );
}
