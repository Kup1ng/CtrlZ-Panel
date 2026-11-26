"use client";

import {Button, Spinner} from "@heroui/react";
import {useIpClaims} from "@ctrlz/api-client/hooks/clients.ts";
import type {ResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {useTranslations} from "next-intl";
import {useCallback, useEffect, useRef, useState} from "react";

import {Tech} from "../data/Tech.tsx";
import {TechCopyRow} from "../data/TechCopyRow.tsx";
import {
  MAX_MS,
  POLL_MS,
  PROBE_TIMEOUT_MS,
  inVerifyOrigin,
  judge,
  myipHost,
  newLabel,
  nextState,
  parseAnswer,
  probeHost,
  type VerifyProtocol,
  type VerifyState,
} from "./verifyModel.ts";
import {useVerifyOrigins} from "./VerifyConfig.tsx";

// Spec p3 8.4, Plan T-236: "is this device using this Endpoint?" asked from the page. Every attempt draws a fresh label and fetches
// `<label>.verify.<zone>/v`; to fetch it the browser resolves the name through the device's own DNS, so a node can tell which Endpoint
// the lookup came through. Three states by the Plan's definitions (verifyModel.ts), polled every 3 seconds for two minutes.
//
// Hidden, and the manual check shown instead, when the installation has no verify origin (CTRLZ_VERIFY_ORIGIN, spec 15.3) or the probe
// name would fall outside it; the private CA mode of P4 (T-237) joins the same branch. The page's policy allows no other origin than that
// one, so nothing else is ever asked. The label is from `crypto.getRandomValues`, used once and never sent anywhere but in that name.

const SCHEME = "https"; // the probe origin is built from the validated verify origin's host, never typed as a URL in source

type Shown = {state: VerifyState; protocol?: VerifyProtocol; clientMatched?: boolean};

/** `endpointId` is the owner's: the page then knows which networks the Endpoint holds, for the manual check. A share page has none. */
export function SetupVerify({view, endpointId}: {view: ResolverView; endpointId?: string}) {
  const origins = useVerifyOrigins();
  const sample = probeHost("x".repeat(26), view.host);
  if (!sample || !inVerifyOrigin(sample, origins)) return <ManualCheck view={view} endpointId={endpointId} />;
  return <Probe view={view} />;
}

function Probe({view}: {view: ResolverView}) {
  const t = useTranslations("setup");
  const [shown, setShown] = useState<Shown>({state: "idle"});
  const run = useRef<AbortController | null>(null);

  const stop = useCallback(() => {
    run.current?.abort();
    run.current = null;
  }, []);
  useEffect(() => stop, [stop]);

  const start = useCallback(() => {
    stop();
    const controller = new AbortController();
    run.current = controller;
    const startedAt = Date.now();
    let progress = {streak: 0};
    setShown({state: "pending"});

    // A new label starts every POLL_MS whether or not the last probe has answered, because a probe may take longer than that (a fresh name needs its
    // own lookup, TCP and TLS on a slow link). The answers are judged as they arrive. After MAX_MS no probe starts, and the last one decides.
    let inflight = 0;
    let finished = false;
    let expired = false;

    const probe = async () => {
      inflight += 1;
      const label = newLabel();
      const host = probeHost(label, view.host);
      let judged: Awaited<ReturnType<typeof judge>> = {state: "pending"};
      if (host) {
        // The two ends are joined by hand: AbortSignal.any is missing in Safari before 17.4 and in older WebViews, where it would throw on every probe.
        const own = new AbortController();
        const onStop = () => own.abort();
        controller.signal.addEventListener("abort", onStop, {once: true});
        const timer = setTimeout(() => own.abort(), PROBE_TIMEOUT_MS);
        try {
          const response = await fetch(`${SCHEME}://${host}/v`, {
            method: "GET",
            cache: "no-store",
            credentials: "omit",
            referrerPolicy: "no-referrer",
            signal: own.signal,
          });
          const answer = response.ok ? parseAnswer(await response.json()) : null;
          judged = await judge(label, answer, {resolverId: view.resolver_id, client: view.client});
        } catch {
          // A failed probe is "pending": the name did not come through, the device is offline, or the page was left.
        } finally {
          clearTimeout(timer);
          controller.signal.removeEventListener("abort", onStop);
        }
      }
      inflight -= 1;
      if (controller.signal.aborted || finished) return;
      const next = nextState(progress, judged);
      progress = {streak: next.streak};
      if (next.state === "success") {
        finished = true;
        setShown({state: "success", protocol: judged.protocol, clientMatched: judged.clientMatched});
        return;
      }
      if (expired && inflight === 0) {
        finished = true;
        setShown({state: "timeout"});
        return;
      }
      setShown({state: next.state, protocol: judged.protocol, clientMatched: judged.clientMatched});
    };

    const tick = () => {
      if (controller.signal.aborted || finished) return;
      if (Date.now() - startedAt >= MAX_MS) {
        expired = true;
        if (inflight === 0) {
          finished = true;
          setShown({state: "timeout"});
        }
        return;
      }
      void probe();
      setTimeout(tick, POLL_MS);
    };
    tick();
  }, [stop, view.host, view.resolver_id, view.client]);

  const running = shown.state === "pending" || shown.state === "partial" || shown.state === "confirming";
  return (
    <section aria-label={t("verify.title")} className="flex flex-col gap-3" data-testid="verify">
      <h3 className="text-sm font-medium">{t("verify.title")}</h3>
      <p className="text-muted text-xs">{t("verify.hint")}</p>
      <div role="status" aria-live="polite" className="flex items-start gap-2 text-sm" data-testid="verify-status" data-state={shown.state}>
        {shown.state === "success" ? <Icon name="check" className="mt-0.5 size-4 shrink-0" /> : null}
        {shown.state === "partial" || shown.state === "timeout" ? <Icon name="warning" className="mt-0.5 size-4 shrink-0" /> : null}
        {shown.state === "pending" || shown.state === "confirming" ? <Spinner size="sm" /> : null}
        <span>
          {shown.state === "idle" ? t("verify.states.idle") : null}
          {shown.state === "pending" ? t("verify.states.pending") : null}
          {shown.state === "partial" ? t("verify.states.partial") : null}
          {shown.state === "confirming" ? t("verify.states.confirming") : null}
          {shown.state === "timeout" ? t("verify.states.timeout") : null}
          {shown.state === "success"
            ? `${t("verify.states.success")}${shown.protocol ? ` ${t("verify.over", {protocol: t(`verify.protocols.${shown.protocol}`)})}` : ""}`
            : null}
        </span>
      </div>
      {shown.state === "success" && shown.clientMatched === false && view.client ? (
        <p className="text-muted text-xs">{t("verify.otherClient")}</p>
      ) : null}
      <div className="flex gap-2">
        {running ? (
          <Button size="sm" variant="secondary" onPress={() => { stop(); setShown({state: "idle"}); }}>
            {t("verify.stop")}
          </Button>
        ) : (
          <Button size="sm" variant="secondary" onPress={start}>
            {shown.state === "idle" ? t("verify.start") : t("verify.again")}
          </Button>
        )}
      </div>
    </section>
  );
}

/**
 * Without the probe: a lookup by hand of `myip.<zone>`. That name is answered only for an identified Endpoint (its source address, or NODATA when
 * the Endpoint does not show addresses) and REFUSED for any other source, so the answer depends on identity. A name under `verify.<zone>` would
 * not do: any recursive resolver gets the node's own address for it (shared contract 8a.3), so it would confirm any device through any resolver.
 * The lookup goes over Plain DNS whatever the browser or system uses for DoH, so it tells about Plain DNS only.
 *
 * The answer does not say which Endpoint, or whose, identified the source: on Plain DNS the identity is whichever Endpoint holds the claim of the network,
 * and on a mobile network several tenants can share one public address. So an address proves only that some Endpoint of the service holds the claim.
 * The page shows the networks this Endpoint holds, and the person compares: it is this Endpoint only when the answer is inside one of them. An empty
 * answer cannot tell (S7-r2-7, spec p3 8.4).
 */
function ManualCheck({view, endpointId}: {view: ResolverView; endpointId?: string}) {
  const t = useTranslations("setup");
  const host = myipHost(view.host);
  return (
    <section aria-label={t("verify.title")} className="flex flex-col gap-3" data-testid="verify-manual">
      <h3 className="text-sm font-medium">{t("verify.title")}</h3>
      <p className="text-muted text-xs">{t("verify.manualHint")}</p>
      {host ? (
        <>
          <TechCopyRow label={t("verify.nslookup")} value={`nslookup ${host}`} />
          <TechCopyRow label={t("verify.dig")} value={`dig ${host}`} />
          <p className="text-muted text-xs">{t("verify.manualResult")}</p>
          {endpointId ? <HeldNetworks endpointId={endpointId} /> : null}
        </>
      ) : null}
    </section>
  );
}

/**
 * The claims of the Endpoint that identify a source now, to compare with the answer of `myip`. The node compiles `active` and `grace` claims (spec p3 3.3
 * and 4.1), so both answer, and a grace one is marked with its end. `pending_proof` and `suspended` identify nobody. Nothing while they load or when
 * they cannot be read: the text above stands alone.
 */
function HeldNetworks({endpointId}: {endpointId: string}) {
  const t = useTranslations("setup");
  const format = useAppFormat();
  const claims = useIpClaims(endpointId);
  if (!claims.data) return null;
  const identifying = claims.data.filter((claim) => claim.state === "active" || claim.state === "grace");
  return (
    <div className="flex flex-col gap-1" data-testid="verify-claims">
      <h4 className="text-xs font-medium">{t("verify.manualClaims")}</h4>
      {identifying.length === 0 ? (
        <p className="text-muted text-xs">{t("verify.manualNoClaims")}</p>
      ) : (
        <>
          <ul className="flex flex-wrap gap-x-3 gap-y-1 text-sm">
            {identifying.map((claim) => (
              <li key={claim.id} className="flex items-baseline gap-1">
                <Tech>{claim.cidr}</Tech>
                {claim.state === "grace" ? (
                  <span className="text-muted text-xs">
                    {claim.grace_until ? t("verify.manualGraceUntil", {date: format.dateTime(claim.grace_until)}) : t("verify.manualGrace")}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
          <p className="text-muted text-xs">{t("verify.manualCompare")}</p>
        </>
      )}
    </div>
  );
}
