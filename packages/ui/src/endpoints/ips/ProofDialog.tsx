"use client";

import {hasCode} from "@ctrlz/api-client/errors.ts";
import {claimsQuery, useOpenClaimChallenge, useTakeIpClaim, type Challenge, type IPClaim} from "@ctrlz/api-client/hooks/clients.ts";
import {resolverViewQuery, useResolverView} from "@ctrlz/api-client/hooks/setup.ts";
import {pollEvery} from "@ctrlz/api-client/activity.ts";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {Alert, Button, FieldError, Input, Label, TextField, toast} from "@heroui/react";
import {useQuery, useQueryClient} from "@tanstack/react-query";
import {useTranslations} from "next-intl";
import {useEffect, useRef, useState} from "react";

import {TechCopyRow} from "../../data/TechCopyRow.tsx";
import {DialogFrame} from "../../dialog/DialogFrame.tsx";
import {AuthForm} from "../../forms/AuthForm.tsx";
import {FormError} from "../../forms/FormError.tsx";
import {stripInvisible} from "../../forms/invisible.ts";
import {useApiForm} from "../../forms/useApiForm.ts";
import {useVerifyOrigins} from "../../setup/VerifyConfig.tsx";
import {isBareIp, isProbeHost, liveChallenge, probeUrl, proofCommands, verifyHostOf} from "./ipModel.ts";
import {PrimaryButton} from "../../forms/PrimaryButton.tsx";

// `ipDialog=proof:<claimId>` (spec p3 4.2, 10, T-267): prove that this network is the one that asked, by a lookup that reaches us from it.
//
//   1. TCP         a TXT query of `<label>.verify.<zone>` over TCP to the first address of the pair (`dig +tcp`, `nslookup -vc`): nothing to type.
//   2. UDP         the same over UDP; a UDP source can be forged, so the TXT answer is typed here as the code.
//   3. Secure DNS  from a device whose encrypted DNS is this Endpoint's: the button makes this browser fetch the name, and the lookup is the proof.
//
// While the dialog is open it reads the claims every 3 seconds, for at most the challenge's life. The challenge shows `observed` and the
// protocol, never the address it came from. On an observation it takes the claim (with the code for UDP). The code is state of this dialog and
// of one mutation, which is reset when the dialog goes; it never reaches a URL, a query key or storage.

const POLL_MS = 3000;

export function ProofDialog({endpointId, claimId, onClose}: {endpointId: string; claimId: string; onClose: () => void}) {
  const t = useTranslations("endpoints");
  const e = useTranslations("errors");
  const c = useTranslations("common");
  const format = useAppFormat();
  const open = useOpenClaimChallenge();
  const take = useTakeIpClaim();
  const form = useApiForm({fieldNamespace: "profiles"});
  const queryClient = useQueryClient();
  const verifyOrigin = useVerifyOrigins();
  const [now, setNow] = useState(() => Date.now());
  const [started, setStarted] = useState<Challenge | null>(null);
  const [code, setCode] = useState("");
  const [outcome, setOutcome] = useState<"none" | "no_proof" | "done">("none");
  // The answer is one `no_proof` for a query seen from another address and for a wrong code; the dialog knows which it asked.
  const [codeWasSent, setCodeWasSent] = useState(false);
  const [probed, setProbed] = useState(false);
  const taken = useRef<string | null>(null);
  const busy = useRef(false);
  const [idle, setIdle] = useState(0);

  const claims = useQuery({
    ...claimsQuery(endpointId),
    // The shorter wait of this dialog, only while a challenge could still be observed.
    refetchInterval: (query) => {
      const live = query.state.data?.find((x) => x.id === claimId);
      return live && liveChallenge(live, Date.now()) ? pollEvery(POLL_MS)() : false;
    },
  });
  const claim: IPClaim | undefined = claims.data?.find((x) => x.id === claimId);
  const challenge = claim ? liveChallenge(claim, now) : null;
  // The answer that opens a challenge carries the name, the pair and whether proof is ready. The Resolver view also carries the DoH token, which
  // this dialog never shows, so once the answer is in hand the view is not read and what it left in the cache goes (S6-r3-6). Until then, and
  // after a reload that finds a live challenge, the view is the only source of the name and the pair. Challenge.commands on the claims list
  // would remove the last case (api_gap 1).
  const sent = started !== null && challenge?.id === started.id ? started.commands : null;
  const view = useResolverView(endpointId, "", {enabled: started === null});
  const viewKey = resolverViewQuery(endpointId).queryKey;
  useEffect(() => {
    if (started === null) return;
    // Only a query nothing observes is removed: the Resolvers dialog may hold the same one.
    queryClient.removeQueries({queryKey: viewKey, type: "inactive"});
  }, [started, queryClient, viewKey]);
  useEffect(
    () => () => {
      // After this dialog's own observer has gone.
      setTimeout(() => queryClient.removeQueries({queryKey: viewKey, type: "inactive"}), 0);
    },
    [queryClient, viewKey],
  );
  const proven = outcome === "done" || (claim !== undefined && claim.proven && claim.state === "active");

  // The clock moves in whole seconds only while there is a challenge to run out.
  useEffect(() => {
    if (!challenge) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [challenge]);
  // What the page holds of this dialog goes with it: the code in the variables of the last take.
  const {reset: resetTake} = take;
  useEffect(() => () => resetTake(), [resetTake]);

  // What the server sent is used only when it has the shape of a name and of an address: it goes into a URL and into commands that get pasted.
  const sentHost = challenge ? sent?.verify_host ?? verifyHostOf(challenge.label, view.data?.host) : null;
  const host = sentHost && isProbeHost(sentHost) ? sentHost : null;
  const sentDns = sent?.legacy?.dns1 ?? view.data?.legacy?.dns1 ?? null;
  const dns1 = sentDns && isBareIp(sentDns) ? sentDns : null;
  const ready = sent ? sent.ready : view.data ? view.data.ready : undefined;
  const commands = host && dns1 ? proofCommands(host, dns1) : null;

  async function begin() {
    if (busy.current || form.blocked) return;
    busy.current = true;
    form.clear();
    // The challenge in hand is the one a new one replaces. The claims are read again only after the request, and until then the old challenge
    // may still show as observed: it must not be taken again, so its id stays the one that was taken.
    const replaced = challenge?.id ?? null;
    try {
      setStarted(await open.mutateAsync({endpointId, claimId}));
      setOutcome("none");
      setCodeWasSent(false);
      setCode("");
      taken.current = replaced;
    } catch (error) {
      form.fail(error);
    } finally {
      busy.current = false;
    }
  }

  /** Whether the check was started: false while another request of this dialog is in flight (the caller may retry when it ends). */
  async function check(withCode: string | undefined): Promise<boolean> {
    if (busy.current || !claim) return false;
    busy.current = true;
    form.clear();
    try {
      const answer = await take.mutateAsync({endpointId, claimId, ...(withCode ? {code: withCode} : {})});
      if (answer.outcome === "no_proof") {
        setCodeWasSent(withCode !== undefined);
        setOutcome("no_proof");
      } else {
        setOutcome("done");
        setCode("");
        toast.success(t("ips.proof.done"));
      }
    } catch (error) {
      form.fail(error);
    } finally {
      busy.current = false;
      setIdle((n) => n + 1);
    }
    return true;
  }

  // An observation arrives: take the claim at once for the protocols that need no code. A UDP one waits for the person's code.
  const observed = challenge?.observed === true;
  const protocol = challenge?.observed_protocol;
  useEffect(() => {
    if (!challenge || !observed || protocol === "udp" || taken.current === challenge.id || proven) return;
    const id = challenge.id;
    taken.current = id;
    // A request of the dialog in flight (the person's code) makes `check` return false: the challenge is then not taken yet, and `idle`
    // changing when that request ends runs this effect again.
    void check(undefined).then((started) => {
      if (!started && taken.current === id) taken.current = null;
    });
    // `check` is the only closure that changes with the render; the guard above is the ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [challenge?.id, observed, protocol, proven, idle]);

  function submitCode() {
    const typed = stripInvisible(code).trim();
    if (typed === "") return form.setFieldError("code", e("fields.required"));
    void check(typed);
  }

  function probe() {
    const url = host ? probeUrl(host, verifyOrigin) : null;
    if (!url) return;
    setProbed(true);
    // The fetch's own result is ignored: the lookup of the name is the observation. `no-cors` keeps the answer opaque on purpose.
    fetch(url, {method: "GET", mode: "no-cors", cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer"}).catch(() => undefined);
  }

  const waitNote =
    form.retryIn > 0 ? (
      <p role="status" className="text-muted text-sm">
        {t("ips.proof.wait", {seconds: format.number(form.retryIn)})}
      </p>
    ) : null;
  // Text of the refusals of a take that are the screen's own words: a shared address points to encrypted DNS (spec p3 4.3, 4.5).
  const takeMessage = hasCode(form.formError, "ip_unavailable")
    ? t("ips.proof.unavailable")
    : hasCode(form.formError, "needs_admin_approval")
      ? t("ips.proof.needsAdmin")
      : hasCode(form.formError, "ip_suspended")
        ? t("ips.proof.suspended")
        : undefined;
  const secureAvailable = host !== null && probeUrl(host, verifyOrigin) !== null;
  const seconds = challenge ? Math.max(0, Math.round((Date.parse(challenge.expires_at) - now) / 1000)) : 0;

  let body;
  if (claims.isError && !claim) body = <p className="text-sm">{t("ips.proof.readFailed")}</p>;
  else if (!claims.data) body = <p role="status" className="text-muted text-sm">{c("loading")}</p>;
  else if (!claim) body = <p className="text-sm">{t("ips.proof.gone")}</p>;
  else if (proven)
    body = (
      <Alert status="success" role="status">
        <Alert.Indicator />
        <Alert.Content>
          <Alert.Title>{t("ips.proof.provenTitle", {cidr: claim.cidr})}</Alert.Title>
          <Alert.Description>{t("ips.proof.provenText")}</Alert.Description>
        </Alert.Content>
      </Alert>
    );
  else if (claim.state === "suspended") body = <p className="text-sm">{t("ips.proof.suspended")}</p>;
  else if (claim.needs_admin) body = <p className="text-sm">{t("ips.proof.needsAdmin")}</p>;
  else if (!challenge)
    body = (
      <div className="flex flex-col gap-3">
        <p className="text-sm">{t("ips.proof.intro", {cidr: claim.cidr})}</p>
        {ready === false ? <p className="text-muted text-sm">{view.data?.reason === "zone_missing" ? t("ips.proof.noZone") : t("ips.proof.noPair")}</p> : null}
        <PrimaryButton isPending={open.isPending} isDisabled={form.retryIn > 0 || ready === false} onPress={() => void begin()}>
          {claim.challenge ? t("ips.proof.again") : t("ips.proof.start")}
        </PrimaryButton>
        {claim.challenge ? <p className="text-muted text-xs">{t("ips.proof.expired")}</p> : null}
        {waitNote}
      </div>
    );
  else
    body = (
      <div className="flex flex-col gap-4" data-testid="proof-steps">
        <p className="text-sm">{t("ips.proof.waiting", {cidr: claim.cidr})}</p>
        {ready === false ? <p className="text-muted text-sm">{t("ips.proof.noZone")}</p> : null}
        <TechCopyRow label={t("ips.proof.nameLabel")} value={host ?? ""} />
        <TechCopyRow label={t("ips.proof.serverLabel")} value={dns1 ?? ""} />

        <section aria-label={t("ips.proof.tcp.title")} className="flex flex-col gap-2">
          <h3 className="text-sm font-medium">{t("ips.proof.tcp.title")}</h3>
          <p className="text-muted text-xs">{t("ips.proof.tcp.text")}</p>
          {commands ? <TechCopyRow label={t("ips.proof.tcp.dig")} value={commands.digTcp} /> : null}
          {commands ? <TechCopyRow label={t("ips.proof.tcp.nslookup")} value={commands.nslookup} /> : null}
        </section>

        <section aria-label={t("ips.proof.udp.title")} className="flex flex-col gap-2">
          <h3 className="text-sm font-medium">{t("ips.proof.udp.title")}</h3>
          <p className="text-muted text-xs">{t("ips.proof.udp.text")}</p>
          {commands ? <TechCopyRow label={t("ips.proof.udp.dig")} value={commands.dig} /> : null}
          {protocol === "udp" && observed ? <p className="text-sm">{t("ips.proof.udp.seen")}</p> : null}
          <AuthForm form={form} onSubmit={submitCode}>
            <TextField fullWidth name="code" value={code} isDisabled={take.isPending} isInvalid={form.fieldMessage("code") !== undefined} onChange={(v) => form.bind("code", setCode).onChange(v)}>
              <Label>{t("ips.proof.udp.code")}</Label>
              <Input autoComplete="off" dir="ltr" spellCheck={false} autoCapitalize="none" />
              <FieldError>{form.fieldMessage("code")}</FieldError>
            </TextField>
            <Button variant="secondary" className="self-start" isPending={take.isPending} isDisabled={form.retryIn > 0} onPress={submitCode}>
              {t("ips.proof.udp.check")}
            </Button>
          </AuthForm>
        </section>

        <section aria-label={t("ips.proof.secure.title")} className="flex flex-col gap-2">
          <h3 className="text-sm font-medium">{t("ips.proof.secure.title")}</h3>
          <p className="text-muted text-xs">{t("ips.proof.secure.text")}</p>
          {secureAvailable ? (
            <Button variant="secondary" className="self-start" onPress={probe}>
              {probed ? t("ips.proof.secure.again") : t("ips.proof.secure.button")}
            </Button>
          ) : (
            <p className="text-muted text-xs">{t("ips.proof.secure.off")}</p>
          )}
        </section>

        <div className="flex flex-col gap-1">
          <p className="text-sm" role="status" data-testid="proof-status">
            {observed ? t("ips.proof.observed", {protocol: protocol ? t(`ips.proof.protocols.${protocol}`) : ""}) : t("ips.proof.notYet")}
          </p>
          {/* The seconds change every second: they are not in the live region, which would read them out each time. */}
          <p className="text-muted text-xs tabular-nums">{t("ips.proof.expires", {seconds})}</p>
        </div>
        {outcome === "no_proof" ? (
          <Alert status="warning" role="alert">
            <Alert.Indicator />
            <Alert.Content>
              <Alert.Title>{t("ips.proof.noProofTitle")}</Alert.Title>
              <Alert.Description>{codeWasSent ? t("ips.proof.noProofCodeText") : t("ips.proof.noProofText")}</Alert.Description>
              {/* The hub keeps only the first query it sees for a label, so a query from another address spoils this challenge for good: the way on is a new one. */}
              <Button size="sm" variant="outline" className="mt-2" isPending={open.isPending} isDisabled={form.retryIn > 0} onPress={() => void begin()}>
                {t("ips.proof.newChallenge")}
              </Button>
              {waitNote}
            </Alert.Content>
          </Alert>
        ) : null}
      </div>
    );

  return (
    <DialogFrame
      isOpen
      onClose={onClose}
      title={claim ? t("ips.proof.title", {cidr: claim.cidr}) : t("ips.proof.titleNone")}
      footer={
        // The one primary button of the dialog is the "done" that ends a proof; a dialog that closes with nothing proven keeps the quiet one.
        proven ? (
          <PrimaryButton onPress={onClose}>{c("done")}</PrimaryButton>
        ) : (
          <Button variant="tertiary" onPress={onClose}>
            {c("close")}
          </Button>
        )
      }
    >
      <div className="flex flex-col gap-4">
        {body}
        <FormError error={form.formError} message={takeMessage} form={form} onRetry={() => void (challenge ? check(undefined) : begin())} />
      </div>
    </DialogFrame>
  );
}
