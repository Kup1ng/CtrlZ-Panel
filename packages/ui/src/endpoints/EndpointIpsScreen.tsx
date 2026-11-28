"use client";

// /endpoints/[id]/ips (spec p3 10, 4, 5; T-262, T-263, T-267): the Plain DNS addresses of the Endpoint (claims, with their state, the date a
// grace ends and a proof button) and its Authorized IPs (time, address, city, ISP, search, copy, add, batch delete, with the current address and
// the last one under Require marked and kept). The dialogs are `ipDialog=claim`, `ipDialog=proof:<claim id>` and `ipDialog=add`; a dialog of
// the claims that holds a code keeps it in its own state.

import {useTranslations} from "next-intl";

import {parseIpDialog} from "../dialog/dialogValues.ts";
import {useUrlDialog} from "../dialog/useUrlDialog.ts";
import {useEndpointFrame} from "./EndpointFrameContext.tsx";
import {AddAuthorizedDialog} from "./ips/AuthorizedDialogs.tsx";
import {AuthorizedSection} from "./ips/AuthorizedSection.tsx";
import {ClaimDialog} from "./ips/ClaimDialog.tsx";
import {ClaimsSection} from "./ips/ClaimsSection.tsx";
import {DdnsSection} from "./ips/DdnsSection.tsx";
import {ProofDialog} from "./ips/ProofDialog.tsx";

export function EndpointIpsScreen({endpointId}: {endpointId: string}) {
  void endpointId;
  const t = useTranslations("endpoints");
  const {endpoint} = useEndpointFrame();
  const dialog = useUrlDialog("ipDialog");
  const parsed = parseIpDialog(dialog.value);

  return (
    <div data-screen="endpoint-ips" className="flex flex-col gap-8">
      <p className="text-muted text-sm">{t("ips.intro")}</p>
      <ClaimsSection endpoint={endpoint} onClaim={() => dialog.open("claim")} onProve={(id) => dialog.open(`proof:${id}`)} />
      <AuthorizedSection endpoint={endpoint} onAdd={() => dialog.open("add")} />
      {endpoint.authorize_ddns ? <DdnsSection endpoint={endpoint} /> : null}

      {parsed?.kind === "claim" ? (
        <ClaimDialog
          endpointId={endpoint.id}
          onClose={dialog.close}
          // A claim that waits for proof goes on to the proof in the same history entry; any other is finished here.
          onClaimed={(claim) => (claim.state === "pending_proof" && !claim.needs_admin ? dialog.open(`proof:${claim.id}`) : dialog.close())}
        />
      ) : null}
      {parsed?.kind === "proof" ? <ProofDialog key={parsed.claimId} endpointId={endpoint.id} claimId={parsed.claimId} onClose={dialog.close} /> : null}
      {parsed?.kind === "add" ? <AddAuthorizedDialog endpointId={endpoint.id} onClose={dialog.close} /> : null}
    </div>
  );
}
