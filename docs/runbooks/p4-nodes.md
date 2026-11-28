# Node runbook (P4)

This is the runbook for the steps that happen outside the panel, or in an order the panel cannot enforce. The admin app shows the numbered steps of each section on its node runbook page (`/runbook`; the text is `runbook.*` in `packages/i18n/messages/<locale>/nodes.json`). This file alone carries the reports step and the two cases that need care under Compromise, and the step texts on the page are shorter, so read this file on a host with a terminal. The Nodes page, the revoke dialog and the hold note link to that page, so the link never leaves the origin. When you change a step here, change that text in both languages with it. A test (`packages/ui/src/admin/runbook/runbookDoc.test.ts`) fails when the number of steps differs.

The rules behind the steps are in the shared contract: 8a.4 (membership, revocation in the log, addresses given up) and 8a.9 (replacement order, compromise runbook), and in `docs/specs/p4-nodes.md` 4.5. This file adds the order in which an operator does them.

Words used here:

- A pair is two nodes, a primary and a fallback. The global pair serves every Endpoint that has no pair of its own, and it is the pair free DNS publishes.
- A slot is one of the four places a node row can hold (D25). A `pending` row (enrolled, waiting for approval) and a `revoked` row still hold theirs.
- The date of an address is the time the panel gave it up plus 30 days. The Nodes page lists every address given up that no node holds now and whose date has not passed.

## Compromise

Use this when you suspect that a node, its host or its key was taken. Do the steps in order. A revocation reaches the other nodes through the configuration log, so step 3 does not wait for it. A hold does not isolate a node and is no step here: until a node has applied the log entry of the revocation, it still trusts the revoked one.

1. Revoke the node on its page (fresh TOTP code). Revocation is terminal. The hub ends the node's streams, the compiler empties its key in every later table, and the worker removes the learned addresses and the untouched automatic clients that the node's reports caused.
2. Replace the node in its pair with a node that already exists. When no node is free, follow the replacement order below (with two nodes, a temporary third host is needed). If it is the primary of a pair, you may swap the roles first, so that the other node becomes DNS1 for Plain DNS devices. The swap leaves the revoked node in the pair, so step 8 still waits for the replacement.
3. Stop the host, or ask the provider to cut its address. Do not wait for the revocation to roll out.
4. After step 1, replace the hub's `proof_key` secret and restart the hub. The restart ends every open stream, and an address proof in flight fails and the user starts it again. Then rotate the zone's wildcard key and certificate on the remaining nodes. With a public CA, revoke the old certificate with its own key, reason key compromise. With a private CA, whose leaf cannot be revoked, rotate the private CA root and have clients install it again when the old certificate lives too long.
5. Look in the Certificate Transparency logs for certificates for the zone's names that the panel did not order, and have each one revoked.
6. Check again the CAA records that apply to the zone's names.
7. Remove the node's name server from the parent zone's NS and glue at the registrar, or change the delegation if needed. If a step at a CA or the registrar fails while resolvers still ask the node, try it again later.
8. Remove the node here once no pair holds it, neither in the last table the log carried nor in the hub's own. Keep its addresses until the date in the list on the Nodes page. A host that comes back is rebuilt from a clean install, enrols as a new node, has its fingerprint confirmed and is approved like any other.

After step 1, read `GET /nodes/{id}/reports` from the time you suspect the compromise began. It lists the Plain DNS claims that were taken on the node's observations, and the addresses the revoke job left because an Endpoint needed them. An admin action on those claims is not built until P7 (T-355), so list them now.

Two cases need care:

- A node that has not applied the entry that empties the revoked node's key (the compiler is stalled, the rollout has not reached it, or it is cut off from the panel) still trusts the revoked node. Repair the compiler, or meanwhile hold the revoked node when its peer is fit, and stop its host (step 3).
- A node cut off from the panel never learns that a node was revoked or removed. There is no hard expiry of the table, because one would turn a long panel outage into a total outage of hostname clients.

## Retire a node

1. Replace the node in its pair with a node that already exists (when all four slots are held, in the replacement order below), and leave it running in no pair while its clients move. A change of a node of the global pair also changes the addresses on the free DNS page: free users who typed the old address keep it until it stops answering, and get no notice.
2. Remove the node's NS record and its address from the parent zone at the registrar.
3. When every node has applied the entry of the pair change (the node page shows that the drain is done), remove the node here and stop its host at once. A removed node would go on answering with its last policy.
4. Give each address back to the provider only after its date in the list on the Nodes page.

## Move a node to a new address

Change the address on the node's page, and change the parent zone's address for the node's name server with it. Keep the old address attached to the host while it still reaches it (behind 1:1 NAT, or while the provider leaves it), where the node still serves it with current policy. Give the old address back only after its date.

The bind address (`dns_bind_ip`, `proxy_bind_ip`) is not edited live in P4: a host whose bind address must change is enrolled again as a new node. When only the public address moves behind 1:1 NAT, the bind address stays the same. When the new node gets a new DNS address and a slot is free, enrol and approve it first, put it in the old node's place in its pair, and retire the old node as above. When it keeps the old DNS address, or all four slots are held, use the replacement order.

## Replacement order

At four nodes every slot is held, a waiting or revoked row included, so a new host cannot be confirmed until a node is removed, and a node in a pair cannot be removed. A new host whose DNS address the old node holds (a key rotation, a revoked host that comes back, a bind address behind 1:1 NAT) cannot be approved while the old row exists, whatever slot is free. The Nodes page states this order when no slot is free. Go in this order, each step an ordinary pair change, removal or approval:

1. Put a node that already exists in the old node's place in its pair. When no node is free, first remove a pair that no Endpoint uses: every pair but the global one.
2. Remove the old node once the removal is accepted.
3. Only then approve the new host, enrolled earlier or into the freed slot, and pair it.

With two nodes no node can take the old one's place: the fallback of a pair is required and the global pair must exist. Such a replacement needs a temporary third host, enrolled, approved and put in the old node's place, and retired by the steps above once the new row has taken the old node's place again.

## Free DNS

Free DNS answers Plain DNS queries from a source with no identity as a public resolver, while its switch on the Nodes page is on. Three cases need a step outside the panel.

- Listed as an open resolver, or the provider warns that it will null-route the address. A listing can lead a provider to null-route a node's DNS address, which cuts that node for its tenants too. Ask the provider to filter the forged packets (queries that spoof a victim's address make the node answer that address, free answers included), and turn free DNS off on the Nodes page meanwhile. The switch reaches every node with an open stream to the hub. A node the panel cannot reach keeps the value it last applied.
- The host's own resolver. The system resolver of a node host must never be the DNS address of a node. The agent warns when it is. Point the host's resolver at another address.
- A second address for the free resolver. Both Unbound processes of a node send from the host's address, so an authoritative server that limits responses per address sees them as one source, and a flood of random names through the free resolver can make those servers limit the address the node's own checks use. When the host has an address in another /24 network that is neither the node's DNS, proxy nor identified-resolver address, give it to the free resolver as its outgoing interface by repeating the install with `--free-outgoing-ip <address>`; the agent renders it as `outgoing-interface`. With one shared address the risk stays, and the shared contract records it (8a.9, the F2 case).

## Outside the panel

A packet-filter rule or another limit on packets to the DNS listeners that anyone but Ctrl Z puts on a node host, and the block of a source, are steps at the host or at the provider. The panel does not see or enforce them. The same holds for an address given back before its date, a parent NS or glue record left pointing at it, and a device that still holds the address after its date: such a device sends its queries to whoever holds the address next, Plain DNS in plaintext and a hostname client's identifier in SNI. The warning on the Nodes page and this runbook are the remedy.
