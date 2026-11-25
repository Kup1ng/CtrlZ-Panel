# CtrlZ-Shared

The code that must be the same in the panel and in every node: names and
hashing, the resolver grammar, rule tokens, the compiled profile format, the
evaluator, the system-names table, the protobuf messages, and the golden vectors
that pin all of it.

Module: `github.com/Kup1ng/CtrlZ-Shared` (Go 1.27.4). The specification is
`docs/specs/shared-contract.md` in the workspace; `Plan.md` wins if they differ.

## Two copies, one direction

`Ctrl Z Panel/shared` is canonical. `Ctrl Z Node/shared` is an identical copy.
Change code **here, in the Panel copy**, then sync. An edit made in the Node
copy is refused by `sync` and shows up as a `verify` failure across the two
copies.

```text
go -C shared run ./cmd/sharedtool sync --from "Ctrl Z Panel/shared" --to "Ctrl Z Node/shared"
go -C shared run ./cmd/sharedtool verify "Ctrl Z Panel/shared" "Ctrl Z Node/shared"
```

`scripts/shared-sync` and `scripts/shared-verify` (`.sh` and `.ps1`) in each
repository are thin wrappers with no logic. `CHECKSUMS` lists every file as
`<sha256>  <path>`; the SHA-256 of that file is the tree hash two copies must
share. Bytes are compared exactly: a carriage return in a text file, a symlink,
or two paths that differ only by case is an error.

## Layout

| Package | What it is |
|---|---|
| `names` | Canonical wire names, label offsets, SipHash-2-4, suffix walk, user input (IDNA) |
| `identity` | Host and DoH path grammar, tokens, slug, identity hashes, proof code |
| `rules` | Rule token grammar, `rule_key`, Upload Folder merge |
| `blob` | CZPB profile blob: builder, `Open` with every bounds check, reader |
| `gtable` | CZGT global tables for filters, services, categories |
| `policy` | The evaluator: `SelectStack`, `Pre`, `Post`, `Decide`, merge, synthesis; `Env.NeverProxied` turns a Redirect for an Iranian name into Bypass (D42) |
| `schedule` | Weekly grid, offset transitions |
| `sysnames` | System-names table |
| `locations` | Allowed and effective location sets, Auto and Random helpers |
| `netclass` | Address classes for Rebind and the Sanity Gate, and the lab-build constant `AllowPrivatePairAddrs` (two files behind the `ctrlz_lab` tag) |
| `zone` | Endpoint hostname target and name servers, `Build`, the failover decision table as data (`Rows`, `Inputs`), the evaluator that runs it, the probe state machine, the flap, drain and `PeerDown` rules (contract 8a) |
| `route` | Hybrid resolver rule schema and matcher |
| `reason` | Failure codes shared by every decoder |
| `wire` | Protobuf validators (pair table, push, peer view, free counters, activity), `ZoneInput`, entry hash chain, `DecodeEntry` |
| `quarantine` | The apply transaction: a bad blob is set aside, the stream goes on |
| `appleprofile` | Apple DNS profile: request validation, the stored params and their canonical JSON, the stable PayloadIdentifier and UUIDs (the builder is the panel's `internal/mobileconfig`) |
| `manifest` | Signature check before parsing, bundle path checks |
| `enrollproof` | The Poll proof of possession: the signed input, its digest and the canonical-DER check the hub runs (node enrolment, p4-nodes 4.2) |
| `vectors` | Golden vectors, fixtures, the single runner and the reference harness |
| `gen` | Generated protobuf and gRPC code, committed so builds need no `buf` |
| `proto` | The `.proto` sources, `buf.yaml`, `buf.gen.yaml` |
| `cmd/sharedtool` | `hash`, `verify`, `sync`, `failover-vectors` |
| `internal/hygiene` | Tests that read this module's source and enforce the package rules |

Rules of the module, enforced by `internal/hygiene`: no `unsafe`; no `os`,
`net`, process or syscall access; no clock reads; no goroutines; no package-level
mutable state; `names` is the leaf; `blob`, `gtable` and `policy` never reach
the generated protobuf code; third-party imports only from the allowed list.

## Commands

```text
go -C shared build ./... && go -C shared vet ./... && go -C shared test ./...
go -C shared test ./names -run xxx -fuzz FuzzFromWire -fuzztime 20s     # any Fuzz target
buf lint                       # in shared/
buf generate                   # needs protoc-gen-go and protoc-gen-go-grpc on PATH
CTRLZ_WRITE_VECTORS=1 go test ./vectors -run TestGenerate   # rewrites blob.json and gtable.json
CTRLZ_WRITE_CORPUS=1 go test ./blob ./gtable ./wire -run TestWriteCorpus
go -C shared run ./cmd/sharedtool failover-vectors --out vectors/zone-failover.json   # the only way to change that file
```

The pinned generator versions are `protoc-gen-go` v1.36.12 and
`protoc-gen-go-grpc` v1.6.2. After `buf generate`, run `sharedtool hash` so
`CHECKSUMS` follows the new files.

## Golden vectors

`vectors/<group>.json` is one file per group: LF, UTF-8, unknown keys fail.
`vectors.Run(t, harness)` is the single runner. The panel runs
`vectors.Reference{}`; the node runs its own glue harness on the same files.
Evaluator groups name a fixture in `vectors/fixtures/` which is compiled with
`blob.Build` and `gtable.Builder` at test time.

A changed expectation needs its reason in the commit message. Expected values
that came from an independent tool (SHA-256 with `sha256sum`, HMAC with
`openssl`, SipHash from the authors' published vectors) say so in `why`.

`zone-answer` is written by hand and run through `vectors.ReferenceZone`, a
transcription of contract 8a.3 over `zone.Target` and `zone.NameServers`; the
node runs the same cases through its own answerer (`vectors.RunZoneAnswers`).
`zone-failover` is written by `sharedtool failover-vectors` from
`internal/failovergen`, which reads only the data `zone.Rows` and `zone.Inputs`
and calls no function of `zone`, so the cases are an independent oracle for the
evaluator; `TestCheckedInFileIsFresh` fails when the file is not what a fresh
run writes.

## Decisions taken in the implementation

The contract left these open or ambiguous. They are in force until someone
decides otherwise, and each is covered by a vector or a test.

- **Filter action.** The FLTS record is `filter_id, mode_wire` with no action
  field, so a filter hit is always **Block**. Filters that Redirect or Bypass
  would need a format change.
- **Filter table id.** `TableRef.wire_id` for a filter table is
  `(filter_id << 16) | mode_wire` (`policy.FilterWire`).
- **Redirect host needs a lookup.** The contract's list of lookups `Post` may
  make does not include the target of a Redirect-to-host. It makes one
  (`PreResult.SynthOnly`): the qname is not resolved first.
- **ANY.** Bypass and default answer ANY with RFC 8482 HINFO and never resolve
  it; `Decide` does not call the resolver for it.
- **Rebind** applies at stage `default` only (an explicit Bypass is exempt).
- **CNAME hops** skip the exfiltration check: it is about what the client typed.
- **Custom Block Response** treats an all-zero address as unset (NODATA).
- **Path over `:authority`.** In DoH form B the path's resolver id wins; an
  authority naming another resolver is ignored entirely, including its client.
- **`ParseHost` order.** The port is stripped first, then one trailing dot, so
  `x.zone.:443` (an FQDN authority, which curl and browsers send unchanged) is
  in the zone. `x.zone:443.` is not.
- **Rule country codes** are checked for shape (two letters), not against an
  ISO table.
- **Glob labels** must be ASCII: the Punycode of a fragment is not a fragment of
  the Punycode.
- **Walk cap.** The CNAME walk looks at 32 hops at most.
- **Local system-name answers** use TTL 3600; the Android synthetic answer
  uses 60 as the contract says.
- **`golang.org/x/text/unicode/norm`** is imported directly for NFKC in
  `identity.SlugClient`. It was already in the build through `x/net/idna`.
  `hygiene` lists it as the one extra allowed import.
- **Quarantine** keeps non-binding fields of an Endpoint record (admin state,
  Authorized IPs) when its policy binding is rejected, so a `hard_disable` works
  while a blob is bad.
- **Review fixes (2026-11-06).** `quarantine.State.Pending` remembers the record
  an Endpoint put meant to bind when a blob was missing; the next `Apply` or
  `quarantine.Retry` switches it once the blob is there, and `Report.Promoted`
  says so. `manifest.Verify` takes the role from the payload type
  (`manifest.RoleFor`), not from the caller; the policy role ignores root and
  delegation expiry (use `DelegationExpired` to alert); `VerifyRoot`,
  `VerifyManifest`, `CheckManifestFresh` and `CheckRollbackTarget` are the
  rotation, typed-verify and anti-rollback helpers. `names.MaxUserInput` (1024
  bytes) is checked before IDNA in `ParseUser` and `rules.Parse`.
  `wire.ValidateGrantForward` decodes `source_prefix` and applies the width
  floors `MinGrantBits4` (16) and `MinGrantBits6` (32), which are placeholders
  until field measurement (contract 10.4). `netclass` classifies NAT64, 6to4,
  Teredo and IPv4-compatible addresses by the IPv4 address they carry, and
  Rebind also runs on the A set DNS64 is about to synthesize from.
- **Review fixes, second round (2026-11-06).** `ParseUser` strips exactly one
  trailing dot, no longer applies the IDNA hyphen rules (blocklists have
  `-ad.example.com`), and refuses a name whose last label is a number (`127.1`,
  `0x7f.1`); `ParseUserPart` is the same for a piece of a longer name. `netclass`
  adds `fec0::/10` and `192.88.99.0/24`. `locations` compares a city folded and
  shows the smaller spelling, with one comparison shared by regions. `manifest.Verify`
  takes the payload type the caller expects, `KeyID` is derived from the public
  key, a key listed twice or an `expires_at` of 0 on a root or grant is
  malformed, `VerifyManifest` takes the kind, `NewIndex` replaces the linear
  `CheckEntry`, and `CheckPath` refuses colons and DOS device names. `blob.Open`
  refuses two plain rules of one name and more than `MaxPlainRun` (8) on one hash.
  A Bogus answer with CD off no longer feeds the CNAME walk or the destination
  country. `wire.ValidateBlockPage`, `ValidateProofObservation`,
  `ValidateLearnedIP`, `ValidateBlockUnblockRequest`, `ValidateHeartbeat`,
  `ValidateApplyResult` and the single door `ValidateNodeMessage` exist, with a
  test that lists the members of the `NodeMessage` oneof; `quarantine.Apply`
  validates block pages; `ValidateActivityBatch` holds `client_label` to the
  client grammar (`names.ValidClientLabel`).
- **P0 gate fixes (2026-11-06).** `sign.v1.Root` names its root keys in
  `root_key_ids` (no derivation by exclusion) and `manifest.Verify` refuses an
  envelope with more than `MaxSignatures` signatures and verifies each key id
  once. A size or hash mismatch of a fetched blob is `quarantine.Report.Failed`,
  not a quarantined hash, and `State.Wanted` keeps every missing or damaged blob
  per hash so `Apply` and `Retry` fetch it again. `wire.MaxSectionName` is 16.
  A Bogus answer (CD off) is refused first in `shapeBypass`; Rebind reads the
  hints of HTTPS and SVCB records. `policy.AcceptGrant` takes a `GrantOffer`.
  `identity.ProofCode` takes a `netip.Addr`. `wire.ValidateLogRow` and
  `ValidateActivityBatch` take `now`; `ValidateLogBatch`,
  `ValidateCountersBatch` and `ValidateTelemetryMessage` exist. The vector runner
  fails on an unknown op, negative text cases carry `error_contains`, and
  `vectors/groups_test.go` lists the groups that must exist.

- **zone (P4 W1a).** `Rows()` and `Inputs()` are functions, not variables, because
  the module has no package-level mutable state. An age limit is `zone.Limit`:
  "from the last 15 s" is the half-open window (now-15 s, now], so a Heartbeat
  exactly 15 s old has passed it; the HeadNotice grace and the request age are
  the two "more than" limits (`Strict`). After a hub start, and when a node
  first enters the membership, `hb(X)` counts its 15 s from that moment (SC 8a.4 says so). The
  timers of a node's rows are in-memory and are cleared on a hub start and, by
  F0, for the nodes of a changed pair and for a node that leaves. A timed row
  starts counting on the tick on which its State and Inputs first hold, and at
  the end of the tick for a state a later row of that tick set (a Release starts
  F3's S on the tick of the Release). A request's own kind is the `op` key of a
  `request` event in `zone-failover`, because `kind` is the event's. Build's
  errors are `*zone.BuildError` whose `Msg` is a stable phrase.

## Not here yet

- `xrayschema` and `sharelink` (contract 14) and their vector groups `xray` and
  `sharelink`: P4b. `appleprofile` is here since P3, with its vector group.
- The `grants` vector group: the Grant table lives in the node (contract 10.4),
  so there is nothing in this module to run it against: P4b, with the node's
  table. `Final.Widenable`, `WantGrant` and `AcceptGrant` are here and tested.
- A fuzz target for the `manifest.Verify` envelope path.
- `wire` validators for the hub-to-node messages (`HubMessage`); the node-to-hub
  ones are all in `ValidateNodeMessage`.
- Open questions 1 to 9 of contract section 18 stand.
