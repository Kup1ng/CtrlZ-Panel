package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The node routes of the admin half of enrolment, and the reads of the nodes page (p4-nodes 4.2 steps 1 to 5,
// 4.5, 9.2). Handlers decode, judge and call the store; every write is one transaction with its audit row.
// No route here writes policy_outbox (T-081): a pending node is in no PairTable, so a confirmation changes
// nothing the compiler reads.

const (
	// enrollmentTTL is the life of an enrolment token (R19, D31).
	enrollmentTTL = 15 * time.Minute
	// addressWait is the fixed wait before a given-up address may go back to the provider (SC 8a.4).
	addressWait = 30 * 24 * time.Hour
	// reportWindow is how far back GET /nodes/{id}/reports looks when `from` is not given.
	reportWindow = 30 * 24 * time.Hour
	reportLimit  = 200
	// keptLimit is the bound of the worker's list of kept rows (adminjobs.maxKeptListed).
	keptLimit    = 500
	givenUpLimit = 100
)

func errAddress(field string) *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeAddressRefused).WithFields(httpx.FieldError{Name: field, Code: "refused"})
}

func errEnrollmentState() *httpx.Error {
	return httpx.New(http.StatusConflict, httpx.CodeEnrollmentState)
}

// addrText renders an optional address of a node row for the API.
func addrText(a *netip.Addr) *string {
	if a == nil || !a.IsValid() {
		return nil
	}
	s := nodeadmin.AddrText(*a)
	return &s
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// parseAddrs judges the four addresses of a new node. The bind addresses may be private (1:1 NAT); the
// advertised ones are public outside a lab build (4.2 steps 1 and 4).
func parseAddrs(b gen.CreateNodeEnrollmentRequest) (nodeadmin.EnrollAddrs, *httpx.Error) {
	var out nodeadmin.EnrollAddrs
	parseOne := func(field, text string, check func(netip.Addr) error) (netip.Addr, *httpx.Error) {
		a, err := nodeadmin.ParseAddr(text)
		if err != nil || check(a) != nil {
			return netip.Addr{}, errAddress(field)
		}
		return a, nil
	}
	var e *httpx.Error
	if out.DNSBind, e = parseOne("dns_bind_ip", b.DnsBindIp, nodeadmin.CheckBind); e != nil {
		return out, e
	}
	if out.DNSAdv, e = parseOne("dns_advertised_ip", b.DnsAdvertisedIp, nodeadmin.CheckAdvertised); e != nil {
		return out, e
	}
	if out.ProxyBind, e = parseOne("proxy_bind_ip", b.ProxyBindIp, nodeadmin.CheckBind); e != nil {
		return out, e
	}
	if out.ProxyAdv, e = parseOne("proxy_advertised_ip", b.ProxyAdvertisedIp, nodeadmin.CheckAdvertised); e != nil {
		return out, e
	}
	return out, nil
}

// CreateNodeEnrollment is POST /node-enrollments (4.2 step 1). The install command is built before the row is
// made: a panel with no pin file, root or signed bundle cannot show a command, and a token nobody can use
// would only expire.
func (s *Server) CreateNodeEnrollment(ctx context.Context, req gen.CreateNodeEnrollmentRequestObject) (gen.CreateNodeEnrollmentResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	addrs, herr := parseAddrs(*req.Body)
	if herr != nil {
		return nil, herr
	}
	var bound netip.Addr
	if req.Body.BoundIp != nil {
		if bound, err = nodeadmin.ParseAddr(*req.Body.BoundIp); err != nil {
			return nil, errAddress("bound_ip")
		}
	}
	if s.d.Install == nil {
		return nil, httpx.Unavailable()
	}
	token, hash, err := hubtoken.New(nil)
	if err != nil {
		return nil, err
	}
	command, err := s.d.Install.Command(token, addrs, s.now())
	if err != nil {
		// Which file was missing is the operator's to find in the deployment; the answer says only that
		// the command cannot be made yet.
		return nil, httpx.Unavailable()
	}
	var id uuid.UUID
	var expires time.Time
	err = s.global(ctx, func(g store.GlobalTx) error {
		var err error
		if id, expires, err = g.NodeEnrollmentCreate(hash, enrollmentTTL, bound); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeEnrollmentCreate{Enrollment: id, Bound: bound.IsValid()})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.CreateNodeEnrollment201JSONResponse{Id: id, ExpiresAt: expires.UTC(), InstallCommand: command}, nil
}

func enrollmentRow(e store.NodeEnrollment) gen.NodeEnrollmentRow {
	return gen.NodeEnrollmentRow{
		Id: e.ID, State: gen.NodeEnrollmentRowState(e.State), CreatedAt: e.CreatedAt.UTC(), ExpiresAt: e.ExpiresAt.UTC(),
		BoundIp: addrText(e.BoundIP), NodeId: e.NodeID, KeyFingerprint: nonEmpty(e.Fingerprint),
		DnsBindIp: addrText(e.DNSBind), DnsAdvertisedIp: addrText(e.DNSAdv), ProxyBindIp: addrText(e.ProxyBind), ProxyAdvertisedIp: addrText(e.ProxyAdv),
		Hostname: nonEmpty(e.Hostname), OsRelease: nonEmpty(e.OSRelease), NodeVersion: nonEmpty(e.NodeVersion),
		EnrolledAt: timePtr(e.EnrolledAt), EnrolledFrom: addrText(e.EnrolledFrom), ApprovedAt: timePtr(e.ApprovedAt), RejectedAt: timePtr(e.RejectedAt),
	}
}

// ListNodeEnrollments is GET /node-enrollments.
func (s *Server) ListNodeEnrollments(ctx context.Context, req gen.ListNodeEnrollmentsRequestObject) (gen.ListNodeEnrollmentsResponseObject, error) {
	before, err := uuidCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.NodeEnrollmentPage{Items: []gen.NodeEnrollmentRow{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.NodeEnrollmentsPage(before, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(rows[len(rows)-1].ID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, enrollmentRow(r))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListNodeEnrollments200JSONResponse(out), nil
}

// normalizeFingerprint folds what a person types from a console into the 64 lower-case hex digits the record
// holds: case, and the spaces, colons and hyphens a fingerprint is often grouped with.
func normalizeFingerprint(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if c == ' ' || c == ':' || c == '-' {
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// firstFreeSlot is the lowest slot of 1 to 4 that no node holds, or 0 when none is free (D25).
func firstFreeSlot(taken []int) int {
	for slot := 1; slot <= 4; slot++ {
		used := false
		for _, t := range taken {
			if t == slot {
				used = true
			}
		}
		if !used {
			return slot
		}
	}
	return 0
}

// ConfirmNodeEnrollment is POST /node-enrollments/{id}:confirm (4.2 step 4). All of it is one transaction under
// the lock of the record, so the node row, the approval and the audit row commit together or not at all.
func (s *Server) ConfirmNodeEnrollment(ctx context.Context, req gen.ConfirmNodeEnrollmentRequestObject) (gen.ConfirmNodeEnrollmentResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Body.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 {
		return nil, errValidation("name", "invalid")
	}
	typed := normalizeFingerprint(req.Body.Fingerprint)
	var nodeID uuid.UUID
	var slot int
	err = s.global(ctx, func(g store.GlobalTx) error {
		// The table check below reads the membership and then writes a row that joins it, so two confirmations or an
		// approval at the same moment must not both pass on rows the other is about to change.
		if err := g.NodePairsLock(); err != nil {
			return err
		}
		// The deferred trigger node_upstreams_no_loop also judges the row this route inserts, so the rule is asked
		// here, under the same lock as the address edit, to answer by name and not as a bare constraint error.
		if err := g.NodeUpstreamsLock(); err != nil {
			return err
		}
		rec, spki, found, err := g.NodeEnrollmentLock(req.Id)
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		if rec.State != "pending_approval" || len(spki) == 0 {
			return errEnrollmentState()
		}
		if typed != rec.Fingerprint {
			return httpx.New(http.StatusUnprocessableEntity, httpx.CodeFingerprintMismatch)
		}
		known, err := g.NodeKeyKnown(spki)
		if err != nil {
			return err
		}
		if known {
			return httpx.New(http.StatusConflict, httpx.CodeNodeKeyReused)
		}
		// The record's addresses were written by the node. The same rules as the request of step 1 apply
		// again, because a record is what the host said, not what the admin chose.
		if rec.DNSBind == nil || rec.DNSAdv == nil {
			return errAddress("dns_bind_ip")
		}
		if nodeadmin.CheckBind(*rec.DNSBind) != nil {
			return errAddress("dns_bind_ip")
		}
		if nodeadmin.CheckAdvertised(*rec.DNSAdv) != nil {
			return errAddress("dns_advertised_ip")
		}
		if rec.ProxyBind != nil && nodeadmin.CheckBind(*rec.ProxyBind) != nil {
			return errAddress("proxy_bind_ip")
		}
		if rec.ProxyAdv != nil && nodeadmin.CheckAdvertised(*rec.ProxyAdv) != nil {
			return errAddress("proxy_advertised_ip")
		}
		for _, a := range []netip.Addr{*rec.DNSAdv, *rec.DNSBind} {
			if loops, err := g.UpstreamLoops(a); err != nil {
				return err
			} else if loops {
				return httpx.New(http.StatusConflict, httpx.CodeUpstreamLoop)
			}
		}
		taken, err := g.NodeSlotsTaken()
		if err != nil {
			return err
		}
		if slot = firstFreeSlot(taken); slot == 0 {
			return httpx.New(http.StatusConflict, httpx.CodeNodeLimitReached)
		}
		nn := store.NewNode{Slot: slot, Name: name, DNSBind: *rec.DNSBind, DNSAdv: *rec.DNSAdv, SPKI: spki}
		if rec.ProxyBind != nil {
			nn.ProxyBind = *rec.ProxyBind
		}
		if rec.ProxyAdv != nil {
			nn.ProxyAdv = *rec.ProxyAdv
		}
		if nodeID, err = g.NodeInsert(nn); err != nil {
			return err
		}
		// The table the log would carry once this node is approved must be one every node accepts (SC 8a.4,
		// Valid table): a node that repeats an address in use, or has no proxy address, is refused here and
		// not at the approval. The inserted row is read back in the same transaction.
		nodes, pairs, global, err := g.NodeMembership()
		if err != nil {
			return err
		}
		if terr := nodeadmin.CheckMembership(&nodeadmin.Membership{Nodes: nodes, Pairs: pairs, Global: global}, nodeID); terr != nil {
			return tableInvalid(terr)
		}
		if err := g.NodeEnrollmentApprove(req.Id, nodeID, p.AdminID); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeEnrollmentConfirm{Enrollment: req.Id, Node: nodeID, Slot: slot})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.ConfirmNodeEnrollment201JSONResponse{NodeId: nodeID, Slot: slot}, nil
}

// tableInvalid is the answer for a PairTable the shared validators refuse. The reason is the validator's
// stable phrase (a field and a rule, never a value) folded into the alphabet of an error code.
func tableInvalid(err error) *httpx.Error {
	reason := "invalid"
	if te, ok := err.(*nodeadmin.TableError); ok {
		reason = te.Reason
	}
	var b strings.Builder
	for _, c := range strings.ToLower(reason) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '.', c == '-':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	code := b.String()
	if code == "" || code[0] < 'a' || code[0] > 'z' {
		code = "t" + code
	}
	if len(code) > 64 {
		code = code[:64]
	}
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeTableInvalid).WithFields(httpx.FieldError{Name: "pair_table", Code: code})
}

// RejectNodeEnrollment is POST /node-enrollments/{id}:reject.
func (s *Server) RejectNodeEnrollment(ctx context.Context, req gen.RejectNodeEnrollmentRequestObject) (gen.RejectNodeEnrollmentResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		rec, _, found, err := g.NodeEnrollmentLock(req.Id)
		if err != nil {
			return err
		}
		if !found {
			return httpx.NotFound()
		}
		if rec.State != "issued" && rec.State != "pending_approval" {
			return errEnrollmentState()
		}
		if err := g.NodeEnrollmentReject(req.Id); err != nil {
			return err
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.NodeEnrollmentReject{Enrollment: req.Id})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.RejectNodeEnrollment204Response{}, nil
}

// versionInfo reads the fields of the hub's Heartbeat summary that the page shows. The hub writes the JSON
// (p4-nodes 3.2 item 8); a field of another type than the one expected is left out, so a change on the hub's
// side shows as a missing value and never as an error of the page.
type versionInfo struct {
	nodeVersion, unboundVersion, catalogVersion string
	blobMajorMax, quarantined, qps, cacheHit    *int
	isolated                                    *bool
}

func parseVersionInfo(raw []byte) versionInfo {
	var m map[string]json.RawMessage
	var v versionInfo
	if json.Unmarshal(raw, &m) != nil {
		return v
	}
	str := func(key string, max int) string {
		var s string
		if json.Unmarshal(m[key], &s) == nil && len(s) <= max && !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			return s
		}
		var n json.Number
		if json.Unmarshal(m[key], &n) == nil && len(n) <= max {
			return n.String()
		}
		return ""
	}
	num := func(key string, lo, hi int) *int {
		var n int
		if json.Unmarshal(m[key], &n) == nil && n >= lo && n <= hi {
			return &n
		}
		return nil
	}
	v.nodeVersion, v.unboundVersion, v.catalogVersion = str("node_version", 64), str("unbound_version", 64), str("catalog_version", 64)
	v.blobMajorMax = num("blob_major_max", 0, 65535)
	v.quarantined = num("quarantined", 0, 1<<31-1)
	v.qps = num("qps", 0, 1<<31-1)
	v.cacheHit = num("cache_hit_permille", 0, 1000)
	var b bool
	if json.Unmarshal(m["isolated"], &b) == nil {
		v.isolated = &b
	}
	return v
}

func nodeView(n store.NodeRow) gen.NodeView {
	vi := parseVersionInfo(n.VersionInfo)
	lag := n.ConfigHead - n.AppliedSeq
	if lag < 0 {
		lag = 0
	}
	return gen.NodeView{
		Id: n.ID, Slot: n.Slot, Name: n.Name, Status: gen.NodeViewStatus(n.Status), ResolveMode: gen.NodeViewResolveMode(n.ResolveMode),
		ProxyBlocked: n.ProxyBlocked, DnsBindIp: addrText(n.DNSBind), DnsAdvertisedIp: addrText(n.DNSAdv),
		ProxyBindIp: addrText(n.ProxyBind), ProxyAdvertisedIp: addrText(n.ProxyAdv), KeyFingerprint: nonEmpty(n.SPKIHex),
		CreatedAt: n.CreatedAt.UTC(), LastHeartbeatAt: timePtr(n.LastHeartbeatAt),
		NodeVersion: nonEmpty(vi.nodeVersion), UnboundVersion: nonEmpty(vi.unboundVersion), CatalogVersion: nonEmpty(vi.catalogVersion),
		BlobMajorMax: vi.blobMajorMax, Isolated: vi.isolated, Quarantined: vi.quarantined, Qps: vi.qps, CacheHitPermille: vi.cacheHit,
		AppliedSeq: n.AppliedSeq, ConfigHead: n.ConfigHead, AppliedSeqLag: lag,
		DnsWithdrawn: n.DNSWithdrawn, DnsHold: n.DNSHold, DnsLastFailbackAt: timePtr(n.DNSLastFailback), DnsFlapUntil: timePtr(n.DNSFlapUntil),
		PairPeerId: n.PairPeer, PendingRequests: n.PendingRequests,
	}
}

// ListNodes is GET /nodes.
func (s *Server) ListNodes(ctx context.Context, req gen.ListNodesRequestObject) (gen.ListNodesResponseObject, error) {
	after, err := uuidCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.NodePage{Items: []gen.NodeView{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.NodesPage(after, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(rows[len(rows)-1].ID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, nodeView(r))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListNodes200JSONResponse(out), nil
}

// GetNode is GET /nodes/{id}.
func (s *Server) GetNode(ctx context.Context, req gen.GetNodeRequestObject) (gen.GetNodeResponseObject, error) {
	var v gen.NodeView
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		n, ok, err := g.NodeGet(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		v = nodeView(n)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetNode200JSONResponse(v), nil
}

// The audit actions whose params record the addresses a node gave up (SC 8a.4, Addresses given up). The routes
// that remove a node and edit its advertised addresses write them with the params old_dns_ip, old_proxy_ip
// and name; the page reads them back here.
const (
	auditNodeRemove         = "node.remove"
	auditNodeAddressesEdit  = "node.addresses_change"
	givenUpScan             = 200
	givenUpParamDNS         = "old_dns_ip"
	givenUpParamProxy       = "old_proxy_ip"
	givenUpParamName        = "name"
	givenUpTargetNodePrefix = "node:"
)

// ListAddressesGivenUp is GET /nodes/addresses-given-up. The panel can neither see nor enforce what happens to
// an address after it is given up, so the list is a warning: each address, the node and the time, and the date
// from which giving it back to the provider is safe. An address a node row holds again is not given up.
func (s *Server) ListAddressesGivenUp(ctx context.Context, _ gen.ListAddressesGivenUpRequestObject) (gen.ListAddressesGivenUpResponseObject, error) {
	out := gen.AddressesGivenUp{Items: []gen.AddressGivenUp{}}
	now := s.now()
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.AddressesGivenUpRows([]string{auditNodeRemove, auditNodeAddressesEdit}, givenUpScan)
		if err != nil {
			return err
		}
		held, err := g.NodeAddressesHeld()
		if err != nil {
			return err
		}
		isHeld := func(a netip.Addr) bool {
			for _, h := range held {
				if h == a {
					return true
				}
			}
			return false
		}
		// Rows come newest first, and an address counts from the newest row that gave it up: an earlier row of the
		// same address (an edit that kept it, or a node that took it back and gave it up again) would show a date
		// before the node stopped serving it plus the wait, and the list is the only guard against an early return.
		seen := map[netip.Addr]bool{}
		for _, r := range rows {
			safe := r.At.Add(addressWait)
			if !safe.After(now) {
				continue
			}
			var params map[string]any
			if json.Unmarshal(r.Params, &params) != nil {
				continue
			}
			var node *uuid.UUID
			if id, err := uuid.Parse(strings.TrimPrefix(r.Target, givenUpTargetNodePrefix)); err == nil && strings.HasPrefix(r.Target, givenUpTargetNodePrefix) {
				node = &id
			}
			var nodeName *string
			if nm, ok := params[givenUpParamName].(string); ok && nm != "" && nm != string(audit.NodeNameInvalid) && utf8.RuneCountInString(nm) <= 64 {
				nodeName = &nm
			}
			for _, k := range []struct {
				param string
				kind  gen.AddressGivenUpKind
			}{{givenUpParamDNS, "dns"}, {givenUpParamProxy, "proxy"}} {
				text, _ := params[k.param].(string)
				a, err := nodeadmin.ParseAddr(text)
				if err != nil || isHeld(a) || seen[a] {
					continue
				}
				seen[a] = true
				out.Items = append(out.Items, gen.AddressGivenUp{
					Address: nodeadmin.AddrText(a), Kind: k.kind, NodeId: node, NodeName: nodeName,
					GivenUpAt: r.At.UTC(), SafeFrom: safe.UTC(),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out.Items) > givenUpLimit {
		out.Items = out.Items[:givenUpLimit]
	}
	return gen.ListAddressesGivenUp200JSONResponse(out), nil
}

// GetNodeReports is GET /nodes/{id}/reports (4.5): after a suspected compromise the admin reads what the node
// reported that other people relied on, from the time of the suspicion. The report outlives the node row (the ids
// of the trace carry no foreign key), so a removed node answers too, and nothing is cut without saying so.
func (s *Server) GetNodeReports(ctx context.Context, req gen.GetNodeReportsRequestObject) (gen.GetNodeReportsResponseObject, error) {
	from := s.now().Add(-reportWindow)
	if req.Params.From != nil {
		from = *req.Params.From
	}
	var until *time.Time
	if req.Params.To != nil {
		u := req.Params.To.UTC()
		until = &u
	}
	out := gen.NodeReports{Claims: []gen.TakenClaim{}, KeptRows: []gen.KeptRow{}}
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		// One more than a page is read, to know whether a page is all there is.
		claims, err := g.NodeTakenClaims(req.Id, from.Unix(), until, reportLimit+1)
		if err != nil {
			return err
		}
		if len(claims) > reportLimit {
			claims = claims[:reportLimit]
			out.ClaimsTruncated = true
		}
		for _, c := range claims {
			out.Claims = append(out.Claims, gen.TakenClaim{
				TenantId: c.TenantID, EndpointId: c.EndpointID, ClaimId: c.ClaimID, Cidr: nodeadmin.PrefixText(c.CIDR), ConsumedAt: c.ConsumedAt.UTC(),
			})
		}
		progress, err := g.NodeRevokedProgress(req.Id)
		if err != nil {
			return err
		}
		out.KeptRows, out.KeptTruncated = keptRows(progress, req.Id)
		if len(out.Claims) > 0 || len(progress) > 0 {
			return nil
		}
		// Nothing to show: an id that never was is not_found, a node whose row was removed is an empty report.
		known, err := g.NodeExists(req.Id)
		if err != nil {
			return err
		}
		if !known {
			if known, err = g.NodeRemovedAudited(req.Id); err != nil {
				return err
			}
		}
		if !known {
			return httpx.NotFound()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetNodeReports200JSONResponse(out), nil
}

// keptRows reads the rows the node_revoked job left in place from its progress documents (8, Revoked node):
// `{"kept": [{"tenant_id": ..., "endpoint_id": ..., "node_id": ...}], "kept_total": n}`. A job covers every node it
// superseded, so an entry that names another node is not this node's report; an entry that names none is kept. A
// document of another shape adds nothing, and a row seen in two jobs is listed once. truncated is true when the
// worker's list was shorter than its exact kept_total, or the list here reached its bound.
func keptRows(docs []json.RawMessage, node uuid.UUID) (rows []gen.KeptRow, truncated bool) {
	rows = []gen.KeptRow{}
	seen := map[gen.KeptRow]bool{}
	for _, d := range docs {
		var p struct {
			Kept []struct {
				TenantID   uuid.UUID `json:"tenant_id"`
				EndpointID uuid.UUID `json:"endpoint_id"`
				NodeID     uuid.UUID `json:"node_id"`
			} `json:"kept"`
			KeptTotal int `json:"kept_total"`
		}
		if json.Unmarshal(d, &p) != nil {
			continue
		}
		if p.KeptTotal > len(p.Kept) {
			truncated = true
		}
		for _, k := range p.Kept {
			if k.NodeID != uuid.Nil && k.NodeID != node {
				continue
			}
			row := gen.KeptRow{TenantId: k.TenantID, EndpointId: k.EndpointID}
			if k.TenantID == uuid.Nil || k.EndpointID == uuid.Nil || seen[row] {
				continue
			}
			if len(rows) >= keptLimit {
				truncated = true
				continue
			}
			seen[row] = true
			rows = append(rows, row)
		}
	}
	return rows, truncated
}
