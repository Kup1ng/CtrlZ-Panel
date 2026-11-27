package wire

import (
	"bytes"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// Limits that keep one message from costing unbounded work at the receiver.
const (
	MaxRecordsPerEntry = 100_000
	MaxClientsPerEP    = 10_000
	MaxAuthorizedIPs   = 1_000
	MaxBitmapBytes     = 8192 // 65536 location ids
	MaxNodes           = 4

	// MaxSectionName bounds QuarantineReport.section. The longest section a
	// node can report is 13 bytes (grant_forward); 16 leaves room without
	// letting a node send free text. TestEverySectionFitsAReport keeps the
	// limit and the names in step.
	MaxSectionName = 16
)

// ValidatePrefix checks (addr, bits) and requires the host bits to be zero, so
// one network has exactly one encoding.
func ValidatePrefix(p *commonv1.Prefix) error {
	if p == nil {
		return bad(reason.BadSection, "prefix", "missing")
	}
	a, ok := netip.AddrFromSlice(p.Addr)
	if !ok || (len(p.Addr) != 4 && len(p.Addr) != 16) {
		return bad(reason.BadSection, "prefix", "address is %d bytes", len(p.Addr))
	}
	if int(p.Bits) > a.BitLen() {
		return bad(reason.BadEnum, "prefix", "%d bits on a %d-bit address", p.Bits, a.BitLen())
	}
	pfx, err := a.Prefix(int(p.Bits))
	if err != nil || pfx.Addr() != a {
		return bad(reason.BadSection, "prefix", "host bits set")
	}
	return nil
}

func validAdmin(s commonv1.AdminState) bool {
	return s >= commonv1.AdminState_ADMIN_STATE_ENABLED && s <= commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
}

func validAnalytics(a commonv1.AnalyticsLevel) bool {
	return a >= commonv1.AnalyticsLevel_ANALYTICS_LEVEL_NONE && a <= commonv1.AnalyticsLevel_ANALYTICS_LEVEL_FULL
}

func validProtocol(p commonv1.Protocol) bool {
	return p >= commonv1.Protocol_PROTOCOL_UDP && p <= commonv1.Protocol_PROTOCOL_DOH3
}

// ValidateStack checks a StackRecord. Profile 2 is optional.
func ValidateStack(s *policyv1.StackRecord) error {
	const w = "stack"
	if s == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := lenIs(w, "profile1_hash", s.Profile1Hash, 32); err != nil {
		return err
	}
	if len(s.Profile2Hash) != 0 {
		if err := lenIs(w, "profile2_hash", s.Profile2Hash, 32); err != nil {
			return err
		}
	}
	if len(s.MergedOptions) != 0 {
		if _, err := blob.ParseOptions(s.MergedOptions); err != nil {
			return err
		}
	}
	if s.MaxDepth > 127 {
		return bad(reason.BadEnum, w, "max_depth %d", s.MaxDepth)
	}
	return nil
}

// ValidateSchedule checks a ScheduleRecord against the same rules the
// compiler used to build it.
func ValidateSchedule(s *policyv1.ScheduleRecord) error {
	const w = "schedule"
	if s == nil {
		return nil
	}
	if len(s.Zone) > 64 {
		return bad(reason.BadSection, w, "zone name too long")
	}
	if len(s.Windows) > 255 {
		return bad(reason.BadEnum, w, "%d windows", len(s.Windows))
	}
	tr := make([]schedule.Transition, len(s.Transitions))
	for i, t := range s.Transitions {
		tr[i] = schedule.Transition{At: t.At, Offset: t.Offset}
	}
	if _, err := schedule.New(s.BaseOffset, tr, s.Grid, len(s.Windows)); err != nil {
		return bad(reason.BadSection, w, "%v", err)
	}
	seen := map[string]bool{}
	for _, win := range s.Windows {
		if err := lenIs(w, "window_id", win.GetWindowId(), 16); err != nil {
			return err
		}
		if seen[string(win.WindowId)] {
			return bad(reason.BadSection, w, "duplicate window_id")
		}
		seen[string(win.WindowId)] = true
		if err := ValidateStack(win.Stack); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEndpoint checks one EndpointRecord.
func ValidateEndpoint(e *policyv1.EndpointRecord) error {
	const w = "endpoint"
	if e == nil {
		return bad(reason.BadSection, w, "missing")
	}
	for _, f := range []struct {
		n string
		b []byte
		l int
	}{{"endpoint_id", e.EndpointId, 16}, {"rid_hash", e.RidHash, 16}, {"doh_token_hash", e.DohTokenHash, 32}, {"pair_id", e.PairId, 16}} {
		if err := lenIs(w, f.n, f.b, f.l); err != nil {
			return err
		}
	}
	if !validAdmin(e.AdminState) {
		return bad(reason.BadEnum, w, "admin_state %d", e.AdminState)
	}
	if !validAnalytics(e.AnalyticsLevel) {
		return bad(reason.BadEnum, w, "analytics_level %d", e.AnalyticsLevel)
	}
	if err := ValidateStack(e.Base); err != nil {
		return err
	}
	if err := ValidateSchedule(e.Schedule); err != nil {
		return err
	}
	if len(e.Clients) > MaxClientsPerEP || len(e.Authorized) > MaxAuthorizedIPs {
		return bad(reason.SizeCap, w, "too many clients or authorized prefixes")
	}
	seen := map[string]bool{}
	for _, c := range e.Clients {
		if err := lenIs(w, "client_id", c.GetClientId(), 16); err != nil {
			return err
		}
		if err := lenIs(w, "client_hash", c.GetClientHash(), 16); err != nil {
			return err
		}
		if seen[string(c.ClientHash)] {
			return bad(reason.BadSection, w, "duplicate client_hash")
		}
		seen[string(c.ClientHash)] = true
		if c.Stack != nil {
			if err := ValidateStack(c.Stack); err != nil {
				return err
			}
		}
		if c.HasAnalyticsOverride && !validAnalytics(c.AnalyticsOverride) {
			return bad(reason.BadEnum, w, "client analytics_override")
		}
	}
	for _, p := range e.Authorized {
		if err := ValidatePrefix(p); err != nil {
			return err
		}
	}
	return nil
}

// ValidateClaim checks a ClaimRecord.
func ValidateClaim(c *policyv1.ClaimRecord) error {
	const w = "claim"
	if c == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := lenIs(w, "claim_id", c.ClaimId, 16); err != nil {
		return err
	}
	if err := lenIs(w, "endpoint_id", c.EndpointId, 16); err != nil {
		return err
	}
	return ValidatePrefix(c.Prefix)
}

func validIP(b []byte) bool { return len(b) == 4 || len(b) == 16 }

// ValidateCatalog checks a CatalogRef.
func ValidateCatalog(c *policyv1.CatalogRef) error {
	const w = "catalog"
	if c == nil {
		return nil
	}
	if err := lenIs(w, "key", c.Key, 16); err != nil {
		return err
	}
	seen := map[uint32]bool{}
	for _, t := range c.Tables {
		if t.Kind < policyv1.TableKind_TABLE_KIND_FILTER || t.Kind > policyv1.TableKind_TABLE_KIND_CATEGORY {
			return bad(reason.BadEnum, w, "table kind %d", t.Kind)
		}
		if err := lenIs(w, "table hash", t.Hash, 32); err != nil {
			return err
		}
		k := t.WireId | uint32(t.Kind)<<30 // wire ids are unique per kind
		if seen[k] {
			return bad(reason.BadSection, w, "duplicate table wire_id")
		}
		seen[k] = true
	}
	locs := map[uint32]bool{}
	for _, l := range c.Locations {
		if l.WireId > 0xFFFF || locs[l.WireId] {
			return bad(reason.BadSection, w, "location wire_id %d", l.WireId)
		}
		locs[l.WireId] = true
		if len(l.Country) != 0 && len(l.Country) != 2 {
			return bad(reason.BadSection, w, "country must be two letters")
		}
	}
	return nil
}

// ValidateBlobRef checks a BlobRef against the size cap of its kind.
func ValidateBlobRef(b *policyv1.BlobRef) error {
	const w = "blob_ref"
	if b == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := lenIs(w, "hash", b.Hash, 32); err != nil {
		return err
	}
	switch b.Kind {
	case policyv1.BlobKind_BLOB_KIND_PROFILE:
		if b.Size > MaxProfileBlob {
			return bad(reason.SizeCap, w, "profile blob of %d bytes", b.Size)
		}
	case policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE:
		if b.Size > MaxBlockPageBlob {
			return bad(reason.SizeCap, w, "block page of %d bytes", b.Size)
		}
	default:
		return bad(reason.BadEnum, w, "kind %d", b.Kind)
	}
	return nil
}

// ValidateEntry checks a whole ConfigEntry, records included.
func ValidateEntry(e *policyv1.ConfigEntry) error {
	const w = "entry"
	if e == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if e.Seq == 0 {
		return bad(reason.BadEnum, w, "seq 0")
	}
	if e.Class != commonv1.EntryClass_ENTRY_CLASS_POLICY && e.Class != commonv1.EntryClass_ENTRY_CLASS_CATALOG {
		return bad(reason.BadEnum, w, "class %d", e.Class)
	}
	if err := lenIs(w, "prev_hash", e.PrevHash, 32); err != nil {
		return err
	}
	if e.CreatedAt < 0 {
		return bad(reason.BadEnum, w, "created_at %d", e.CreatedAt)
	}
	if len(e.PutBlobs)+len(e.DelBlobs)+len(e.PutEndpoints)+len(e.DelEndpoints)+len(e.PutClaims)+len(e.DelClaims) > MaxRecordsPerEntry {
		return bad(reason.SizeCap, w, "too many records")
	}
	seen := map[string]bool{}
	for _, b := range e.PutBlobs {
		if err := ValidateBlobRef(b); err != nil {
			return err
		}
		if seen[string(b.Hash)] {
			return bad(reason.BadSection, w, "blob listed twice")
		}
		seen[string(b.Hash)] = true
	}
	for _, h := range e.DelBlobs {
		if err := lenIs(w, "del_blobs", h, 32); err != nil {
			return err
		}
	}
	seen = map[string]bool{}
	for _, ep := range e.PutEndpoints {
		if err := ValidateEndpoint(ep); err != nil {
			return err
		}
		if seen[string(ep.EndpointId)] {
			return bad(reason.BadSection, w, "endpoint listed twice")
		}
		seen[string(ep.EndpointId)] = true
	}
	for _, id := range e.DelEndpoints {
		if err := lenIs(w, "del_endpoints", id, 16); err != nil {
			return err
		}
	}
	seen = map[string]bool{}
	for _, c := range e.PutClaims {
		if err := ValidateClaim(c); err != nil {
			return err
		}
		if seen[string(c.ClaimId)] {
			return bad(reason.BadSection, w, "claim listed twice")
		}
		seen[string(c.ClaimId)] = true
	}
	for _, id := range e.DelClaims {
		if err := lenIs(w, "del_claims", id, 16); err != nil {
			return err
		}
	}
	if err := ValidatePairTable(e.PairTable); err != nil {
		return err
	}
	if err := ValidateFreeDns(e.FreeDns); err != nil {
		return err
	}
	return ValidateCatalog(e.Catalog)
}

// ValidateRevocation checks a Revocation.
func ValidateRevocation(r *policyv1.Revocation) error {
	const w = "revocation"
	if r == nil || r.RevSeq == 0 {
		return bad(reason.BadEnum, w, "missing or rev_seq 0")
	}
	if r.Kind < policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT || r.Kind > policyv1.RevocationKind_REVOCATION_KIND_GRANTS_BY_ENDPOINT {
		return bad(reason.BadEnum, w, "kind %d", r.Kind)
	}
	if len(r.Ids) == 0 || len(r.Ids) > MaxRecordsPerEntry {
		return bad(reason.SizeCap, w, "%d ids", len(r.Ids))
	}
	for _, id := range r.Ids {
		if err := lenIs(w, "id", id, 16); err != nil {
			return err
		}
	}
	return nil
}

// ValidateNodeConfig checks a NodeConfig, including its resolver rules through
// the same parser the matcher uses.
func ValidateNodeConfig(c *hubv1.NodeConfig) error {
	const w = "node_config"
	if c == nil {
		return bad(reason.BadSection, w, "missing")
	}
	for _, ip := range [][]byte{c.DnsBindIp, c.DnsAdvertisedIp, c.ProxyBindIp, c.ProxyAdvertisedIp} {
		if !validIP(ip) {
			return bad(reason.BadSection, w, "address length")
		}
	}
	if len(c.Zones) == 0 || len(c.Zones) > 2 {
		return bad(reason.BadSection, w, "%d zones, want one or two", len(c.Zones))
	}
	for _, z := range append(append([]string(nil), c.Zones...), c.PanelHostnames...) {
		if _, err := names.ParseUser(z); err != nil {
			return bad(reason.BadName, w, "hostname %q: %v", z, err)
		}
	}
	if c.Mode < commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE || c.Mode > commonv1.ResolveMode_RESOLVE_MODE_HYBRID {
		return bad(reason.BadEnum, w, "mode %d", c.Mode)
	}
	if len(c.ProofKey) < 16 {
		return bad(reason.BadSection, w, "proof_key shorter than 16 bytes")
	}
	ups := map[string]bool{}
	for _, u := range c.Upstreams {
		if err := lenIs(w, "upstream id", u.GetId(), 16); err != nil {
			return err
		}
		// The id of the local Unbound is not an upstream row's (8a.7).
		if local := LocalUnboundID(); bytes.Equal(u.Id, local[:]) {
			return bad(reason.BadSection, w, "upstream id is the reserved local Unbound id")
		}
		if u.Kind < commonv1.UpstreamKind_UPSTREAM_KIND_UDP || u.Kind > commonv1.UpstreamKind_UPSTREAM_KIND_DOQ {
			return bad(reason.BadEnum, w, "upstream kind %d", u.Kind)
		}
		// An encrypted upstream named by hostname would need DNS to reach it,
		// which is circular; the contract requires an explicit bootstrap IP.
		if u.Kind != commonv1.UpstreamKind_UPSTREAM_KIND_UDP && !validIP(u.BootstrapIp) {
			return bad(reason.BadSection, w, "encrypted upstream without a bootstrap IP")
		}
		if u.TimeoutMs == 0 || u.TimeoutMs > 60_000 {
			return bad(reason.BadEnum, w, "timeout_ms %d", u.TimeoutMs)
		}
		ups[string(u.Id)] = true
	}
	groups := map[string]bool{}
	for _, g := range c.Groups {
		if g.Name == "" || groups[g.Name] {
			return bad(reason.BadSection, w, "group name empty or repeated")
		}
		groups[g.Name] = true
		for _, id := range g.UpstreamIds {
			if !ups[string(id)] {
				return bad(reason.IndexRange, w, "group %q names an unknown upstream", g.Name)
			}
		}
	}
	for _, r := range c.Rules {
		if _, err := route.ParseRule(r.Order, r.MatchType, r.MatchValue, r.Group, r.FinalDefault); err != nil {
			return bad(reason.BadSection, w, "rule %d: %v", r.Order, err)
		}
		if !groups[r.Group] {
			return bad(reason.IndexRange, w, "rule %d names an unknown group", r.Order)
		}
	}
	return nil
}

// Narrowest source prefix a peer may forward, by address family. Section 10.4
// allows /32, /24 and carrier widths, "chosen after field measurement"; these
// floors are the widest the contract can mean by carrier, so a peer that is
// stolen or buggy cannot forward a /0 that lets every source use the proxy for
// a name. A node with a measured policy passes its own floors to
// ValidateGrantForwardWidth.
const (
	MinGrantBits4 = 16
	MinGrantBits6 = 32
)

// ValidateGrantForward checks a peer GrantForward before it is considered,
// with the default width floors.
func ValidateGrantForward(g *peerv1.GrantForward, now int64) error {
	return ValidateGrantForwardWidth(g, now, MinGrantBits4, MinGrantBits6)
}

// grantPrefix decodes source_prefix: the address (4 or 16 bytes) followed by
// one byte of prefix length. It applies the ValidatePrefix rules (length fits
// the family, host bits zero) so one network has one encoding, and rejects an
// IPv4-mapped IPv6 address, which would be a second spelling of an IPv4 source.
func grantPrefix(b []byte) (netip.Prefix, error) {
	const w = "grant_forward"
	if len(b) != 5 && len(b) != 17 {
		return netip.Prefix{}, bad(reason.BadSection, w, "source_prefix is %d bytes", len(b))
	}
	addr, ok := netip.AddrFromSlice(b[:len(b)-1])
	if !ok {
		return netip.Prefix{}, bad(reason.BadSection, w, "source_prefix address")
	}
	if addr.Is4In6() {
		return netip.Prefix{}, bad(reason.BadSection, w, "source_prefix is an IPv4-mapped address")
	}
	bits := int(b[len(b)-1])
	if bits > addr.BitLen() {
		return netip.Prefix{}, bad(reason.BadEnum, w, "source_prefix: %d bits on a %d-bit address", bits, addr.BitLen())
	}
	pfx, err := addr.Prefix(bits)
	if err != nil || pfx.Addr() != addr {
		return netip.Prefix{}, bad(reason.BadSection, w, "source_prefix: host bits set")
	}
	return pfx, nil
}

// ValidateGrantForwardWidth is ValidateGrantForward with explicit minimum
// prefix lengths for IPv4 and IPv6 sources.
func ValidateGrantForwardWidth(g *peerv1.GrantForward, now int64, min4, min6 int) error {
	const w = "grant_forward"
	if g == nil {
		return bad(reason.BadSection, w, "missing")
	}
	for _, f := range []struct {
		n string
		b []byte
		l int
	}{{"grant_id", g.GrantId, 16}, {"endpoint_id", g.EndpointId, 16}} {
		if err := lenIs(w, f.n, f.b, f.l); err != nil {
			return err
		}
	}
	pfx, err := grantPrefix(g.SourcePrefix)
	if err != nil {
		return err
	}
	floor := min6
	if pfx.Addr().Is4() {
		floor = min4
	}
	if pfx.Bits() < floor {
		return bad(reason.BadEnum, w, "source_prefix /%d is wider than the /%d floor", pfx.Bits(), floor)
	}
	// The grant key is the exact qname; the root is never a name a client asked
	// for. A name must already be in folded form: FromCanonicalWire folds
	// rather than rejects, and two spellings of one key would break the table.
	name, err := names.FromCanonicalWire(g.NameWire)
	if err != nil {
		return bad(reason.BadName, w, "name_wire: %v", err)
	}
	if name.IsRoot() {
		return bad(reason.BadName, w, "name_wire is the root")
	}
	if !bytes.Equal(name.Wire(), g.NameWire) {
		return bad(reason.BadName, w, "name_wire is not in folded form")
	}
	if len(g.DialHostWire) != 0 {
		dial, err := names.FromCanonicalWire(g.DialHostWire)
		if err != nil {
			return bad(reason.BadName, w, "dial_host_wire: %v", err)
		}
		if !bytes.Equal(dial.Wire(), g.DialHostWire) {
			return bad(reason.BadName, w, "dial_host_wire is not in folded form")
		}
	}
	if g.Location > 0xFFFF {
		return bad(reason.BadEnum, w, "location %d", g.Location)
	}
	if g.GrantKind != 1 && g.GrantKind != 2 {
		return bad(reason.BadEnum, w, "grant_kind %d", g.GrantKind)
	}
	// A grant lives about four hours (10.4); anything claiming longer is wrong.
	if g.ExpiresAt <= now || g.ExpiresAt > now+5*3600 {
		return bad(reason.BadEnum, w, "expires_at out of range")
	}
	return nil
}

// ValidateQuarantineReport checks the report a node sends about a bad item.
func ValidateQuarantineReport(q *hubv1.QuarantineReport) error {
	const w = "quarantine_report"
	if q == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if q.Scope < hubv1.Scope_SCOPE_ENTRY || q.Scope > hubv1.Scope_SCOPE_RECORD {
		return bad(reason.BadEnum, w, "scope %d", q.Scope)
	}
	known := false
	for _, c := range reason.All() {
		if string(c) == q.Reason {
			known = true
		}
	}
	if !known {
		return bad(reason.BadEnum, w, "unknown reason %q", q.Reason)
	}
	if len(q.Section) > MaxSectionName {
		return bad(reason.BadSection, w, "section name too long")
	}
	return nil
}

// ValidateFreeDns checks the free DNS value of an entry or a snapshot (5.2a). A nil
// value is valid: an entry carries one only when it changes the value in force.
// qps is at least 1 so that enabled false is the one off state, and version is the
// settings row's, never 0.
func ValidateFreeDns(f *policyv1.FreeDns) error {
	const w = "free_dns"
	if f == nil {
		return nil
	}
	if f.Qps == 0 || f.Qps > MaxFreeQPS {
		return bad(reason.BadEnum, w, "qps %d", f.Qps)
	}
	if f.Version == 0 {
		return bad(reason.BadEnum, w, "version 0")
	}
	return nil
}

// ValidateFreeDnsOff checks the hub's message that raises a node's off floor
// (5.2a, Turning it off fast). The node refuses a version of 0.
func ValidateFreeDnsOff(m *hubv1.FreeDnsOff) error {
	if m == nil || m.Version == 0 {
		return bad(reason.BadEnum, "free_dns_off", "missing or version 0")
	}
	return nil
}
