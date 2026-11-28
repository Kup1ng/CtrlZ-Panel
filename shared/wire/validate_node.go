package wire

import (
	"bytes"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"unicode/utf8"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

// Limits of the node-to-hub messages and of the block page. The block page
// limits are counted in characters, the unit of the database CHECKs on
// block_pages (migration 0009), so a row the database accepts is a record this
// validator accepts.
const (
	MaxBlockTitleChars   = 120
	MaxBlockMessageChars = 2000
	MaxUnblockURLBytes   = 2048
	MaxUnblockNoteChars  = 500
	MaxVersionString     = 64
	MaxHeartbeatItems    = 1 << 16
	MaxPeerView          = 64 << 10
	// MaxHeartbeatQPS bounds Heartbeat.qps. A node is sized for 20,000 queries a second
	// (p4-nodes 11), so this is 50 times that: a lie shows on the Overview, but a real
	// reading is never refused. Provisional until the P5 load test (D31).
	MaxHeartbeatQPS = 1_000_000
	MaxAcmeTokenID  = 64
	MaxApplyMillis  = 3_600_000

	// MaxObservationAge and MaxObservationSkew bound the clock of an
	// observation against the receiver's: older than an hour is a replay or a
	// stuck queue (a proof challenge lives ten minutes), and more than five
	// minutes ahead is a wrong clock.
	MaxObservationAge  = 3600
	MaxObservationSkew = 300
)

// validText reports whether s is valid UTF-8 of at most max characters with no
// control character other than newline and tab when multiline is true.
func validText(s string, max int, multiline bool) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 && !(multiline && (r == '\n' || r == '\t')) || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidateBlockPage checks a BlockPage record before a node renders it or the
// API stores it. The page is served for a blocked domain, so its text is
// bounded and free of control characters, its logo is a content hash, and its
// unblock link can only be an https URL.
func ValidateBlockPage(b *policyv1.BlockPage) error {
	const w = "block_page"
	if b == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if !validText(b.Title, MaxBlockTitleChars, false) {
		return bad(reason.BadSection, w, "title is not valid text of at most %d characters", MaxBlockTitleChars)
	}
	if !validText(b.Message, MaxBlockMessageChars, true) {
		return bad(reason.BadSection, w, "message is not valid text of at most %d characters", MaxBlockMessageChars)
	}
	if len(b.LogoHash) != 0 {
		if err := lenIs(w, "logo_hash", b.LogoHash, 32); err != nil {
			return err
		}
	}
	if err := validateBlockLogo(b.Logo, b.LogoHash); err != nil {
		return err
	}
	// The node has no profile id of its own and an unblock request names one (3.4).
	if err := lenIs(w, "profile_id", b.ProfileId, 16); err != nil {
		return err
	}
	switch b.UnblockMode {
	case policyv1.UnblockMode_UNBLOCK_MODE_NONE, policyv1.UnblockMode_UNBLOCK_MODE_REQUEST:
		if b.UnblockUrl != "" {
			return bad(reason.BadSection, w, "unblock_url set for a mode that has none")
		}
	case policyv1.UnblockMode_UNBLOCK_MODE_URL:
		if err := validHTTPSURL(b.UnblockUrl); err != nil {
			return bad(reason.BadSection, w, "unblock_url: %v", err)
		}
	default:
		return bad(reason.BadEnum, w, "unblock_mode %d", b.UnblockMode)
	}
	return nil
}

var errURL = errors.New("not an https URL with a host")

// urlAuthority is the host and port the block_pages CHECK takes: letters, digits,
// dots and hyphens starting with a letter or digit, or an IPv6 literal in
// brackets, then an optional port. The URL parser alone is wider (an underscore,
// sub-delimiters, a percent escape, an IPv6 zone), and a link it takes that the
// table refuses would pass the API's validation and fail as a database error.
var urlAuthority = regexp.MustCompile(`^https://([A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:.]+\])(:[0-9]*)?([/?#]|$)`)

// validHTTPSURL accepts only https://host[:port]/path with no credentials, no
// control characters or spaces, and at most MaxUnblockURLBytes. A javascript:,
// data: or http: link, or one with a user part that disguises the host, is
// refused. Everything it accepts the block_pages CHECK accepts.
func validHTTPSURL(s string) error {
	if s == "" || len(s) > MaxUnblockURLBytes {
		return errURL
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return errURL
		}
	}
	// ParseRequestURI folds the scheme to lower case, but the block_pages CHECK is
	// a case-sensitive ^https://, so a link the parser accepts as HTTPS://... would
	// pass here and be refused by the table.
	if !urlAuthority.MatchString(s) {
		return errURL
	}
	u, err := url.ParseRequestURI(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Hostname() == "" {
		return errURL
	}
	return nil
}

// validSourceIP reports whether b is a client address in its one canonical
// byte form: 4 bytes for IPv4, 16 for IPv6, and never an IPv4-mapped IPv6
// address (::ffff:a.b.c.d). The mapped form is a second spelling of an IPv4
// source, and anything computed over the address text, such as the proof code,
// would differ between a sender that unmaps and a receiver that does not.
func validSourceIP(b []byte) bool {
	a, ok := netip.AddrFromSlice(b)
	return ok && !a.Is4In6()
}

// saneObservedAt reports whether t is a plausible observation time at receiver
// time now.
func saneObservedAt(w string, t, now int64) error {
	if t < now-MaxObservationAge || t > now+MaxObservationSkew {
		return bad(reason.BadEnum, w, "observed_at %d against the receiver's %d", t, now)
	}
	return nil
}

// ValidateProofObservation checks what a node reports for a query to a
// proof label: the label grammar, a 4 or 16 byte source address, a known
// transport and a plausible time. The hub derives the TXT code from exactly
// these three values, so each is checked before it reaches the HMAC.
func ValidateProofObservation(p *hubv1.ProofObservation, now int64) error {
	const w = "proof_observation"
	if p == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if !names.ValidVerifyLabel(p.Label) {
		return bad(reason.BadName, w, "label is not [a-z2-7]{26}")
	}
	if !validSourceIP(p.SourceIp) {
		return bad(reason.BadSection, w, "source_ip is not a 4-byte or 16-byte non-mapped address (%d bytes)", len(p.SourceIp))
	}
	if !validProtocol(p.Protocol) {
		return bad(reason.BadEnum, w, "protocol %d", p.Protocol)
	}
	// rid_hash names the resolver identity an encrypted query arrived on, and
	// plain DNS has none. Accepting the wrong shape for a protocol would let a
	// node (or a bug) make the hub's identity check pass or fail by omission.
	// A node never sends an encrypted observation for a connection that has no
	// identity (SC 3.5): it drops that report instead of padding rid_hash, and
	// the hub drops one that fails here and keeps the stream open.
	if encryptedProtocol(p.Protocol) {
		if err := lenIs(w, "rid_hash", p.RidHash, 16); err != nil {
			return err
		}
	} else if len(p.RidHash) != 0 {
		return bad(reason.BadSection, w, "rid_hash is %d bytes for a plain protocol, want none", len(p.RidHash))
	}
	return saneObservedAt(w, p.ObservedAt, now)
}

// encryptedProtocol reports whether a query on p carries a resolver identity.
// DoH3 carries the same resolver identity as DoH (D51, T-548).
func encryptedProtocol(p commonv1.Protocol) bool {
	switch p {
	case commonv1.Protocol_PROTOCOL_DOH, commonv1.Protocol_PROTOCOL_DOH3, commonv1.Protocol_PROTOCOL_DOT, commonv1.Protocol_PROTOCOL_DOQ:
		return true
	}
	return false
}

// ValidateLearnedIP checks an address a node learned for an Endpoint.
func ValidateLearnedIP(l *hubv1.LearnedIP, now int64) error {
	const w = "learned_ip"
	if l == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := lenIs(w, "endpoint_id", l.EndpointId, 16); err != nil {
		return err
	}
	if !validSourceIP(l.SourceIp) {
		return bad(reason.BadSection, w, "source_ip is not a 4-byte or 16-byte non-mapped address (%d bytes)", len(l.SourceIp))
	}
	if !validProtocol(l.Protocol) {
		return bad(reason.BadEnum, w, "protocol %d", l.Protocol)
	}
	return saneObservedAt(w, l.ObservedAt, now)
}

// ValidateBlockUnblockRequest checks an unblock request typed on a block page.
// The message is the visitor's own text and is bounded like any other free text.
func ValidateBlockUnblockRequest(r *hubv1.BlockUnblockRequest, now int64) error {
	const w = "block_unblock_request"
	if r == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if err := lenIs(w, "endpoint_id", r.EndpointId, 16); err != nil {
		return err
	}
	// unblock_requests.profile_id is NOT NULL, and the node knows it only from the
	// block page blob (3.4).
	if err := lenIs(w, "profile_id", r.ProfileId, 16); err != nil {
		return err
	}
	n, err := names.FromCanonicalWire(r.QnameWire)
	if err != nil {
		return bad(reason.BadName, w, "qname_wire: %v", err)
	}
	if n.IsRoot() {
		return bad(reason.BadName, w, "qname_wire is the root")
	}
	if !validText(r.Message, MaxUnblockNoteChars, true) {
		return bad(reason.BadSection, w, "message is not valid text of at most %d characters", MaxUnblockNoteChars)
	}
	return saneObservedAt(w, r.At, now)
}

func validVersion(s string) bool { return validText(s, MaxVersionString, false) }

// ValidateHeartbeat checks a node's periodic report. node_time is not compared
// with the receiver's clock here: the hub uses the difference to detect skew
// and must see it. Everything else is bounded.
func ValidateHeartbeat(h *hubv1.Heartbeat) error {
	const w = "heartbeat"
	if h == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if h.NodeTime < 0 {
		return bad(reason.BadEnum, w, "node_time %d", h.NodeTime)
	}
	for _, v := range []string{h.NodeVersion, h.XrayVersion, h.UnboundVersion} {
		if !validVersion(v) {
			return bad(reason.BadSection, w, "a version string is not valid text of at most %d characters", MaxVersionString)
		}
	}
	// The compiler may not emit a major above the lowest value among
	// non-revoked nodes (9.6), and no real major is below 1, so a 0 from a
	// buggy or hostile node would stop every emission until it is revoked.
	if h.BlobMajorMax < 1 || h.BlobMajorMax > 255 {
		return bad(reason.BadEnum, w, "blob_major_max %d", h.BlobMajorMax)
	}
	if h.Qps > MaxHeartbeatQPS || h.CacheHitPermille > 1000 {
		return bad(reason.BadEnum, w, "qps %d or cache_hit_permille %d out of range", h.Qps, h.CacheHitPermille)
	}
	if len(h.Upstreams) > MaxHeartbeatItems || len(h.Locations) > MaxHeartbeatItems {
		return bad(reason.SizeCap, w, "too many upstreams or locations")
	}
	// The local Unbound reports under its reserved id (8a.4), once.
	local := LocalUnboundID()
	locals := 0
	for _, u := range h.Upstreams {
		if err := lenIs(w, "upstream id", u.GetId(), 16); err != nil {
			return err
		}
		if bytes.Equal(u.Id, local[:]) {
			if locals++; locals > 1 {
				return bad(reason.BadSection, w, "the local Unbound is listed twice")
			}
		}
	}
	seen := map[uint32]bool{}
	for _, l := range h.Locations {
		if l.Location > 0xFFFF || seen[l.Location] {
			return bad(reason.BadEnum, w, "location %d repeated or out of range", l.Location)
		}
		seen[l.Location] = true
	}
	if _, err := ValidatePeerView(h.PeerView); err != nil {
		return err
	}
	return validateHeartbeatP4b(h)
}

// ValidateApplyResult checks a node's answer about one applied entry.
func ValidateApplyResult(a *hubv1.ApplyResult) error {
	const w = "apply_result"
	if a == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if a.Seq == 0 {
		return bad(reason.BadEnum, w, "seq 0")
	}
	if a.ApplyMs > MaxApplyMillis {
		return bad(reason.BadEnum, w, "apply_ms %d", a.ApplyMs)
	}
	return nil
}

// errUnhandledBody is what ValidateNodeMessage returns for a oneof member it
// has no case for. A test lists the members of NodeMessage from the descriptor
// and fails on this error, so adding a message to the proto without a validator
// breaks the build instead of reaching the hub unchecked.
var errUnhandledBody = errors.New("wire: NodeMessage body without a validator")

// ValidateNodeMessage is the one door for a message from a node: the hub calls
// it on every NodeMessage before it looks inside. now is the hub's clock in
// Unix seconds.
func ValidateNodeMessage(m *hubv1.NodeMessage, now int64) error {
	if m == nil {
		return bad(reason.BadSection, "node_message", "missing")
	}
	switch b := m.Body.(type) {
	case *hubv1.NodeMessage_Heartbeat:
		return ValidateHeartbeat(b.Heartbeat)
	case *hubv1.NodeMessage_ApplyResult:
		return ValidateApplyResult(b.ApplyResult)
	case *hubv1.NodeMessage_QuarantineReport:
		return ValidateQuarantineReport(b.QuarantineReport)
	case *hubv1.NodeMessage_RevocationAck:
		if b.RevocationAck == nil || b.RevocationAck.RevSeq == 0 {
			return bad(reason.BadEnum, "revocation_ack", "rev_seq 0")
		}
		return nil
	case *hubv1.NodeMessage_AcmeAck:
		if n := len(b.AcmeAck.GetTokenId()); n == 0 || n > MaxAcmeTokenID {
			return bad(reason.BadSection, "acme_ack", "token_id is %d bytes", n)
		}
		return nil
	case *hubv1.NodeMessage_LearnedIp:
		return ValidateLearnedIP(b.LearnedIp, now)
	case *hubv1.NodeMessage_ProofObservation:
		return ValidateProofObservation(b.ProofObservation, now)
	case *hubv1.NodeMessage_BlockUnblockRequest:
		return ValidateBlockUnblockRequest(b.BlockUnblockRequest, now)
	case *hubv1.NodeMessage_BlockKeyRequest:
		return ValidateBlockKeyRequest(b.BlockKeyRequest)
	case nil:
		return bad(reason.BadSection, "node_message", "empty body")
	}
	return errUnhandledBody
}
