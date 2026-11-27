package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// Limits added by P4b (p4b-proxy 3.4, 12). All D31 numbers: the P4b load test
// measures them.
const (
	// MaxXrayConfigs, MaxXrayFragment and MaxXrayFragments are the limits per node of
	// the config table: rows, one fragment, and all fragments together. The database
	// triggers and CHECKs hold the same numbers, so a row the database accepts is a
	// record this validator accepts.
	MaxXrayConfigs    = 64
	MaxXrayFragment   = 32 << 10
	MaxXrayFragments  = 2 << 20
	MaxXrayErrorChars = 500
	MaxXrayTagChars   = 32
	MaxXrayPriority   = 99
	// MaxAcceptedUnknown is the number of accept_unknown paths one config may hold.
	MaxAcceptedUnknown = 64
	MaxXrayFailedIDs   = 64
	// MaxBlockLogo is the largest logo PNG, and MaxBlockLogoSide the largest side its
	// header may declare (p4b-proxy 10.5).
	MaxBlockLogo     = 256 << 10
	MaxBlockLogoSide = 1024
	MaxProbeURLBytes = 256
	MaxProbeURLs     = 2
	// MaxCertBundlePEM bounds the chain and the wrapped key of a CertBundle. A zone
	// certificate with its chain is under 8 KiB; the block intermediate is smaller.
	MaxCertBundlePEM = 64 << 10
)

// validXrayTag is the config tag grammar of node_location_configs: [a-z0-9][a-z0-9-]{0,31}.
func validXrayTag(s string) bool {
	if s == "" || len(s) > MaxXrayTagChars {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i > 0 {
			continue
		}
		return false
	}
	return true
}

// validProbeURL: http or https, a host of letters, digits, dots and hyphens or an
// IPv6 literal, no user part, no control character or space, at most
// MaxProbeURLBytes. The probe of a location fetches it through the exit, so a
// scheme such as file: or a host with a user part would be a way to point the
// agent at something else.
func validProbeURL(s string) bool {
	if s == "" || len(s) > MaxProbeURLBytes {
		return false
	}
	rest := ""
	switch {
	case strings.HasPrefix(s, "http://"):
		rest = s[len("http://"):]
	case strings.HasPrefix(s, "https://"):
		rest = s[len("https://"):]
	default:
		return false
	}
	// validHTTPSURL holds the one grammar for host, port and path; the scheme was
	// judged above.
	return validHTTPSURL("https://"+rest) == nil
}

// validateXrayConfigs checks the rows of NodeConfig.xray_configs.
func validateXrayConfigs(cs []*hubv1.XrayConfig) error {
	const w = "node_config"
	if len(cs) > MaxXrayConfigs {
		return bad(reason.SizeCap, w, "%d xray configs", len(cs))
	}
	seen := map[string]bool{}
	total := 0
	for _, c := range cs {
		if c == nil {
			return bad(reason.BadSection, w, "empty xray config")
		}
		if err := lenIs(w, "xray config id", c.Id, 16); err != nil {
			return err
		}
		if seen[string(c.Id)] {
			return bad(reason.BadSection, w, "xray config listed twice")
		}
		seen[string(c.Id)] = true
		if c.Location > 0xFFFF {
			return bad(reason.BadEnum, w, "xray config location %d", c.Location)
		}
		if !validXrayTag(c.Tag) {
			return bad(reason.BadSection, w, "xray config tag is not [a-z0-9][a-z0-9-]{0,31}")
		}
		if c.Priority > MaxXrayPriority {
			return bad(reason.BadEnum, w, "xray config priority %d", c.Priority)
		}
		// Disabled rows are not sent: the hub filters them, and a node never has to
		// decide what a disabled config on the wire would mean.
		if !c.Enabled {
			return bad(reason.BadSection, w, "xray config is not enabled")
		}
		// fragment_json may be empty: nodecfg and the copy dns reads hold none (7.5).
		if len(c.FragmentJson) > MaxXrayFragment {
			return bad(reason.SizeCap, w, "xray fragment of %d bytes", len(c.FragmentJson))
		}
		if total += len(c.FragmentJson); total > MaxXrayFragments {
			return bad(reason.SizeCap, w, "xray fragments of %d bytes", total)
		}
		if len(c.AcceptedUnknown) > MaxAcceptedUnknown {
			return bad(reason.SizeCap, w, "%d accepted_unknown paths", len(c.AcceptedUnknown))
		}
		paths := map[string]bool{}
		for _, p := range c.AcceptedUnknown {
			if !xrayschema.ValidPath(p) || paths[p] {
				return bad(reason.BadSection, w, "accepted_unknown path is not a valid, distinct outbound path")
			}
			paths[p] = true
		}
	}
	return nil
}

// validateNodeConfigP4b checks the fields P4b added to NodeConfig.
func validateNodeConfigP4b(c *hubv1.NodeConfig) error {
	const w = "node_config"
	if c.GrantWidth < hubv1.GrantWidth_GRANT_WIDTH_UNSPECIFIED || c.GrantWidth > hubv1.GrantWidth_GRANT_WIDTH_CARRIER {
		return bad(reason.BadEnum, w, "grant_width %d", c.GrantWidth)
	}
	if len(c.ProbeUrls) > MaxProbeURLs {
		return bad(reason.SizeCap, w, "%d probe_urls", len(c.ProbeUrls))
	}
	for _, u := range c.ProbeUrls {
		if !validProbeURL(u) {
			return bad(reason.BadSection, w, "probe_url is not an http(s) URL with a plain host")
		}
	}
	for _, v := range []string{c.XraySchemaVersion, c.XrayFetchVersion} {
		if v != "" && !xrayschema.ValidReleaseTag(v) {
			return bad(reason.BadSection, w, "an xray release tag is not v<major>.<minor>.<patch>")
		}
	}
	if len(c.BlockRootEpoch) != 0 {
		if err := lenIs(w, "block_root_epoch", c.BlockRootEpoch, 8); err != nil {
			return err
		}
	}
	return validateXrayConfigs(c.XrayConfigs)
}

// pngSignature is the eight bytes every PNG starts with.
const pngSignature = "\x89PNG\r\n\x1a\n"

// validPNGHeader reports whether b starts like a PNG whose IHDR declares at most
// MaxBlockLogoSide on each side. It reads the header only: the panel re-encodes
// every logo, so a node meets a file its own encoder wrote, and what this check
// stops is a blob that never passed through the panel.
func validPNGHeader(b []byte) bool {
	if len(b) < 33 || string(b[:8]) != pngSignature {
		return false
	}
	if binary.BigEndian.Uint32(b[8:12]) != 13 || string(b[12:16]) != "IHDR" {
		return false
	}
	w, h := binary.BigEndian.Uint32(b[16:20]), binary.BigEndian.Uint32(b[20:24])
	return w >= 1 && h >= 1 && w <= MaxBlockLogoSide && h <= MaxBlockLogoSide
}

// validateBlockLogo checks logo and logo_hash together: both or neither, the hash
// is the SHA-256 of the bytes, and the bytes are a PNG of bounded size.
func validateBlockLogo(logo, hash []byte) error {
	const w = "block_page"
	if len(logo) == 0 && len(hash) == 0 {
		return nil
	}
	if len(logo) == 0 || len(hash) == 0 {
		return bad(reason.BadSection, w, "logo and logo_hash are set together or not at all")
	}
	if len(logo) > MaxBlockLogo {
		return bad(reason.SizeCap, w, "logo of %d bytes", len(logo))
	}
	if sum := sha256.Sum256(logo); !bytes.Equal(sum[:], hash) {
		return bad(reason.HashMismatch, w, "logo_hash is not the SHA-256 of the logo")
	}
	if !validPNGHeader(logo) {
		return bad(reason.BadSection, w, "logo is not a PNG of at most %d by %d", MaxBlockLogoSide, MaxBlockLogoSide)
	}
	return nil
}

// ValidateCertBundle checks a CertBundle, with the parts P4b added. A bundle of
// use zone has no account_hash and no block_root_epoch; one of use
// block_intermediate has both, so a node can file it under the right account and
// drop it when the epoch has moved (p4b-proxy 10.3). The chain and the wrapped key
// are judged where they are opened.
func ValidateCertBundle(b *hubv1.CertBundle) error {
	const w = "cert_bundle"
	if b == nil {
		return bad(reason.BadSection, w, "missing")
	}
	if len(b.WrappedKey) == 0 || len(b.WrappedKey) > MaxCertBundlePEM || len(b.ChainPem) == 0 || len(b.ChainPem) > MaxCertBundlePEM {
		return bad(reason.SizeCap, w, "wrapped_key of %d bytes or chain_pem of %d", len(b.WrappedKey), len(b.ChainPem))
	}
	if b.NotAfter <= 0 {
		return bad(reason.BadEnum, w, "not_after %d", b.NotAfter)
	}
	switch b.Use {
	case hubv1.CertUse_CERT_USE_UNSPECIFIED:
		if len(b.AccountHash) != 0 || len(b.BlockRootEpoch) != 0 {
			return bad(reason.BadSection, w, "account_hash or block_root_epoch on a zone bundle")
		}
	case hubv1.CertUse_CERT_USE_BLOCK_INTERMEDIATE:
		if err := lenIs(w, "account_hash", b.AccountHash, 16); err != nil {
			return err
		}
		if err := lenIs(w, "block_root_epoch", b.BlockRootEpoch, 8); err != nil {
			return err
		}
		if b.Kind != signv1.Kind_KIND_CERTS {
			return bad(reason.BadEnum, w, "kind %d on a block intermediate", b.Kind)
		}
	default:
		return bad(reason.BadEnum, w, "use %d", b.Use)
	}
	return nil
}

// validateHeartbeatP4b checks the Heartbeat fields P4b added.
func validateHeartbeatP4b(h *hubv1.Heartbeat) error {
	const w = "heartbeat"
	if len(h.XrayConfigs) > MaxXrayConfigs {
		return bad(reason.SizeCap, w, "%d xray_configs", len(h.XrayConfigs))
	}
	seen := map[string]bool{}
	for _, c := range h.XrayConfigs {
		if c == nil {
			return bad(reason.BadSection, w, "empty xray_configs item")
		}
		if err := lenIs(w, "xray config id", c.Id, 16); err != nil {
			return err
		}
		if seen[string(c.Id)] {
			return bad(reason.BadSection, w, "xray config reported twice")
		}
		seen[string(c.Id)] = true
		if len(c.FragmentSha256) != 0 {
			if err := lenIs(w, "fragment_sha256", c.FragmentSha256, 32); err != nil {
				return err
			}
		}
		if c.State < hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_PENDING || c.State > hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_LAST_GOOD {
			return bad(reason.BadEnum, w, "xray config state %d", c.State)
		}
		if !validText(c.Error, MaxXrayErrorChars, false) {
			return bad(reason.BadSection, w, "an xray config error is not valid text of at most %d characters", MaxXrayErrorChars)
		}
		if c.LatencyMs > MaxApplyMillis {
			return bad(reason.BadEnum, w, "xray config latency_ms %d", c.LatencyMs)
		}
	}
	faults := map[hubv1.NodeFault]bool{}
	for _, f := range h.Faults {
		if f < hubv1.NodeFault_NODE_FAULT_NFT_FAILED || f > hubv1.NodeFault_NODE_FAULT_XRAY_STUCK {
			return bad(reason.BadEnum, w, "fault %d", f)
		}
		if faults[f] {
			return bad(reason.BadSection, w, "fault %d listed twice", f)
		}
		faults[f] = true
	}
	if h.BindError < hubv1.BindError_BIND_ERROR_UNSPECIFIED || h.BindError > hubv1.BindError_BIND_ERROR_PROXY_FAILED {
		return bad(reason.BadEnum, w, "bind_error %d", h.BindError)
	}
	// The hub copies xray_version into NodeConfig.xray_schema_version, which
	// ValidateNodeConfig refuses unless it is a release tag; a free-text report would
	// turn into a config the node can never be sent (B1-r5-1), so the report is held to
	// the same form here. Empty stays valid: no node reports them yet.
	if h.XrayVersion != "" && !xrayschema.ValidReleaseTag(h.XrayVersion) {
		return bad(reason.BadSection, w, "xray_version is not a release tag v<major>.<minor>.<patch>")
	}
	if u := h.XrayUpgrade; u != nil {
		if !validVersion(u.Fetched) || !validVersion(u.Version) {
			return bad(reason.BadSection, w, "an xray_upgrade version is not valid text")
		}
		for _, v := range []string{u.Fetched, u.Version} {
			if v != "" && !xrayschema.ValidReleaseTag(v) {
				return bad(reason.BadSection, w, "an xray_upgrade version is not a release tag v<major>.<minor>.<patch>")
			}
		}
		if len(u.FailedIds) > MaxXrayFailedIDs {
			return bad(reason.SizeCap, w, "%d failed_ids", len(u.FailedIds))
		}
		for _, id := range u.FailedIds {
			if err := lenIs(w, "failed_id", id, 16); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateBlockKeyRequest checks a node's ask for a block page intermediate.
func ValidateBlockKeyRequest(r *hubv1.BlockKeyRequest) error {
	if r == nil {
		return bad(reason.BadSection, "block_key_request", "missing")
	}
	return lenIs("block_key_request", "endpoint_id", r.EndpointId, 16)
}
