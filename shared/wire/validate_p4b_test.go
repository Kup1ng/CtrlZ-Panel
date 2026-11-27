package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"google.golang.org/protobuf/proto"
)

// tinyPNG is the 33-byte start of a PNG with the given sides: the signature and
// an IHDR chunk. validPNGHeader reads nothing more.
func tinyPNG(w, h uint32) []byte {
	b := []byte(pngSignature)
	b = binary.BigEndian.AppendUint32(b, 13)
	b = append(b, "IHDR"...)
	b = binary.BigEndian.AppendUint32(b, w)
	b = binary.BigEndian.AppendUint32(b, h)
	return append(b, 8, 6, 0, 0, 0, 0, 0, 0, 0)
}

func pageWithLogo(logo []byte) *policyv1.BlockPage {
	p := &policyv1.BlockPage{ProfileId: make([]byte, 16), UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE, Logo: logo}
	if logo != nil {
		sum := sha256.Sum256(logo)
		p.LogoHash = sum[:]
	}
	return p
}

func TestValidateBlockPageLogoAndProfile(t *testing.T) {
	if err := ValidateBlockPage(pageWithLogo(tinyPNG(64, 64))); err != nil {
		t.Fatalf("a good logo: %v", err)
	}
	big := append(tinyPNG(10, 10), make([]byte, MaxBlockLogo)...)
	hashOnly := pageWithLogo(nil)
	hashOnly.LogoHash = make([]byte, 32)
	wrongHash := pageWithLogo(tinyPNG(64, 64))
	wrongHash.LogoHash[0] ^= 1
	noProfile := pageWithLogo(nil)
	noProfile.ProfileId = nil
	for name, p := range map[string]*policyv1.BlockPage{
		"hash without logo":    hashOnly,
		"logo without hash":    {ProfileId: make([]byte, 16), Logo: tinyPNG(8, 8)},
		"hash is not the logo": wrongHash,
		"logo over 256 KiB":    pageWithLogo(big),
		"not a PNG":            pageWithLogo([]byte(strings.Repeat("x", 64))),
		"side of 1025":         pageWithLogo(tinyPNG(1025, 8)),
		"side of 0":            pageWithLogo(tinyPNG(0, 8)),
		"no profile id":        noProfile,
	} {
		if ValidateBlockPage(p) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// 256 KiB exactly passes: the limit is on the stored bytes.
	edge := append(tinyPNG(10, 10), make([]byte, MaxBlockLogo-33)...)
	if err := ValidateBlockPage(pageWithLogo(edge)); err != nil {
		t.Errorf("a logo of exactly %d bytes: %v", MaxBlockLogo, err)
	}
}

func TestValidateEndpointAccountHash(t *testing.T) {
	ok := func() *policyv1.EndpointRecord {
		return &policyv1.EndpointRecord{
			EndpointId: make([]byte, 16), RidHash: make([]byte, 16), DohTokenHash: make([]byte, 32), PairId: make([]byte, 16),
			AdminState: 1, AnalyticsLevel: 1, Base: &policyv1.StackRecord{Profile1Hash: make([]byte, 32)},
		}
	}
	if err := ValidateEndpoint(ok()); err != nil {
		t.Fatalf("no account_hash (a compiler of before P4b): %v", err)
	}
	e := ok()
	e.AccountHash = bytes.Repeat([]byte{3}, 16)
	if err := ValidateEndpoint(e); err != nil {
		t.Errorf("a 16-byte account_hash: %v", err)
	}
	for _, n := range []int{1, 15, 17, 32} {
		e.AccountHash = make([]byte, n)
		if ValidateEndpoint(e) == nil {
			t.Errorf("account_hash of %d bytes accepted", n)
		}
	}
}

func goodXrayConfig(i byte) *hubv1.XrayConfig {
	return &hubv1.XrayConfig{Id: bytes.Repeat([]byte{i}, 16), Location: 3, Tag: "main-1", Priority: 0, Enabled: true,
		FragmentJson: []byte(`{"outbounds":[]}`)}
}

func goodNodeConfig() *hubv1.NodeConfig {
	ip := []byte{10, 0, 0, 1}
	return &hubv1.NodeConfig{
		DnsBindIp: ip, DnsAdvertisedIp: ip, ProxyBindIp: ip, ProxyAdvertisedIp: ip,
		Zones: []string{"dns.ctrlz.test"}, Mode: 1, ProofKey: make([]byte, 32),
	}
}

func TestValidateNodeConfigP4b(t *testing.T) {
	c := goodNodeConfig()
	if err := ValidateNodeConfig(c); err != nil {
		t.Fatalf("a config with none of the P4b fields: %v", err)
	}
	c.GrantWidth = hubv1.GrantWidth_GRANT_WIDTH_CARRIER
	c.ProbeUrls = []string{"http://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"}
	c.XraySchemaVersion, c.XrayFetchVersion = "v26.11.9", "v26.11.9"
	c.BlockRootEpoch = make([]byte, 8)
	c.XrayConfigs = []*hubv1.XrayConfig{goodXrayConfig(1), goodXrayConfig(2)}
	c.XrayConfigs[0].AcceptedUnknown = []string{"outbounds[0].streamSettings.newKey", "outbounds[1].settings.vnext[0].x"}
	if err := ValidateNodeConfig(c); err != nil {
		t.Fatalf("a full P4b config: %v", err)
	}
	many := func() []*hubv1.XrayConfig {
		var cs []*hubv1.XrayConfig
		for i := 0; i < MaxXrayConfigs+1; i++ {
			x := goodXrayConfig(1)
			x.Id = binary.BigEndian.AppendUint64(make([]byte, 8), uint64(i+1))
			cs = append(cs, x)
		}
		return cs
	}
	mut := map[string]func(c *hubv1.NodeConfig){
		"grant_width 4": func(c *hubv1.NodeConfig) { c.GrantWidth = 4 },
		"three probe urls": func(c *hubv1.NodeConfig) {
			c.ProbeUrls = []string{"http://a.test/", "http://b.test/", "http://c.test/"}
		},
		"probe url with a user":  func(c *hubv1.NodeConfig) { c.ProbeUrls = []string{"http://u:p@a.test/"} },
		"probe url, file scheme": func(c *hubv1.NodeConfig) { c.ProbeUrls = []string{"file:///etc/passwd"} },
		"probe url with space":   func(c *hubv1.NodeConfig) { c.ProbeUrls = []string{"http://a.test/x y"} },
		"probe url too long": func(c *hubv1.NodeConfig) {
			c.ProbeUrls = []string{"http://a.test/" + strings.Repeat("a", MaxProbeURLBytes)}
		},
		"schema version, no v":              func(c *hubv1.NodeConfig) { c.XraySchemaVersion = "26.11.9" },
		"fetch version, suffix":             func(c *hubv1.NodeConfig) { c.XrayFetchVersion = "v26.11.9-rc1" },
		"fetch version, path":               func(c *hubv1.NodeConfig) { c.XrayFetchVersion = "v1.2.3/../x" },
		"epoch of 7 bytes":                  func(c *hubv1.NodeConfig) { c.BlockRootEpoch = make([]byte, 7) },
		"65 configs":                        func(c *hubv1.NodeConfig) { c.XrayConfigs = many() },
		"config id twice":                   func(c *hubv1.NodeConfig) { c.XrayConfigs = []*hubv1.XrayConfig{goodXrayConfig(1), goodXrayConfig(1)} },
		"config id of 15":                   func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Id = make([]byte, 15) },
		"config location 65536":             func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Location = 1 << 16 },
		"tag with capital":                  func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Tag = "Main" },
		"tag starting with dash":            func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Tag = "-a" },
		"tag of 33":                         func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Tag = strings.Repeat("a", 33) },
		"empty tag":                         func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Tag = "" },
		"priority 100":                      func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Priority = 100 },
		"disabled config":                   func(c *hubv1.NodeConfig) { c.XrayConfigs[0].Enabled = false },
		"fragment of 32 KiB + 1":            func(c *hubv1.NodeConfig) { c.XrayConfigs[0].FragmentJson = make([]byte, MaxXrayFragment+1) },
		"accepted path outside an outbound": func(c *hubv1.NodeConfig) { c.XrayConfigs[0].AcceptedUnknown = []string{"routing.rules"} },
		"accepted path, outbound 8":         func(c *hubv1.NodeConfig) { c.XrayConfigs[0].AcceptedUnknown = []string{"outbounds[8].x"} },
		"accepted path, no key":             func(c *hubv1.NodeConfig) { c.XrayConfigs[0].AcceptedUnknown = []string{"outbounds[0]"} },
		"accepted path twice": func(c *hubv1.NodeConfig) {
			c.XrayConfigs[0].AcceptedUnknown = []string{"outbounds[0].a", "outbounds[0].a"}
		},
		"accepted path with a space": func(c *hubv1.NodeConfig) { c.XrayConfigs[0].AcceptedUnknown = []string{"outbounds[0].a b"} },
	}
	for name, f := range mut {
		c := goodNodeConfig()
		c.XrayConfigs = []*hubv1.XrayConfig{goodXrayConfig(1)}
		f(c)
		if ValidateNodeConfig(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The sum limit alone: 64 rows of 32 KiB is exactly 2 MiB and passes.
	c = goodNodeConfig()
	for i := byte(1); i <= MaxXrayConfigs; i++ {
		x := goodXrayConfig(i)
		x.FragmentJson = make([]byte, MaxXrayFragment)
		c.XrayConfigs = append(c.XrayConfigs, x)
	}
	if err := ValidateNodeConfig(c); err != nil {
		t.Errorf("64 fragments of 32 KiB: %v", err)
	}
	// A stripped config (fragment_json empty) is valid: nodecfg stores it so.
	c = goodNodeConfig()
	x := goodXrayConfig(1)
	x.FragmentJson = nil
	c.XrayConfigs = []*hubv1.XrayConfig{x}
	if err := ValidateNodeConfig(c); err != nil {
		t.Errorf("a stripped config: %v", err)
	}
}

func TestValidateCertBundle(t *testing.T) {
	zone := func() *hubv1.CertBundle {
		return &hubv1.CertBundle{Kind: signv1.Kind_KIND_CERTS, WrappedKey: []byte{1}, ChainPem: []byte{2}, NotAfter: 1}
	}
	inter := func() *hubv1.CertBundle {
		b := zone()
		b.Use = hubv1.CertUse_CERT_USE_BLOCK_INTERMEDIATE
		b.AccountHash, b.BlockRootEpoch = make([]byte, 16), make([]byte, 8)
		return b
	}
	if err := ValidateCertBundle(zone()); err != nil {
		t.Errorf("a zone bundle: %v", err)
	}
	if err := ValidateCertBundle(inter()); err != nil {
		t.Errorf("an intermediate: %v", err)
	}
	bad := map[string]func() *hubv1.CertBundle{
		"nil":                          func() *hubv1.CertBundle { return nil },
		"zone with an account":         func() *hubv1.CertBundle { b := zone(); b.AccountHash = make([]byte, 16); return b },
		"zone with an epoch":           func() *hubv1.CertBundle { b := zone(); b.BlockRootEpoch = make([]byte, 8); return b },
		"intermediate without one":     func() *hubv1.CertBundle { b := inter(); b.AccountHash = nil; return b },
		"intermediate, short epoch":    func() *hubv1.CertBundle { b := inter(); b.BlockRootEpoch = make([]byte, 7); return b },
		"intermediate, no epoch":       func() *hubv1.CertBundle { b := inter(); b.BlockRootEpoch = nil; return b },
		"intermediate of another kind": func() *hubv1.CertBundle { b := inter(); b.Kind = signv1.Kind_KIND_XRAY; return b },
		"use 2":                        func() *hubv1.CertBundle { b := zone(); b.Use = 2; return b },
		"no key":                       func() *hubv1.CertBundle { b := zone(); b.WrappedKey = nil; return b },
		"no chain":                     func() *hubv1.CertBundle { b := zone(); b.ChainPem = nil; return b },
		"no expiry":                    func() *hubv1.CertBundle { b := zone(); b.NotAfter = 0; return b },
	}
	for name, f := range bad {
		if ValidateCertBundle(f()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func goodHeartbeat() *hubv1.Heartbeat {
	return &hubv1.Heartbeat{BlobMajorMax: 1}
}

func TestValidateHeartbeatP4b(t *testing.T) {
	h := goodHeartbeat()
	h.XrayConfigs = []*hubv1.XrayConfigState{{Id: make([]byte, 16), FragmentSha256: make([]byte, 32), State: hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_APPLIED, Healthy: true, LatencyMs: 40}}
	h.Proxy = &hubv1.ProxyState{Listening: true, OpenConnections: 12}
	h.Faults = []hubv1.NodeFault{hubv1.NodeFault_NODE_FAULT_NFT_FAILED, hubv1.NodeFault_NODE_FAULT_GRANTS_FULL}
	h.XrayUpgrade = &hubv1.XrayUpgradeState{Fetched: "v26.11.9", Version: "v26.11.9", Ok: false, FailedIds: [][]byte{make([]byte, 16)}}
	h.BindError = hubv1.BindError_BIND_ERROR_DNS_FAILED
	h.XrayVersion = "v26.11.9"
	if err := ValidateHeartbeat(h); err != nil {
		t.Fatalf("a full heartbeat: %v", err)
	}
	state := func(f func(s *hubv1.XrayConfigState)) func(h *hubv1.Heartbeat) {
		return func(h *hubv1.Heartbeat) {
			s := &hubv1.XrayConfigState{Id: make([]byte, 16), State: hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_PENDING}
			f(s)
			h.XrayConfigs = []*hubv1.XrayConfigState{s}
		}
	}
	mut := map[string]func(h *hubv1.Heartbeat){
		"state 0":            state(func(s *hubv1.XrayConfigState) { s.State = 0 }),
		"state 5":            state(func(s *hubv1.XrayConfigState) { s.State = 5 }),
		"id of 8":            state(func(s *hubv1.XrayConfigState) { s.Id = make([]byte, 8) }),
		"sha of 31":          state(func(s *hubv1.XrayConfigState) { s.FragmentSha256 = make([]byte, 31) }),
		"error of 501":       state(func(s *hubv1.XrayConfigState) { s.Error = strings.Repeat("e", 501) }),
		"error with control": state(func(s *hubv1.XrayConfigState) { s.Error = "x\x1b[0m" }),
		"two equal ids": func(h *hubv1.Heartbeat) {
			s := &hubv1.XrayConfigState{Id: make([]byte, 16), State: 1}
			h.XrayConfigs = []*hubv1.XrayConfigState{s, s}
		},
		"65 states": func(h *hubv1.Heartbeat) {
			for i := 0; i < 65; i++ {
				h.XrayConfigs = append(h.XrayConfigs, &hubv1.XrayConfigState{Id: binary.BigEndian.AppendUint64(make([]byte, 8), uint64(i)), State: 1})
			}
		},
		"fault 0":             func(h *hubv1.Heartbeat) { h.Faults = []hubv1.NodeFault{0} },
		"fault 6":             func(h *hubv1.Heartbeat) { h.Faults = []hubv1.NodeFault{6} },
		"a fault twice":       func(h *hubv1.Heartbeat) { h.Faults = []hubv1.NodeFault{2, 2} },
		"bind_error 5":        func(h *hubv1.Heartbeat) { h.BindError = 5 },
		"upgrade version bad": func(h *hubv1.Heartbeat) { h.XrayUpgrade = &hubv1.XrayUpgradeState{Version: "a\nb"} },
		// B1-r5-1: the hub copies the reports into NodeConfig.xray_schema_version, which
		// wants a release tag, so free text must stop here.
		"xray_version without v":     func(h *hubv1.Heartbeat) { h.XrayVersion = "26.11.9" },
		"xray_version is the banner": func(h *hubv1.Heartbeat) { h.XrayVersion = "Xray 26.11.9 (go1.27.3 linux/amd64)" },
		"upgrade fetched free text":  func(h *hubv1.Heartbeat) { h.XrayUpgrade = &hubv1.XrayUpgradeState{Fetched: "latest"} },
		"upgrade version without v":  func(h *hubv1.Heartbeat) { h.XrayUpgrade = &hubv1.XrayUpgradeState{Version: "26.11.9"} },
		"65 failed ids": func(h *hubv1.Heartbeat) {
			u := &hubv1.XrayUpgradeState{}
			for i := 0; i < 65; i++ {
				u.FailedIds = append(u.FailedIds, make([]byte, 16))
			}
			h.XrayUpgrade = u
		},
		"failed id of 4": func(h *hubv1.Heartbeat) {
			h.XrayUpgrade = &hubv1.XrayUpgradeState{FailedIds: [][]byte{make([]byte, 4)}}
		},
	}
	for name, f := range mut {
		h := goodHeartbeat()
		f(h)
		if ValidateHeartbeat(h) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidatePeerViewProxyFields(t *testing.T) {
	enc := func(p *hubv1.PeerProbe) []byte {
		b, err := EncodePeerView(&hubv1.PeerView{Peers: []*hubv1.PeerProbe{p}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	id := make([]byte, 16)
	if _, err := ValidatePeerView(enc(&hubv1.PeerProbe{NodeId: id, ProxyKnown: true, ProxyDown: true})); err != nil {
		t.Errorf("proxy down and known: %v", err)
	}
	if _, err := ValidatePeerView(enc(&hubv1.PeerProbe{NodeId: id, ProxyDown: true})); err == nil {
		t.Error("proxy_down with proxy_known false accepted")
	}
}

func TestValidateBlockKeyRequestThroughTheDoor(t *testing.T) {
	m := &hubv1.NodeMessage{Body: &hubv1.NodeMessage_BlockKeyRequest{BlockKeyRequest: &hubv1.BlockKeyRequest{EndpointId: make([]byte, 16)}}}
	if err := ValidateNodeMessage(m, 100); err != nil {
		t.Errorf("a block key request: %v", err)
	}
	for _, r := range []*hubv1.BlockKeyRequest{nil, {}, {EndpointId: make([]byte, 15)}} {
		if ValidateNodeMessage(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_BlockKeyRequest{BlockKeyRequest: r}}, 100) == nil {
			t.Errorf("request %v accepted", r)
		}
	}
}

// Every new message and field round-trips through the wire form, so a field
// number that clashes would show here before it shows on a node.
func TestP4bFieldsSurviveTheWire(t *testing.T) {
	g := &peerv1.GrantForward{ClientHash: bytes.Repeat([]byte{1}, 16)}
	b, _ := proto.Marshal(g)
	var back peerv1.GrantForward
	if err := proto.Unmarshal(b, &back); err != nil || !bytes.Equal(back.ClientHash, g.ClientHash) {
		t.Errorf("client_hash: %v", err)
	}
}

// FuzzValidateP4bMessages: whatever bytes arrive as a block page, a cert bundle, a
// grant forward or a node config of P4b, validating the decoded message never panics
// and a block page that passes has a logo that hashes to its logo_hash.
func FuzzValidateP4bMessages(f *testing.F) {
	logo := tinyPNG(8, 8)
	for _, m := range []proto.Message{
		pageWithLogo(logo),
		&hubv1.CertBundle{Kind: signv1.Kind_KIND_CERTS, WrappedKey: []byte{1}, ChainPem: []byte{2}, NotAfter: 1, Use: hubv1.CertUse_CERT_USE_BLOCK_INTERMEDIATE, AccountHash: make([]byte, 16), BlockRootEpoch: make([]byte, 8)},
		&peerv1.GrantForward{ClientHash: make([]byte, 16), SourcePrefix: []byte{1, 2, 3, 4, 32}},
	} {
		b, err := proto.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(0), b)
		f.Add(uint8(1), b)
		f.Add(uint8(2), b)
	}
	c := goodNodeConfig()
	c.XrayConfigs = []*hubv1.XrayConfig{goodXrayConfig(1)}
	cb, _ := proto.Marshal(c)
	f.Add(uint8(3), cb)
	f.Fuzz(func(t *testing.T, which uint8, data []byte) {
		switch which % 4 {
		case 0:
			var p policyv1.BlockPage
			if proto.Unmarshal(data, &p) == nil && ValidateBlockPage(&p) == nil && len(p.Logo) != 0 {
				if sum := sha256.Sum256(p.Logo); !bytes.Equal(sum[:], p.LogoHash) {
					t.Fatal("a block page passed with a logo that does not hash to logo_hash")
				}
			}
		case 1:
			var b hubv1.CertBundle
			if proto.Unmarshal(data, &b) == nil {
				_ = ValidateCertBundle(&b)
			}
		case 2:
			var g peerv1.GrantForward
			if proto.Unmarshal(data, &g) == nil {
				_ = ValidateGrantForward(&g, 100)
			}
		case 3:
			var nc hubv1.NodeConfig
			if proto.Unmarshal(data, &nc) == nil {
				_ = ValidateNodeConfig(&nc)
			}
		}
	})
}

// A value the enum has and the validator refuses would drop the whole Heartbeat of
// a node in exactly the incident that value reports (B1-r3-1, xray_stuck), so every
// value the generated enum holds is sent, and the one above the last is refused.
func TestValidateHeartbeatEveryNodeFault(t *testing.T) {
	values := hubv1.NodeFault(0).Descriptor().Values()
	last := hubv1.NodeFault(0)
	for i := 0; i < values.Len(); i++ {
		f := hubv1.NodeFault(values.Get(i).Number())
		if f > last {
			last = f
		}
		if f == hubv1.NodeFault_NODE_FAULT_UNSPECIFIED {
			continue
		}
		h := goodHeartbeat()
		h.Faults = []hubv1.NodeFault{f}
		if err := ValidateHeartbeat(h); err != nil {
			t.Errorf("fault %s: %v", f, err)
		}
	}
	h := goodHeartbeat()
	h.Faults = []hubv1.NodeFault{last + 1}
	if ValidateHeartbeat(h) == nil {
		t.Errorf("fault %d above the last value accepted", last+1)
	}
	if hubv1.NodeFault_NODE_FAULT_XRAY_STUCK != 5 {
		t.Errorf("xray_stuck is %d; p6-ops 7.4 starts its faults at 6", hubv1.NodeFault_NODE_FAULT_XRAY_STUCK)
	}
}
