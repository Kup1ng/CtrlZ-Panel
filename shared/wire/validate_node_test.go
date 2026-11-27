package wire

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const goodLabel = "abcdefghijklmnopqrstuvwxy2"

func TestValidateBlockPage(t *testing.T) {
	ok := func() *policyv1.BlockPage {
		return &policyv1.BlockPage{ProfileId: make([]byte, 16), Title: "Blocked", Message: "Line one\nline two",
			UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_URL, UnblockUrl: "https://example.com/unblock?id=1"}
	}
	if err := ValidateBlockPage(ok()); err != nil {
		t.Fatalf("a good page: %v", err)
	}
	if err := ValidateBlockPage(&policyv1.BlockPage{ProfileId: make([]byte, 16), UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE}); err != nil {
		t.Errorf("an empty page with mode none: %v", err)
	}
	if err := ValidateBlockPage(&policyv1.BlockPage{ProfileId: make([]byte, 16), Title: "سایت مسدود است", UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_REQUEST}); err != nil {
		t.Errorf("a Persian title: %v", err)
	}
	mut := map[string]func(*policyv1.BlockPage){
		"javascript link":      func(p *policyv1.BlockPage) { p.UnblockUrl = "javascript:alert(1)" },
		"data link":            func(p *policyv1.BlockPage) { p.UnblockUrl = "data:text/html,x" },
		"upper-case scheme":    func(p *policyv1.BlockPage) { p.UnblockUrl = "HTTPS://example.com/" },
		"mixed-case scheme":    func(p *policyv1.BlockPage) { p.UnblockUrl = "htTps://0" },
		"plain http":           func(p *policyv1.BlockPage) { p.UnblockUrl = "http://example.com/" },
		"underscore in host":   func(p *policyv1.BlockPage) { p.UnblockUrl = "https://a_b.example.com/" },
		"sub-delim in host":    func(p *policyv1.BlockPage) { p.UnblockUrl = "https://a!b.example.com/" },
		"tilde in host":        func(p *policyv1.BlockPage) { p.UnblockUrl = "https://a~b.example.com/" },
		"escape in host":       func(p *policyv1.BlockPage) { p.UnblockUrl = "https://a%C3%A9.example.com/" },
		"IPv6 zone":            func(p *policyv1.BlockPage) { p.UnblockUrl = "https://[2001:db8::1%25eth0]/" },
		"leading hyphen":       func(p *policyv1.BlockPage) { p.UnblockUrl = "https://-a.example.com/" },
		"user part":            func(p *policyv1.BlockPage) { p.UnblockUrl = "https://example.com@evil.example/" },
		"no host":              func(p *policyv1.BlockPage) { p.UnblockUrl = "https:///path" },
		"relative":             func(p *policyv1.BlockPage) { p.UnblockUrl = "/unblock" },
		"space in the link":    func(p *policyv1.BlockPage) { p.UnblockUrl = "https://example.com/a b" },
		"newline in the link":  func(p *policyv1.BlockPage) { p.UnblockUrl = "https://example.com/\nX" },
		"link of 2049 bytes":   func(p *policyv1.BlockPage) { p.UnblockUrl = "https://example.com/" + strings.Repeat("a", 2029) },
		"mode url without url": func(p *policyv1.BlockPage) { p.UnblockUrl = "" },
		"url with mode none": func(p *policyv1.BlockPage) {
			p.UnblockMode = policyv1.UnblockMode_UNBLOCK_MODE_NONE
		},
		"mode unspecified": func(p *policyv1.BlockPage) { p.UnblockMode = 0 },
		"mode 9":           func(p *policyv1.BlockPage) { p.UnblockMode = 9 },
		"title 121 chars":  func(p *policyv1.BlockPage) { p.Title = strings.Repeat("a", 121) },
		"title newline":    func(p *policyv1.BlockPage) { p.Title = "a\nb" },
		"title NUL":        func(p *policyv1.BlockPage) { p.Title = "a\x00b" },
		"title invalid":    func(p *policyv1.BlockPage) { p.Title = "a\xffb" },
		"message huge":     func(p *policyv1.BlockPage) { p.Message = strings.Repeat("a", 2001) },
		"message escape":   func(p *policyv1.BlockPage) { p.Message = "a\x1b[2J" },
		"logo of 31 bytes": func(p *policyv1.BlockPage) { p.LogoHash = make([]byte, 31) },
	}
	for name, f := range mut {
		p := ok()
		f(p)
		if ValidateBlockPage(p) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if ValidateBlockPage(nil) == nil {
		t.Error("nil accepted")
	}
	// Characters, not bytes: 120 Persian letters are 240 bytes and fit.
	if err := ValidateBlockPage(&policyv1.BlockPage{ProfileId: make([]byte, 16), Title: strings.Repeat("س", 120), UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE}); err != nil {
		t.Errorf("120 characters: %v", err)
	}
}

func TestValidateProofObservation(t *testing.T) {
	const now = 1_800_000_000
	good := func() *hubv1.ProofObservation {
		return &hubv1.ProofObservation{Label: goodLabel, SourceIp: []byte{192, 0, 2, 1}, Protocol: commonv1.Protocol_PROTOCOL_UDP, ObservedAt: now - 5}
	}
	if err := ValidateProofObservation(good(), now); err != nil {
		t.Fatalf("a good observation: %v", err)
	}
	p := good()
	p.SourceIp = make([]byte, 16)
	if err := ValidateProofObservation(p, now); err != nil {
		t.Errorf("a 16-byte source: %v", err)
	}
	mut := map[string]func(*hubv1.ProofObservation){
		"upper case label": func(p *hubv1.ProofObservation) { p.Label = strings.ToUpper(goodLabel) },
		"25 characters":    func(p *hubv1.ProofObservation) { p.Label = goodLabel[:25] },
		"27 characters":    func(p *hubv1.ProofObservation) { p.Label = goodLabel + "a" },
		"digit 1":          func(p *hubv1.ProofObservation) { p.Label = "1" + goodLabel[1:] },
		"hyphen":           func(p *hubv1.ProofObservation) { p.Label = "a-" + goodLabel[2:] },
		"dot":              func(p *hubv1.ProofObservation) { p.Label = "a." + goodLabel[2:] },
		"empty label":      func(p *hubv1.ProofObservation) { p.Label = "" },
		"3 byte source":    func(p *hubv1.ProofObservation) { p.SourceIp = []byte{1, 2, 3} },
		"5 byte source":    func(p *hubv1.ProofObservation) { p.SourceIp = []byte{1, 2, 3, 4, 5} },
		"no source":        func(p *hubv1.ProofObservation) { p.SourceIp = nil },
		"no protocol":      func(p *hubv1.ProofObservation) { p.Protocol = 0 },
		"protocol 9":       func(p *hubv1.ProofObservation) { p.Protocol = 9 },
		"time zero":        func(p *hubv1.ProofObservation) { p.ObservedAt = 0 },
		"time negative":    func(p *hubv1.ProofObservation) { p.ObservedAt = -1 },
		"time too old":     func(p *hubv1.ProofObservation) { p.ObservedAt = now - MaxObservationAge - 1 },
		"time in future":   func(p *hubv1.ProofObservation) { p.ObservedAt = now + MaxObservationSkew + 1 },
	}
	for name, f := range mut {
		p := good()
		f(p)
		if ValidateProofObservation(p, now) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if ValidateProofObservation(nil, now) == nil {
		t.Error("nil accepted")
	}
}

// TestValidateProofObservationRidHash pins the SC 3.5 rule per protocol: an
// encrypted transport carries exactly the 16 bytes of identity.RIDHash, plain
// DNS carries none.
func TestValidateProofObservationRidHash(t *testing.T) {
	const now = 1_800_000_000
	// The bytes are arbitrary: wire checks the length, the hub compares the value.
	rid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	cases := []struct {
		name      string
		protocol  commonv1.Protocol
		encrypted bool
	}{
		{"udp", commonv1.Protocol_PROTOCOL_UDP, false},
		{"tcp", commonv1.Protocol_PROTOCOL_TCP, false},
		{"doh", commonv1.Protocol_PROTOCOL_DOH, true},
		{"doh3", commonv1.Protocol_PROTOCOL_DOH3, true},
		{"dot", commonv1.Protocol_PROTOCOL_DOT, true},
		{"doq", commonv1.Protocol_PROTOCOL_DOQ, true},
	}
	for _, c := range cases {
		mk := func(h []byte) *hubv1.ProofObservation {
			return &hubv1.ProofObservation{Label: goodLabel, SourceIp: []byte{192, 0, 2, 1}, Protocol: c.protocol, ObservedAt: now - 5, RidHash: h}
		}
		if c.encrypted {
			if err := ValidateProofObservation(mk(rid), now); err != nil {
				t.Errorf("%s with a 16-byte rid_hash: %v", c.name, err)
			}
			for _, bad := range [][]byte{nil, {}, rid[:15], append(append([]byte{}, rid...), 0), make([]byte, 32)} {
				if ValidateProofObservation(mk(bad), now) == nil {
					t.Errorf("%s with a %d-byte rid_hash was accepted", c.name, len(bad))
				}
			}
			continue
		}
		if err := ValidateProofObservation(mk(nil), now); err != nil {
			t.Errorf("%s with no rid_hash: %v", c.name, err)
		}
		if ValidateProofObservation(mk(rid), now) == nil {
			t.Errorf("%s with a rid_hash was accepted", c.name)
		}
		if ValidateProofObservation(mk([]byte{1}), now) == nil {
			t.Errorf("%s with a 1-byte rid_hash was accepted", c.name)
		}
	}
}

func TestValidateNodeReports(t *testing.T) {
	const now = 1_800_000_000
	ep := make([]byte, 16)
	bn := names.MustString("blocked.example")
	qn := bn.Wire()
	if err := ValidateLearnedIP(&hubv1.LearnedIP{EndpointId: ep, SourceIp: []byte{1, 2, 3, 4}, Protocol: commonv1.Protocol_PROTOCOL_DOH, ObservedAt: now}, now); err != nil {
		t.Errorf("learned ip: %v", err)
	}
	for name, l := range map[string]*hubv1.LearnedIP{
		"endpoint of 15 bytes": {EndpointId: ep[:15], SourceIp: []byte{1, 2, 3, 4}, Protocol: 2, ObservedAt: now},
		"source of 6 bytes":    {EndpointId: ep, SourceIp: make([]byte, 6), Protocol: 2, ObservedAt: now},
		"protocol 0":           {EndpointId: ep, SourceIp: []byte{1, 2, 3, 4}, ObservedAt: now},
		"time in the future":   {EndpointId: ep, SourceIp: []byte{1, 2, 3, 4}, Protocol: 2, ObservedAt: now + 1e6},
	} {
		if ValidateLearnedIP(l, now) == nil {
			t.Errorf("learned ip: %s accepted", name)
		}
	}

	if err := ValidateBlockUnblockRequest(&hubv1.BlockUnblockRequest{EndpointId: ep, ProfileId: make([]byte, 16), QnameWire: qn, Message: "please unblock", At: now}, now); err != nil {
		t.Errorf("unblock request: %v", err)
	}
	prof := make([]byte, 16)
	for name, r := range map[string]*hubv1.BlockUnblockRequest{
		"endpoint of 17 bytes": {EndpointId: make([]byte, 17), ProfileId: prof, QnameWire: qn, At: now},
		"truncated name":       {EndpointId: ep, ProfileId: prof, QnameWire: qn[:3], At: now},
		"root name":            {EndpointId: ep, ProfileId: prof, QnameWire: []byte{0}, At: now},
		"message of 501":       {EndpointId: ep, ProfileId: prof, QnameWire: qn, Message: strings.Repeat("a", 501), At: now},
		"escape in message":    {EndpointId: ep, ProfileId: prof, QnameWire: qn, Message: "x\x1b[31m", At: now},
		"time zero":            {EndpointId: ep, ProfileId: prof, QnameWire: qn},
		"no profile id":        {EndpointId: ep, QnameWire: qn, At: now},
		"profile id of 15":     {EndpointId: ep, ProfileId: make([]byte, 15), QnameWire: qn, At: now},
	} {
		if ValidateBlockUnblockRequest(r, now) == nil {
			t.Errorf("unblock request: %s accepted", name)
		}
	}

	hb := func() *hubv1.Heartbeat {
		return &hubv1.Heartbeat{NodeTime: now, NodeVersion: "1.2.3", BlobMajorMax: 1, Upstreams: []*hubv1.UpstreamHealth{{Id: ep}}, Locations: []*hubv1.LocationHealth{{Location: 3}, {Location: 4}}}
	}
	// The three fields of P4 are valid at their ends, and a P0 node sends none.
	full := hb()
	full.NodeConfigVersion, full.Qps, full.CacheHitPermille = 1<<63, MaxHeartbeatQPS, 1000
	if err := ValidateHeartbeat(full); err != nil {
		t.Errorf("heartbeat with the P4 fields: %v", err)
	}
	if err := ValidateHeartbeat(hb()); err != nil {
		t.Errorf("heartbeat: %v", err)
	}
	mut := map[string]func(*hubv1.Heartbeat){
		"negative node_time":    func(h *hubv1.Heartbeat) { h.NodeTime = -1 },
		"long version":          func(h *hubv1.Heartbeat) { h.NodeVersion = strings.Repeat("v", 65) },
		"control in version":    func(h *hubv1.Heartbeat) { h.XrayVersion = "1\n2" },
		"blob major 256":        func(h *hubv1.Heartbeat) { h.BlobMajorMax = 256 },
		"blob major 0":          func(h *hubv1.Heartbeat) { h.BlobMajorMax = 0 },
		"upstream id of 3":      func(h *hubv1.Heartbeat) { h.Upstreams = []*hubv1.UpstreamHealth{{Id: []byte{1, 2, 3}}} },
		"repeated location":     func(h *hubv1.Heartbeat) { h.Locations = []*hubv1.LocationHealth{{Location: 3}, {Location: 3}} },
		"location above 65535":  func(h *hubv1.Heartbeat) { h.Locations = []*hubv1.LocationHealth{{Location: 70000}} },
		"peer view of 64 KiB+1": func(h *hubv1.Heartbeat) { h.PeerView = make([]byte, MaxPeerView+1) },
		"qps above the bound":   func(h *hubv1.Heartbeat) { h.Qps = MaxHeartbeatQPS + 1 },
		"permille above 1000":   func(h *hubv1.Heartbeat) { h.CacheHitPermille = 1001 },
	}
	for name, f := range mut {
		h := hb()
		f(h)
		if ValidateHeartbeat(h) == nil {
			t.Errorf("heartbeat: %s accepted", name)
		}
	}
}

// L2-F19: every member of the NodeMessage oneof has a case in
// ValidateNodeMessage. The list comes from the generated descriptor, so a
// member added to the proto without a validator fails here.
func TestEveryNodeMessageMemberHasAValidator(t *testing.T) {
	desc := (&hubv1.NodeMessage{}).ProtoReflect().Descriptor()
	oneof := desc.Oneofs().ByName("body")
	if oneof == nil {
		t.Fatal("NodeMessage has no oneof named body")
	}
	fields := oneof.Fields()
	if fields.Len() < 8 {
		t.Fatalf("the oneof lists %d members; the descriptor walk is broken", fields.Len())
	}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		m := &hubv1.NodeMessage{}
		r := m.ProtoReflect()
		// An empty message of the member's type: invalid content, but present.
		r.Set(fd, r.NewField(fd))
		err := ValidateNodeMessage(m, 1_800_000_000)
		if errors.Is(err, errUnhandledBody) {
			t.Errorf("NodeMessage.%s has no validator in ValidateNodeMessage", fd.Name())
		}
		// An empty heartbeat is a legal heartbeat; every other empty member is not.
		if err == nil && fd.Name() != "heartbeat" {
			t.Errorf("an empty %s was accepted", fd.Name())
		}
	}
	if err := ValidateNodeMessage(&hubv1.NodeMessage{}, 1); err == nil {
		t.Error("a message with no body was accepted")
	}
	if err := ValidateNodeMessage(nil, 1); err == nil {
		t.Error("nil accepted")
	}
	// And the dispatch reaches the member validators.
	obs := &hubv1.NodeMessage{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{
		Label: "BAD", SourceIp: []byte{1, 2, 3, 4}, Protocol: 1, ObservedAt: 100}}}
	if ValidateNodeMessage(obs, 100) == nil {
		t.Error("a bad label passed through ValidateNodeMessage")
	}
}

// FuzzValidateNodeMessage: whatever bytes a node sends, decoding them and
// validating the result never panics, and a block page that validates has an
// https link or none.
func FuzzValidateNodeMessage(f *testing.F) {
	for _, m := range []*hubv1.NodeMessage{
		{Body: &hubv1.NodeMessage_ProofObservation{ProofObservation: &hubv1.ProofObservation{Label: goodLabel, SourceIp: []byte{1, 2, 3, 4}, Protocol: 1, ObservedAt: 100}}},
		{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{NodeTime: 5, NodeVersion: "1", BlobMajorMax: 1}}},
		{Body: &hubv1.NodeMessage_BlockUnblockRequest{BlockUnblockRequest: &hubv1.BlockUnblockRequest{EndpointId: make([]byte, 16), ProfileId: make([]byte, 16), QnameWire: []byte{1, 'a', 0}, At: 1}}},
		{Body: &hubv1.NodeMessage_BlockKeyRequest{BlockKeyRequest: &hubv1.BlockKeyRequest{EndpointId: make([]byte, 16)}}},
		{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{BlobMajorMax: 1,
			XrayConfigs: []*hubv1.XrayConfigState{{Id: make([]byte, 16), State: hubv1.XrayConfigStateKind_XRAY_CONFIG_STATE_KIND_APPLIED, Error: "e"}},
			Proxy:       &hubv1.ProxyState{Listening: true}, Faults: []hubv1.NodeFault{hubv1.NodeFault_NODE_FAULT_XRAY_DOWN},
			XrayUpgrade: &hubv1.XrayUpgradeState{Version: "v26.11.9", FailedIds: [][]byte{make([]byte, 16)}}, BindError: hubv1.BindError_BIND_ERROR_DNS_FAILED}}},
	} {
		b, err := proto.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var m hubv1.NodeMessage
		if proto.Unmarshal(b, &m) != nil {
			return
		}
		_ = ValidateNodeMessage(&m, 100)
	})
}

func FuzzValidateBlockPage(f *testing.F) {
	f.Add("Blocked", "msg", "https://example.com/x", int32(3))
	f.Add("", "", "javascript:alert(1)", int32(3))
	f.Fuzz(func(t *testing.T, title, msg, link string, mode int32) {
		p := &policyv1.BlockPage{ProfileId: make([]byte, 16), Title: title, Message: msg, UnblockUrl: link, UnblockMode: policyv1.UnblockMode(mode)}
		if ValidateBlockPage(p) != nil || link == "" {
			return
		}
		if !strings.HasPrefix(link, "https://") {
			t.Fatalf("accepted the link %q", link)
		}
	})
}
