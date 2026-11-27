package wire

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const telNow = 1_800_000_000 // a multiple of 300

func activity(mut func(*telemetryv1.ActivityEntry)) *telemetryv1.ActivityBatch {
	e := &telemetryv1.ActivityEntry{
		EndpointId: make([]byte, 16), SourceIpHash: make([]byte, 16), ClientLabel: "default",
		Protocol: commonv1.Protocol_PROTOCOL_UDP, FirstSeenBucket: telNow - 600, LastSeenBucket: telNow - 300,
	}
	if mut != nil {
		mut(e)
	}
	return &telemetryv1.ActivityBatch{Entries: []*telemetryv1.ActivityEntry{e}}
}

// L2-F16: the one free-text field of an activity batch is a client label.
func TestActivityBatchClientLabel(t *testing.T) {
	for _, good := range []string{"default", "kid", "a", "tv-1", strings.Repeat("a", 36)} {
		if err := ValidateActivityBatch(activity(func(e *telemetryv1.ActivityEntry) { e.ClientLabel = good }), telNow); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"", "x' OR 1=1 --\n<script>", "Kid", "-a", "a-", "a b", "a.b", "é", strings.Repeat("a", 37)} {
		if ValidateActivityBatch(activity(func(e *telemetryv1.ActivityEntry) { e.ClientLabel = bad }), telNow) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The plan's heartbeat names the source by a claim id or a source IP hash, or by neither. A
// Plain DNS query from a claimed address has a claim and no hash, and a query
// that names no client sends the label "default"; neither may fail the batch.
func TestActivityEntryHasAtMostOneSource(t *testing.T) {
	claim := make([]byte, 16)
	cases := []struct {
		name string
		mut  func(*telemetryv1.ActivityEntry)
		ok   bool
	}{
		{"hash only", nil, true},
		{"claim only", func(e *telemetryv1.ActivityEntry) { e.ClaimId, e.SourceIpHash = claim, nil }, true},
		{"claim only, no client", func(e *telemetryv1.ActivityEntry) { e.ClaimId, e.SourceIpHash, e.ClientLabel = claim, nil, "default" }, true},
		{"both", func(e *telemetryv1.ActivityEntry) { e.ClaimId = claim }, false},
		{"neither (p4-nodes 7.6: the source is in no claim and no authorized prefix)", func(e *telemetryv1.ActivityEntry) { e.SourceIpHash = nil }, true},
		{"neither, empty label", func(e *telemetryv1.ActivityEntry) { e.SourceIpHash, e.ClientLabel = nil, "" }, false},
		{"neither, empty hash and claim slices", func(e *telemetryv1.ActivityEntry) { e.SourceIpHash, e.ClaimId = []byte{}, []byte{} }, true},
		{"claim of 15 bytes", func(e *telemetryv1.ActivityEntry) { e.ClaimId, e.SourceIpHash = claim[:15], nil }, false},
		{"hash of 15 bytes", func(e *telemetryv1.ActivityEntry) { e.SourceIpHash = e.SourceIpHash[:15] }, false},
		{"claim and no label", func(e *telemetryv1.ActivityEntry) { e.ClaimId, e.SourceIpHash, e.ClientLabel = claim, nil, "" }, false},
	}
	for _, c := range cases {
		err := ValidateActivityBatch(activity(c.mut), telNow)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// Activity buckets are held to the receiver's clock: the hub keeps the maximum
// last_seen over nodes, so a bucket far ahead would keep a claim "seen" forever.
func TestActivityBucketsAreBoundedByTheClock(t *testing.T) {
	set := func(first, last int64) func(*telemetryv1.ActivityEntry) {
		return func(e *telemetryv1.ActivityEntry) { e.FirstSeenBucket, e.LastSeenBucket = first, last }
	}
	cases := []struct {
		name string
		mut  func(*telemetryv1.ActivityEntry)
		ok   bool
	}{
		{"the current bucket", set(telNow, telNow), true},
		{"oldest allowed", set(telNow-MaxSpoolAge, telNow-MaxSpoolAge), true},
		{"a spool flushed after 29 days", set(telNow-29*86400, telNow-29*86400+3000), true},
		{"older than the spool lifetime", set(telNow-MaxSpoolAge-300, telNow-MaxSpoolAge-300), false},
		{"one bucket ahead", set(telNow, telNow+300), true},
		{"far in the future", set(telNow, 4_611_686_018_427_387_900/300*300), false},
		{"year 2100", set(4_102_444_800/300*300, 4_102_444_800/300*300), false},
		{"negative", set(-600, -300), false},
		{"first bucket ancient, last current", set(0, telNow), false},
	}
	for _, c := range cases {
		err := ValidateActivityBatch(activity(c.mut), telNow)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func wireOf(s string) []byte {
	n := names.MustString(s)
	return n.Wire()
}

func goodLogRow() *telemetryv1.LogRow {
	return &telemetryv1.LogRow{
		Ts: telNow, EndpointId: make([]byte, 16), ClientId: make([]byte, 16),
		ProfileId: make([]byte, 16), Profile2Id: make([]byte, 16), ScheduleWindowId: make([]byte, 16),
		QnameWire: wireOf("a.example"), Qtype: 1, Rcode: 0,
		Protocol: commonv1.Protocol_PROTOCOL_DOH, Action: commonv1.Action_ACTION_BLOCK, DecisionStage: commonv1.Stage_STAGE_FILTER,
		DecisionRef: []byte("filter:4294967295"), Location: 0xFFFF, SourceIp: []byte{5, 160, 0, 1},
		SourceCountry: "IR", AnswerCountry: "us",
		CnameChain: [][]byte{wireOf("b.example")},
	}
}

// Every id of a row has one width, decision_ref is bounded by its text form,
// and the small fields have the shapes their columns can hold.
func TestValidateLogRow(t *testing.T) {
	if err := ValidateLogRow(goodLogRow(), telNow); err != nil {
		t.Fatalf("the control row: %v", err)
	}
	empty := goodLogRow()
	empty.ClientId, empty.ProfileId, empty.Profile2Id, empty.ScheduleWindowId = nil, nil, nil, nil
	empty.DecisionRef, empty.SourceCountry, empty.AnswerCountry, empty.CnameChain, empty.Location = nil, "", "", nil, 0
	if err := ValidateLogRow(empty, telNow); err != nil {
		t.Errorf("a row with every optional field absent: %v", err)
	}
	chain := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = wireOf("b.example")
		}
		return out
	}
	cases := []struct {
		name string
		mut  func(*telemetryv1.LogRow)
		ok   bool
	}{
		{"profile_id of 3 bytes", func(r *telemetryv1.LogRow) { r.ProfileId = make([]byte, 3) }, false},
		{"profile_id of 17 bytes", func(r *telemetryv1.LogRow) { r.ProfileId = make([]byte, 17) }, false},
		{"profile2_id of 200 bytes", func(r *telemetryv1.LogRow) { r.Profile2Id = make([]byte, 200) }, false},
		{"schedule_window_id of 1 byte", func(r *telemetryv1.LogRow) { r.ScheduleWindowId = make([]byte, 1) }, false},
		{"client_id of 15 bytes", func(r *telemetryv1.LogRow) { r.ClientId = make([]byte, 15) }, false},
		{"decision_ref of exactly the bound", func(r *telemetryv1.LogRow) { r.DecisionRef = make([]byte, MaxDecisionRefBytes) }, true},
		{"decision_ref one byte over the bound", func(r *telemetryv1.LogRow) { r.DecisionRef = make([]byte, MaxDecisionRefBytes+1) }, false},
		{"decision_ref of 1 MiB", func(r *telemetryv1.LogRow) { r.DecisionRef = make([]byte, 1<<20) }, false},
		{"decision_ref of a rule id", func(r *telemetryv1.LogRow) { r.DecisionRef = []byte("rule:" + strings.Repeat("ab", 16)) }, true},
		{"location 65535", func(r *telemetryv1.LogRow) { r.Location = 0xFFFF }, true},
		{"location 65536", func(r *telemetryv1.LogRow) { r.Location = 0x10000 }, false},
		{"location 2^31", func(r *telemetryv1.LogRow) { r.Location = 1 << 31 }, false},
		{"source_country of one letter", func(r *telemetryv1.LogRow) { r.SourceCountry = "I" }, false},
		{"source_country NUL and <", func(r *telemetryv1.LogRow) { r.SourceCountry = "\x00<" }, false},
		{"source_country digits", func(r *telemetryv1.LogRow) { r.SourceCountry = "I1" }, false},
		{"source_country of three letters", func(r *telemetryv1.LogRow) { r.SourceCountry = "IRN" }, false},
		{"answer_country invalid UTF-8", func(r *telemetryv1.LogRow) { r.AnswerCountry = "\xff\xff" }, false},
		{"answer_country just outside the letters", func(r *telemetryv1.LogRow) { r.AnswerCountry = "[a" }, false},
		{"answer_country lower case", func(r *telemetryv1.LogRow) { r.AnswerCountry = "zz" }, true},
		{"cname_chain at the walk limit", func(r *telemetryv1.LogRow) { r.CnameChain = chain(MaxCNAMEChain) }, true},
		{"cname_chain one hop over", func(r *telemetryv1.LogRow) { r.CnameChain = chain(MaxCNAMEChain + 1) }, false},
		{"cname_chain of 5000 hops", func(r *telemetryv1.LogRow) { r.CnameChain = chain(5000) }, false},
	}
	for _, c := range cases {
		r := goodLogRow()
		c.mut(r)
		if err := ValidateLogRow(r, telNow); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestValidateLogRowTime(t *testing.T) {
	qn := names.MustString("a.example")
	row := func(ts int64) *telemetryv1.LogRow {
		return &telemetryv1.LogRow{
			Ts: ts, EndpointId: make([]byte, 16), QnameWire: qn.Wire(),
			Protocol: commonv1.Protocol_PROTOCOL_UDP, Action: commonv1.Action_ACTION_BLOCK, DecisionStage: commonv1.Stage_STAGE_RULE,
		}
	}
	for ts, ok := range map[int64]bool{
		telNow: true, telNow - 60: true, telNow + MaxObservationSkew: true, telNow - MaxSpoolAge: true,
		telNow - MaxSpoolAge - 1: false, telNow + MaxObservationSkew + 1: false, -1: false, 0: false, 1 << 62: false,
	} {
		if err := ValidateLogRow(row(ts), telNow); (err == nil) != ok {
			t.Errorf("ts %d: err = %v, want ok=%v", ts, err, ok)
		}
	}
	if ValidateLogRow(nil, telNow) == nil {
		t.Error("nil accepted")
	}
}

func TestValidateLogBatch(t *testing.T) {
	good := func() *telemetryv1.LogBatch {
		return &telemetryv1.LogBatch{BatchId: 1, Count: 10, EphemeralPub: make([]byte, 32), Nonce: make([]byte, 24), Sealed: []byte{1, 2, 3}}
	}
	if err := ValidateLogBatch(good()); err != nil {
		t.Fatalf("a good batch: %v", err)
	}
	b := good()
	b.Nonce = make([]byte, 12)
	if err := ValidateLogBatch(b); err != nil {
		t.Errorf("a 12-byte nonce: %v", err)
	}
	for name, mut := range map[string]func(*telemetryv1.LogBatch){
		"count 0":            func(b *telemetryv1.LogBatch) { b.Count = 0 },
		"count over the cap": func(b *telemetryv1.LogBatch) { b.Count = MaxLogRowsPerBatch + 1 },
		"31-byte key":        func(b *telemetryv1.LogBatch) { b.EphemeralPub = make([]byte, 31) },
		"no key":             func(b *telemetryv1.LogBatch) { b.EphemeralPub = nil },
		"nonce of 8":         func(b *telemetryv1.LogBatch) { b.Nonce = make([]byte, 8) },
		"no nonce":           func(b *telemetryv1.LogBatch) { b.Nonce = nil },
		"empty sealed":       func(b *telemetryv1.LogBatch) { b.Sealed = nil },
		"sealed over the cap": func(b *telemetryv1.LogBatch) {
			b.Sealed = make([]byte, MaxSealedLogBatch+1)
		},
	} {
		b := good()
		mut(b)
		if ValidateLogBatch(b) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if ValidateLogBatch(nil) == nil {
		t.Error("nil accepted")
	}
}

func TestValidateCountersBatch(t *testing.T) {
	good := func() *telemetryv1.CountersBatch {
		return &telemetryv1.CountersBatch{BatchId: 1, BucketStart: telNow - 300, Counters: []*telemetryv1.Counter{
			{EndpointId: make([]byte, 16), Protocol: commonv1.Protocol_PROTOCOL_DOH, Action: commonv1.Action_ACTION_BYPASS, Count: 12},
		}}
	}
	if err := ValidateCountersBatch(good(), telNow); err != nil {
		t.Fatalf("a good batch: %v", err)
	}
	for name, mut := range map[string]func(*telemetryv1.CountersBatch){
		"bucket in the future":   func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow + 3600 },
		"bucket too old":         func(b *telemetryv1.CountersBatch) { b.BucketStart = telNow - MaxSpoolAge - 1 },
		"negative bucket":        func(b *telemetryv1.CountersBatch) { b.BucketStart = -5 },
		"no counters":            func(b *telemetryv1.CountersBatch) { b.Counters = nil },
		"endpoint of 15 bytes":   func(b *telemetryv1.CountersBatch) { b.Counters[0].EndpointId = make([]byte, 15) },
		"protocol 0":             func(b *telemetryv1.CountersBatch) { b.Counters[0].Protocol = 0 },
		"protocol 9":             func(b *telemetryv1.CountersBatch) { b.Counters[0].Protocol = 9 },
		"action 0":               func(b *telemetryv1.CountersBatch) { b.Counters[0].Action = 0 },
		"action 7":               func(b *telemetryv1.CountersBatch) { b.Counters[0].Action = 7 },
		"count 0":                func(b *telemetryv1.CountersBatch) { b.Counters[0].Count = 0 },
		"count over the bound":   func(b *telemetryv1.CountersBatch) { b.Counters[0].Count = MaxCounterValue + 1 },
		"count that would wrap":  func(b *telemetryv1.CountersBatch) { b.Counters[0].Count = 1<<64 - 1 },
		"a second bad counter":   func(b *telemetryv1.CountersBatch) { b.Counters = append(b.Counters, &telemetryv1.Counter{}) },
		"nil counter in a batch": func(b *telemetryv1.CountersBatch) { b.Counters = append(b.Counters, nil) },
	} {
		b := good()
		mut(b)
		if ValidateCountersBatch(b, telNow) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if ValidateCountersBatch(nil, telNow) == nil {
		t.Error("nil accepted")
	}
}

// An IPv4-mapped source is a second spelling of an IPv4 source: it is refused
// where the hub derives the proof code from it and where it learns an address.
func TestSourceAddressIsNotIPv4Mapped(t *testing.T) {
	mapped := append(append(make([]byte, 10), 0xff, 0xff), 5, 160, 0, 1)
	plain4 := []byte{5, 160, 0, 1}
	v6 := make([]byte, 16)
	v6[0], v6[1], v6[15] = 0x20, 0x01, 1
	for name, c := range map[string]struct {
		ip []byte
		ok bool
	}{"4 bytes": {plain4, true}, "plain IPv6": {v6, true}, "mapped": {mapped, false}, "5 bytes": {append(plain4, 1), false}} {
		p := &hubv1.ProofObservation{Label: goodLabel, SourceIp: c.ip, Protocol: commonv1.Protocol_PROTOCOL_UDP, ObservedAt: telNow}
		if err := ValidateProofObservation(p, telNow); (err == nil) != c.ok {
			t.Errorf("proof observation, %s: %v", name, err)
		}
		l := &hubv1.LearnedIP{EndpointId: make([]byte, 16), SourceIp: c.ip, Protocol: commonv1.Protocol_PROTOCOL_DOH, ObservedAt: telNow}
		if err := ValidateLearnedIP(l, telNow); (err == nil) != c.ok {
			t.Errorf("learned ip, %s: %v", name, err)
		}
	}
}

// Every client-streaming method of NodeHub except Control (whose messages go
// through ValidateNodeMessage) has a case in ValidateTelemetryMessage. The
// list comes from the generated descriptor, so a stream added to the proto
// without a validator fails here.
func TestEveryUploadStreamHasAValidator(t *testing.T) {
	svc := hubv1.File_ctrlz_hub_v1_hub_proto.Services().ByName("NodeHub")
	if svc == nil {
		t.Fatal("no NodeHub service in the descriptor")
	}
	var checked []string
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		if !m.IsStreamingClient() || m.Input().FullName() == (&hubv1.NodeMessage{}).ProtoReflect().Descriptor().FullName() {
			continue
		}
		mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(m.Input().FullName()))
		if err != nil {
			t.Fatalf("%s: %v", m.Name(), err)
		}
		// An empty message: invalid content, but of the right type.
		err = ValidateTelemetryMessage(mt.New().Interface(), telNow)
		if errors.Is(err, errUnhandledBody) {
			t.Errorf("NodeHub.%s carries %s, which has no validator in ValidateTelemetryMessage", m.Name(), m.Input().FullName())
		}
		checked = append(checked, string(m.Name()))
	}
	if len(checked) < 3 {
		t.Fatalf("the walk found only %v; UploadLogs, UploadCounters and ReportActivity are expected", checked)
	}
	// And the dispatch reaches the validators.
	if ValidateTelemetryMessage(&telemetryv1.CountersBatch{BucketStart: -1}, telNow) == nil {
		t.Error("a bad counters batch passed through ValidateTelemetryMessage")
	}
	if ValidateTelemetryMessage(&telemetryv1.Ack{}, telNow) == nil {
		t.Error("an Ack is not an upload message")
	}
}

// The activity batch is bounded in entries, and a bucket pair that runs
// backwards is refused. Entries here are valid, so only the bound can refuse
// the batch: a nil entry would fail on its own fields and hide a loosened
// limit.
func TestActivityBatchBounds(t *testing.T) {
	if err := ValidateActivityBatch(activity(func(e *telemetryv1.ActivityEntry) {
		e.FirstSeenBucket, e.LastSeenBucket = telNow-300, telNow-600
	}), telNow); err == nil {
		t.Error("last_seen_bucket before first_seen_bucket was accepted")
	}
	many := func(n int) *telemetryv1.ActivityBatch {
		one := activity(nil).Entries[0]
		b := &telemetryv1.ActivityBatch{Entries: make([]*telemetryv1.ActivityEntry, n)}
		for i := range b.Entries {
			b.Entries[i] = one
		}
		return b
	}
	if err := ValidateActivityBatch(many(MaxActivityPerBatch), telNow); err != nil {
		t.Errorf("a batch of exactly MaxActivityPerBatch entries: %v", err)
	}
	if ValidateActivityBatch(many(MaxActivityPerBatch+1), telNow) == nil {
		t.Error("a batch of MaxActivityPerBatch+1 entries was accepted")
	}
}
