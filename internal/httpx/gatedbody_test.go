package httpx

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/bulkgate"
)

// A body that trickles holds what it has sent and no more, and a read the gate has no room for ends with errBusy and
// marks the body busy (spec 6.2, finding p2-B3-r2-7).
func TestAGatedBodyHoldsOnlyTheBytesItRead(t *testing.T) {
	g := bulkgate.New(1<<10, 1<<10)
	rsv := g.Reserve("t")
	defer rsv.Release()
	// A sender that declared a large body and sent 10 bytes holds 10 times the read weight.
	gb := &gatedBody{rc: io.NopCloser(strings.NewReader(strings.Repeat("x", 10))), rsv: rsv}
	buf := make([]byte, 64)
	if n, err := gb.Read(buf); err != nil || n != 10 {
		t.Fatalf("read %d, %v", n, err)
	}
	if all, _ := g.Held("t"); all != 10*bulkgate.ReadWeight {
		t.Fatalf("a body that sent 10 bytes holds %d", all)
	}
	// Another body that is bigger than what is left is refused at the read that does not fit.
	rsv2 := g.Reserve("u")
	defer rsv2.Release()
	big := &gatedBody{rc: io.NopCloser(strings.NewReader(strings.Repeat("x", 2<<10))), rsv: rsv2}
	_, err := io.ReadAll(big)
	if !errors.Is(err, errBusy) || !big.busy {
		t.Fatalf("a body above the gate read as %v, busy %v", err, big.busy)
	}
}
