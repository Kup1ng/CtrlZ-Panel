package hubctl

import (
	"testing"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
)

// H-r1-3: the canary's "resolve path healthy" reads the upstreams only. A healthy proxy location is not a resolve path.
func TestResolveHealthyReadsUpstreamsOnly(t *testing.T) {
	up := func(ok bool) *hubv1.UpstreamHealth { return &hubv1.UpstreamHealth{Id: []byte{1}, Healthy: ok} }
	loc := func(ok bool) *hubv1.LocationHealth { return &hubv1.LocationHealth{Location: 1, Healthy: ok} }
	for _, c := range []struct {
		name string
		h    *hubv1.Heartbeat
		want bool
	}{
		{"no path listed (recursive mode)", &hubv1.Heartbeat{}, true},
		{"only locations listed, all up", &hubv1.Heartbeat{Locations: []*hubv1.LocationHealth{loc(true)}}, true},
		{"one upstream up", &hubv1.Heartbeat{Upstreams: []*hubv1.UpstreamHealth{up(false), up(true)}}, true},
		{"every upstream down, one location up", &hubv1.Heartbeat{Upstreams: []*hubv1.UpstreamHealth{up(false), up(false)}, Locations: []*hubv1.LocationHealth{loc(true)}}, false},
	} {
		if got := resolveHealthy(c.h); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
