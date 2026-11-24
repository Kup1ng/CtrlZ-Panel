package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTheTenantRouterAnswersTheHealthMuxToLoopbackPeersOnly is the host-independent half of rule 28
// (admin-r12-2): the peer is set on the request, so the check runs on a host with no second address
// too, and fails when the router mounts the health mux with no gate.
func TestTheTenantRouterAnswersTheHealthMuxToLoopbackPeersOnly(t *testing.T) {
	f := newFrig(t, frigOpts{})
	for peer, want := range map[string]int{
		"127.0.0.1:4000": 200, "[::1]:4000": 200,
		"10.20.30.40:4000": 404, "[fd00::5]:4000": 404, "172.18.0.9:1": 404,
	} {
		for _, path := range []string{"/healthz", "/readyz"} {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = peer
			w := httptest.NewRecorder()
			f.h.ServeHTTP(w, req)
			if w.Code != want || (want == 404 && strings.Contains(w.Body.String(), "status")) {
				t.Errorf("%s from %s = %d %q, want %d", path, peer, w.Code, w.Body.String(), want)
			}
		}
	}
}
