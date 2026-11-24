package adminapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWebauthnSwitchIsInTheAuditRow is admin-r12-3. Turning passkeys off while keeping the RP ID
// drops every user with enforce_passkey to a password or an SMS code at once, and the row used to
// hold the RP ID and the impact counts only, so it was the row of a harmless re-save. The row now
// names the switch before and after, and a save that changes nothing says so.
func TestWebauthnSwitchIsInTheAuditRow(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `DELETE FROM ctrlz.audit_log WHERE action = 'webauthn.config_change'`)

	put := func(enabled bool) {
		t.Helper()
		b.put("/settings/webauthn", map[string]any{"rp_id": "panel.example.test", "enabled": enabled}).want(200, "")
	}
	last := func() (from, to bool) {
		t.Helper()
		r.env.Scan(t, `SELECT (params->>'from_enabled')::boolean, (params->>'to_enabled')::boolean
			FROM ctrlz.audit_log WHERE action = 'webauthn.config_change' ORDER BY id DESC LIMIT 1`, nil, &from, &to)
		return from, to
	}
	put(false) // a known start, whatever the seed holds
	put(true)
	if from, to := last(); from || !to {
		t.Fatalf("switched on: from_enabled=%v to_enabled=%v", from, to)
	}
	put(false)
	if from, to := last(); !from || to {
		t.Fatalf("switched off with the RP ID kept: from_enabled=%v to_enabled=%v", from, to)
	}
	put(false)
	if from, to := last(); from || to {
		t.Fatalf("a save that changes nothing: from_enabled=%v to_enabled=%v", from, to)
	}
	// Every row carries both keys, so a row of the old shape cannot pass for a switch that stayed.
	if n := r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = 'webauthn.config_change' AND NOT (params ? 'from_enabled' AND params ? 'to_enabled')`); n != 0 {
		t.Fatalf("%d rows without the switch", n)
	}
}

// TestTheAdminRouterAnswersTheHealthMuxToLoopbackPeersOnly is the host-independent half of rule 28
// (admin-r12-2). The runtime test of internal/app needs a second address of the host and skips
// without one; this one sets the peer on the request, so it runs on every machine and fails when the
// router mounts the mux with no gate.
func TestTheAdminRouterAnswersTheHealthMuxToLoopbackPeersOnly(t *testing.T) {
	r := newRig(t)
	h := r.handler(t, func(*Deps) {})
	for peer, want := range map[string]int{
		"127.0.0.1:4000": 200, "[::1]:4000": 200,
		"10.20.30.40:4000": 404, "[fd00::5]:4000": 404, "172.18.0.9:1": 404,
	} {
		for _, path := range []string{"/healthz", "/readyz", "/anything"} {
			req := httptest.NewRequest("GET", path, nil)
			req.Host = adminHost
			req.RemoteAddr = peer
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != want || (want == 404 && strings.Contains(w.Body.String(), "ok")) {
				t.Errorf("%s from %s = %d %q, want %d", path, peer, w.Code, w.Body.String(), want)
			}
		}
	}
}
