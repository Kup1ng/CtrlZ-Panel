package adminapi

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
)

// TestEveryAdminOperationRefusesABearer is the admin half of rule E1 of docs/specs/p3-endpoints.md 11.2 (review round 1 of D5,
// p3-D5-r1-2): the admin document has no API token, so a bearer, a well-formed one or junk, is 403 token_not_allowed on every one
// of its operations, before any lookup, and with a session cookie too. Walking the document, not a list, means an operation added
// tomorrow is covered, and a refactor of how the pipeline knows it has no token reader cannot silently open one.
func TestEveryAdminOperationRefusesABearer(t *testing.T) {
	r := newRig(t)
	cases, err := boundary.Cases(api.Admin())
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for i, c := range cases {
		if !c.Baseline || c.Edge || !strings.HasSuffix(c.Name, "/baseline") {
			continue
		}
		for j, value := range []string{"ctz_" + strings.Repeat("A", 64), "junk"} {
			withBearer := c
			withBearer.Header = map[string]string{}
			for k, v := range c.Header {
				withBearer.Header[k] = v
			}
			withBearer.Header["Authorization"] = "Bearer " + value
			for k, cookie := range []bool{false, true} {
				ck := boundary.AdminCookie(r.keys, r.ck.now().Add(time.Hour))
				if !cookie {
					ck = nil
				}
				res := boundary.DoAs(context.Background(), r.h, adminHost, boundary.IP(i*8+j*2+k), withBearer, ck)
				if res.Status != 403 || !bytes.Contains(res.Body, []byte("token_not_allowed")) {
					t.Errorf("%s with %q (cookie %v): %d %s", c.Name, value[:4], cookie, res.Status, res.Body)
				}
			}
		}
		seen++
	}
	if seen < 30 {
		t.Errorf("only %d operations walked: the generator has stopped covering the admin document", seen)
	}
}
