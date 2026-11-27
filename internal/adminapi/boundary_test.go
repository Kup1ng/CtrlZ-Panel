package adminapi

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
)

// TestBoundaryFuzz is the admin half of rule boundary-input (P1 auth review round 5,
// spec 15.2, 18.5; the tenant half, with the full description, is internal/api
// boundary_test.go). The admin API takes free text an operator types (usernames, SMS
// template bodies and parameter names, gateway credentials, phone numbers), so every
// one of those must be refused at the pipeline when it carries a NUL, a bidi override
// or a padded name, with no WARN line.
func TestBoundaryFuzz(t *testing.T) {
	r := newRig(t)
	cases, err := boundary.Cases(api.Admin())
	if err != nil {
		t.Fatal(err)
	}
	baselines, refused := 0, 0
	for i, c := range cases {
		res := boundary.DoAs(context.Background(), r.h, adminHost, boundary.IP(i), c, boundary.AdminCookie(r.keys, r.ck.now().Add(time.Hour)))
		if v := boundary.Verdict(c, res); v != "" {
			t.Errorf("%s: %s", c.Name, v)
			continue
		}
		if c.Baseline {
			baselines++
		} else {
			refused++
		}
	}
	if baselines < 30 || refused < 1000 {
		t.Errorf("only %d baselines and %d refusals fired: the generator has stopped covering the document", baselines, refused)
	}

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for i, c := range cases {
		if !c.Baseline {
			continue
		}
		if v := boundary.AbortVerdict(boundary.DoAs(gone, r.h, adminHost, boundary.IP(len(cases)+i), c, boundary.AdminCookie(r.keys, r.ck.now().Add(time.Hour)))); v != "" {
			t.Errorf("%s: %s", c.Name, v)
		}
	}

	if lines := boundary.WarnLines(r.logs.String()); len(lines) > 0 {
		t.Errorf("%d WARN or ERROR lines from client input, first: %s", len(lines), lines[0])
	}
}
