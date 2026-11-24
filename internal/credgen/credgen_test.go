package credgen_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/credgen"
)

func TestHolds(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	now := credgen.Stamp{Tenant: tenant, Subject: user, Gen: 4}
	for _, c := range []struct {
		name   string
		issued credgen.Stamp
		want   bool
	}{
		{"the same", now, true},
		{"an older generation", credgen.Stamp{Tenant: tenant, Subject: user, Gen: 3}, false},
		{"a newer generation", credgen.Stamp{Tenant: tenant, Subject: user, Gen: 5}, false},
		{"another subject", credgen.Stamp{Tenant: tenant, Subject: uuid.New(), Gen: 4}, false},
		{"another tenant", credgen.Stamp{Tenant: uuid.New(), Subject: user, Gen: 4}, false},
		{"a zero stamp", credgen.Stamp{}, false},
		{"generation zero is not one", credgen.Stamp{Tenant: tenant, Subject: user}, false},
	} {
		if got := c.issued.Holds(now); got != c.want {
			t.Errorf("%s: Holds = %v, want %v", c.name, got, c.want)
		}
		if err := c.issued.Check(now); (err == nil) != c.want || (err != nil && !errors.Is(err, credgen.ErrStale)) {
			t.Errorf("%s: Check = %v", c.name, err)
		}
	}
	// Two zero stamps do not hold for each other: nothing was derived.
	if (credgen.Stamp{}).Holds(credgen.Stamp{}) {
		t.Error("a zero stamp held for a zero stamp")
	}
}
