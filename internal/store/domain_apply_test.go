package store_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// VL-r1-2: DomainApplyLoad runs as ctrlz_domain_apply against the migrated schema, because the filter that decides which wildcard
// rows the apply step sees, and whether a key leaves the database with them, lives in the statement and not in the grants.
// The fake source of the domainapply tests bypasses it, so dropping `state = 'active'`, `source = 'uploaded'` or the sealed-key
// test from qDomainApplyCerts would leave a retired wildcard's zone in CTRLZ_VERIFY_ORIGIN and fail nothing there.
func TestDomainApplyLoadReadsOnlyTheActiveUploadedWildcardsAndNeverTheirKey(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	apply := db.Store(ctx, t, store.RoleDomainApply)

	// The chain text names the row, so the answer says which rows came back.
	for _, r := range []struct {
		pem, kind, state, source string
		key                      []byte
	}{
		{"wildcard-active", "wildcard", "active", "uploaded", []byte{1}},
		{"wildcard-retired", "wildcard", "retired", "uploaded", []byte{1}},
		{"wildcard-issued", "wildcard", "active", "issued", []byte{1}},
		{"wildcard-keyless", "wildcard", "active", "uploaded", nil},
		{"panel-active", "panel", "active", "uploaded", []byte{2}},
		{"panel-retired", "panel", "retired", "uploaded", []byte{2}},
	} {
		if err := db.Exec(ctx, `INSERT INTO ctrlz.certificates (kind, chain_pem, wrapped_key_ct, not_before, not_after, state, source, names)
			VALUES ($1, $2, $3, now() - interval '1 day', now() + interval '60 days', $4, $5, '{}')`, r.kind, r.pem, r.key, r.state, r.source); err != nil {
			t.Fatal(err)
		}
	}
	_, certs, err := apply.DomainApplyLoad(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range certs {
		got = append(got, c.ChainPEM)
		switch c.Kind {
		case "wildcard":
			if c.SealedKey != nil {
				t.Errorf("%s: the sealed key of a wildcard reached the apply step", c.ChainPEM)
			}
		case "panel":
			if len(c.SealedKey) == 0 {
				t.Errorf("%s: the panel certificate must come with its key, the apply step writes it to a file", c.ChainPEM)
			}
		}
	}
	sort.Strings(got)
	if want := []string{"panel-active", "wildcard-active"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("the apply step read %v, want %v", got, want)
	}
}
