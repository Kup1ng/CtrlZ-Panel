package profiles_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/vectors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

type tokenError struct {
	input string
	err   error
}

type tokenValid struct {
	input, key, kind string
	negated          bool
}

func tokenCases(t *testing.T) []vectors.TextCase {
	t.Helper()
	g, err := vectors.ReadGroup("tokens")
	if err != nil {
		t.Fatal(err)
	}
	var cases []vectors.TextCase
	if err := json.Unmarshal(g.Cases, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// tokenErrorCases are the cases of the tokens group that the parser refuses.
func tokenErrorCases(t *testing.T) []tokenError {
	var out []tokenError
	for _, c := range tokenCases(t) {
		if c.Op != "rules_parse" || !c.Error {
			continue
		}
		input := c.Input
		if c.Repeat > 1 {
			input = strings.Repeat(input, c.Repeat)
		}
		_, err := rules.Parse(input)
		if err == nil {
			t.Fatalf("%s: the parser accepted a case the vectors refuse", c.ID)
		}
		out = append(out, tokenError{input: c.ID, err: err})
	}
	if len(out) < 20 {
		t.Fatalf("only %d error cases", len(out))
	}
	return out
}

// tokenValidCases are the cases the parser accepts, with the key, kind and sign their expectation names. A case that
// no profile may hold (a Redirect-only or Iranian pattern) is not in the group; the route creates them with Block.
func tokenValidCases(t *testing.T) []tokenValid {
	var out []tokenValid
	for _, c := range tokenCases(t) {
		if c.Op != "rules_parse" || c.Error || c.Repeat > 1 || strings.TrimSpace(c.Input) == "" {
			continue
		}
		v := tokenValid{input: c.Input}
		for _, part := range strings.Fields(c.Expect) {
			k, val, _ := strings.Cut(part, "=")
			switch k {
			case "key":
				v.key = val
			case "kind":
				v.kind = val
			case "negated":
				v.negated = val == "true"
			}
		}
		out = append(out, v)
	}
	if len(out) < 10 {
		t.Fatalf("only %d valid cases", len(out))
	}
	return out
}

// TestDevLocationsFixture applies the development fixture to an empty database, as the e2e seed does, and reads it
// back through the production catalog: two nodes in the global pair, a country with and without a city, a
// label-only location, and one location only one node has.
func TestDevLocationsFixture(t *testing.T) {
	// A database with nothing in it but the migrations: the fixture must apply on its own.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db := testpg.Need(t, cluster).NewDB(ctx, t)
	sql, err := os.ReadFile("../../deploy/compose/dev-locations.sql")
	if err != nil {
		t.Fatal(err)
	}
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	for i := 0; i < 2; i++ { // twice: it is idempotent
		if _, err := super.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := super.Exec(ctx, `INSERT INTO ctrlz.tenants (id) VALUES ('00000000-0000-7000-8000-000000000a01')`); err != nil {
		t.Fatal(err)
	}
	st := db.Store(ctx, t, store.RoleTenant)
	var snapLen, allowedLen int
	var hasGlobal bool
	err = st.WithTenant(ctx, mustUUID("00000000-0000-7000-8000-000000000a01"), store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		snap, err := locations.Store{}.Snapshot(tx)
		if err != nil {
			return err
		}
		snapLen, hasGlobal = len(snap.Rows), snap.HasGlobal
		set, err := locations.Allowed(tx, snap, mustUUID("00000000-0000-7000-8000-0000000000ff"))
		allowedLen = len(set)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapLen != 5 || !hasGlobal {
		t.Errorf("the snapshot has %d locations and a global pair %v, want 5 and true", snapLen, hasGlobal)
	}
	if allowedLen != 4 {
		t.Errorf("the allowed set has %d locations, want 4 (Los Angeles is on one node only)", allowedLen)
	}
}

func mustUUID(s string) uuid.UUID { return uuid.MustParse(s) }
