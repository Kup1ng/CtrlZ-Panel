package reachcheck_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
)

// fakeRows serves the one integer of the max_prepared_transactions query and nothing else.
type fakeRows struct {
	vals []int
	i    int
}

func (r *fakeRows) Next() bool { r.i++; return r.i <= len(r.vals) }
func (r *fakeRows) Scan(dest ...any) error {
	*(dest[0].(*int)) = r.vals[r.i-1]
	return nil
}
func (r *fakeRows) Close()     {}
func (r *fakeRows) Err() error { return nil }

// TestPreparedTransactionsMustBeOff is db-r17-7. The watchdog ends backends; a prepared transaction belongs to
// none, so a server that allows them lets a login role leave its row locks where no sweep can end them. The
// every-start judgement refuses a server whose max_prepared_transactions is not 0, whatever put it there (a
// profile's -c flag, a changed default).
func TestPreparedTransactionsMustBeOff(t *testing.T) {
	for _, c := range []struct {
		n    int
		want bool
	}{{0, false}, {1, true}, {50, true}} {
		q := reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
			if strings.Contains(sql, "max_prepared_transactions") {
				return &fakeRows{vals: []int{c.n}}, nil
			}
			return &fakeRows{}, nil
		})
		fs, err := reachcheck.JudgeBootstrapState(context.Background(), q, reachcheck.RolesFile{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range fs {
			if f.Security && strings.Contains(f.Text, "max_prepared_transactions is") {
				found = true
			}
		}
		if found != c.want {
			t.Errorf("max_prepared_transactions = %d: refused %v, want %v (%v)", c.n, found, c.want, reachcheck.Texts(fs))
		}
	}
}
