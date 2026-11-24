package isolation

import (
	"net/http"
	"strings"
	"testing"
)

// world is two tenants in memory. A statement that lost its tenant predicate is a call that
// writes to both, which is all the harness has to be able to see.
type world struct {
	rows  [2]string
	shape [2]string
}

func (w *world) hooks() Hooks {
	return Hooks{
		Reset:   func(x Who) { w.rows[x], w.shape[x] = "base", "shape" },
		Digest:  func(x Who) map[string]string { return map[string]string{"t": w.rows[x]} },
		Shape:   func(x Who) string { return w.shape[x] },
		Leaks:   func() []string { return []string{"tenant-a-secret"} },
		ACookie: func() string { return "a-cookie" },
	}
}

// good is a fixture that does what the rule asks: A and B alike, a 200, B's rows written.
func good(w *world) Fixture {
	return Fixture{
		Effect: Changes, Status: 200,
		Arrange: func(Who) {},
		Call: func() Result {
			w.rows[B] = "written"
			return Result{Status: 200, Body: []byte("ok")}
		},
	}
}

func problems(t *testing.T, mutate func(w *world, fx *Fixture)) string {
	t.Helper()
	w := &world{}
	fx := good(w)
	mutate(w, &fx)
	return strings.Join(Judge(fx, w.hooks()), "\n")
}

// TestHarnessAcceptsTheRule is the control: the good fixture passes, so the failures below come
// from the one thing each of them breaks.
func TestHarnessAcceptsTheRule(t *testing.T) {
	if p := problems(t, func(*world, *Fixture) {}); p != "" {
		t.Fatalf("a correct fixture was refused: %s", p)
	}
}

// TestHarnessCanFail plants every way a fixture or a service can break the rule and requires
// the harness to say so. This is the mutant of the rule: without it a harness that always
// passed would look the same as one that works.
func TestHarnessCanFail(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(w *world, fx *Fixture)
		want   string
	}{
		"B's call is refused": {func(w *world, fx *Fixture) {
			fx.Call = func() Result { return Result{Status: 409, Body: []byte(`{"code":"conflict"}`)} }
		}, "a refusal proves nothing"},
		"B's call writes nothing": {func(w *world, fx *Fixture) {
			fx.Call = func() Result { return Result{Status: 200} }
		}, "wrote nothing"},
		"the call reaches A too": {func(w *world, fx *Fixture) {
			fx.Call = func() Result {
				w.rows[A], w.rows[B] = "written", "written"
				return Result{Status: 200}
			}
		}, "A's rows in t changed"},
		"a read that writes": {func(w *world, fx *Fixture) { fx.Effect = Shows; fx.Reason = "a read" }, "labelled Shows"},
		"elsewhere that writes to B": {func(w *world, fx *Fixture) {
			fx.Effect, fx.Reason, fx.Proof = Elsewhere, "console", func() error { return nil }
		}, "labelled Elsewhere"},
		"elsewhere whose write is missing": {func(w *world, fx *Fixture) {
			fx.Effect, fx.Reason = Elsewhere, "console"
			fx.Proof = func() error { return errNoWrite }
			fx.Call = func() Result { return Result{Status: 200} }
		}, "is not there"},
		"A is in another state": {func(w *world, fx *Fixture) {
			fx.Arrange = func(x Who) {
				if x == B {
					w.shape[B] = "more"
				}
			}
		}, "not in the same state"},
		"the answer does not reach B's data": {func(w *world, fx *Fixture) {
			fx.Sees = func() []string { return []string{"only-b"} }
		}, "did not reach B's data"},
		"the answer holds A's data": {func(w *world, fx *Fixture) {
			fx.Call = func() Result {
				w.rows[B] = "written"
				return Result{Status: 200, Body: []byte("x tenant-a-secret y")}
			}
		}, "which is A's"},
		"B's call on A's id writes A": {func(w *world, fx *Fixture) {
			fx.CrossStatus = 404
			fx.Cross = func() Result { w.rows[A] = "written"; return Result{Status: 404} }
		}, "A's rows in t changed by B's call on A's id"},
		"B's call on A's id succeeds": {func(w *world, fx *Fixture) {
			fx.CrossStatus = 404
			fx.Cross = func() Result { return Result{Status: 200} }
		}, "on A's id answered 200"},
		"B's call on A's id writes B beyond CrossBMay": {func(w *world, fx *Fixture) {
			fx.CrossStatus = 404
			fx.Cross = func() Result { w.rows[B] = "written"; return Result{Status: 404} }
		}, "B's rows in t changed by a refused call"},
		"the refusal names A": {func(w *world, fx *Fixture) {
			fx.CrossStatus = 404
			fx.Cross = func() Result { return Result{Status: 404, Body: []byte("tenant-a-secret")} }
		}, "refusal of B's call on A's id holds"},
		"A's token comes back": {func(w *world, fx *Fixture) {
			fx.Call = func() Result {
				w.rows[B] = "written"
				return Result{Status: 200, Cookies: "session=a-cookie"}
			}
		}, "A's token came back"},
	} {
		t.Run(name, func(t *testing.T) {
			if p := problems(t, c.mutate); !strings.Contains(p, c.want) {
				t.Fatalf("the harness said %q, want it to say %q", p, c.want)
			}
		})
	}
}

type noWrite struct{}

func (noWrite) Error() string { return "nothing was written" }

var errNoWrite error = noWrite{}

// TestCompleteCanFail plants the ways a set of fixtures can be incomplete or empty of proof.
func TestCompleteCanFail(t *testing.T) {
	ops := []Op{{ID: "a", Method: http.MethodGet}, {ID: "b", Method: http.MethodPost}}
	ok := func() Fixture { return good(&world{}) }
	for name, c := range map[string]struct {
		fixtures map[string]Fixture
		want     string
	}{
		"an operation with no fixture":     {map[string]Fixture{"a": ok()}, "operation b has no two-tenant success fixture"},
		"a fixture for no operation":       {map[string]Fixture{"a": ok(), "b": ok(), "c": ok()}, "c, which is not in the document"},
		"no effect":                        {map[string]Fixture{"a": ok(), "b": func() Fixture { f := ok(); f.Effect = 0; return f }()}, "names no effect"},
		"a refusal as the expected status": {map[string]Fixture{"a": ok(), "b": func() Fixture { f := ok(); f.Status = 404; return f }()}, "not a success"},
		"no call":                          {map[string]Fixture{"a": ok(), "b": func() Fixture { f := ok(); f.Call = nil; return f }()}, "no Arrange or no Call"},
		"elsewhere with no proof":          {map[string]Fixture{"a": ok(), "b": func() Fixture { f := ok(); f.Effect, f.Reason = Elsewhere, "r"; return f }()}, "Elsewhere needs a Proof"},
		"a POST that shows with no reason": {map[string]Fixture{"a": ok(), "b": func() Fixture { f := ok(); f.Effect = Shows; return f }()}, "Shows on a POST needs a Reason"},
	} {
		t.Run(name, func(t *testing.T) {
			if p := strings.Join(Complete(ops, c.fixtures), "\n"); !strings.Contains(p, c.want) {
				t.Fatalf("Complete said %q, want it to say %q", p, c.want)
			}
		})
	}
	if p := Complete(ops, map[string]Fixture{"a": ok(), "b": ok()}); len(p) != 0 {
		t.Fatalf("a complete set was refused: %v", p)
	}
}

// TestCompleteDemandsACrossCall is tenant-r5-5: an operation that takes an id the client chooses
// is not complete with a success fixture alone.
func TestCompleteDemandsACrossCall(t *testing.T) {
	ops := []Op{{ID: "a", Method: http.MethodDelete, Takes: "a path id"}}
	fx := good(&world{})
	if p := strings.Join(Complete(ops, map[string]Fixture{"a": fx}), "\n"); !strings.Contains(p, "has no Cross call") {
		t.Fatalf("Complete said %q for an id with no cross call", p)
	}
	fx.Cross, fx.CrossStatus = func() Result { return Result{Status: 404} }, 200
	if p := strings.Join(Complete(ops, map[string]Fixture{"a": fx}), "\n"); !strings.Contains(p, "not a refusal of the client") {
		t.Fatalf("Complete said %q for a cross call that expects a success", p)
	}
	fx.CrossStatus = 404
	fx.CrossBMay = []string{"t"}
	if p := strings.Join(Complete(ops, map[string]Fixture{"a": fx}), "\n"); !strings.Contains(p, "need a CrossReason") {
		t.Fatalf("Complete said %q for CrossBMay with no reason", p)
	}
	fx.CrossBMay = nil
	if p := Complete(ops, map[string]Fixture{"a": fx}); len(p) != 0 {
		t.Fatalf("a complete set was refused: %v", p)
	}
}

// TestCompleteDemandsACrossCallForEveryPlaceAnIDIsTaken is tenant-r16-13: an operation that takes a row id
// in two places (a path id and a body field, say) is not complete with one Cross call, because a handler
// that drops the tenant predicate for the place the call did not use passes it. Each place after the first
// needs its CrossAt call, and a CrossAt for a place the document does not have is stale.
func TestCompleteDemandsACrossCallForEveryPlaceAnIDIsTaken(t *testing.T) {
	ops := []Op{{ID: "a", Method: http.MethodPost, Takes: "two places", Locations: []string{"body:credential", "path:id"}}}
	fx := good(&world{})
	fx.Cross, fx.CrossStatus = func() Result { return Result{Status: 404} }, 404
	if p := strings.Join(Complete(ops, map[string]Fixture{"a": fx}), "\n"); !strings.Contains(p, "no Cross call for path:id") {
		t.Fatalf("Complete said %q for a second place with no call", p)
	}
	fx.CrossAt = map[string]func() Result{"path:id": func() Result { return Result{Status: 404} }}
	if p := Complete(ops, map[string]Fixture{"a": fx}); len(p) != 0 {
		t.Fatalf("a complete set was refused: %v", p)
	}
	fx.CrossAt["body:other"] = func() Result { return Result{Status: 404} }
	if p := strings.Join(Complete(ops, map[string]Fixture{"a": fx}), "\n"); !strings.Contains(p, "CrossAt names body:other") {
		t.Fatalf("Complete said %q for a stale CrossAt", p)
	}
}

// A CrossAt call is judged like Cross: one that writes A fails the fixture.
func TestACrossAtCallIsJudgedLikeCross(t *testing.T) {
	p := problems(t, func(w *world, fx *Fixture) {
		fx.CrossStatus = 404
		fx.Cross = func() Result { return Result{Status: 404} }
		fx.CrossAt = map[string]func() Result{"path:id": func() Result { w.rows[A] = "written"; return Result{Status: 404} }}
	})
	if !strings.Contains(p, "A's rows in t changed by B's call on A's id") {
		t.Fatalf("the harness said %q for a second place that writes A", p)
	}
}
