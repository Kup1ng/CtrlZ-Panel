package totp_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// memGuard is the in-memory twin of the two real guards: a counter for the
// throttle and an atomic "last step" for replay, the same rule as the UPDATE of
// 6.3, under a mutex in place of row atomicity.
type memGuard struct {
	mu       sync.Mutex
	hits     int
	max      int
	lastStep *int64
	resets   int
	hitErr   error
	spendErr error
	order    []string
}

func newGuard(max int) *memGuard { return &memGuard{max: max} }

func (g *memGuard) Hit(context.Context) (bool, time.Duration, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "hit")
	if g.hitErr != nil {
		return false, 0, g.hitErr
	}
	g.hits++
	if g.hits > g.max {
		return false, 7 * time.Minute, nil
	}
	return true, 0, nil
}

func (g *memGuard) Spend(_ context.Context, step int64) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "spend")
	if g.spendErr != nil {
		return false, g.spendErr
	}
	if g.lastStep != nil && *g.lastStep >= step {
		return false, nil
	}
	g.lastStep = &step
	return true, nil
}

func (g *memGuard) Reset(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.order = append(g.order, "reset")
	g.hits = 0
	g.resets++
	return nil
}

var (
	seed = secret.NewBytes([]byte("12345678901234567890"))
	t0   = time.Unix(1111111109, 0) // inside a step; its 6-digit code is 081804
)

func gen(at time.Time) secret.String { return secret.New(totp.Generate(seed, at)) }

func TestCheckAcceptsTheCurrentCode(t *testing.T) {
	g := newGuard(5)
	if err := totp.CheckAt(context.Background(), g, seed, secret.New("081804"), t0); err != nil {
		t.Fatalf("%v", err)
	}
	if strings.Join(g.order, ",") != "hit,spend,reset" {
		t.Errorf("order = %v, want hit, spend, reset (6.3)", g.order)
	}
	if g.resets != 1 {
		t.Error("success must reset the throttle")
	}
}

// TestWindowEdges: one step either side passes, two steps do not.
func TestWindowEdges(t *testing.T) {
	for off, ok := range map[int]bool{-3: false, -2: false, -1: true, 0: true, 1: true, 2: false, 3: false} {
		g := newGuard(100)
		code := gen(t0.Add(time.Duration(off) * 30 * time.Second))
		err := totp.CheckAt(context.Background(), g, seed, code, t0)
		if ok != (err == nil) {
			t.Errorf("offset %+d steps: err = %v, want accept=%v", off, err, ok)
		}
		if !ok && !errors.Is(err, totp.ErrInvalid) {
			t.Errorf("offset %+d: %v, want ErrInvalid", off, err)
		}
	}
}

func TestWrongCodesAreInvalidAndCostAnAttempt(t *testing.T) {
	for name, in := range map[string]string{
		"wrong":     "000000",
		"short":     "08180",
		"long":      "0818044",
		"empty":     "",
		"letters":   "08180a",
		"symbol":    "081.04",
		"huge":      strings.Repeat("1", 5000),
		"sql":       "0';--",
		"unicode":   "０８１８０４x",
		"zero-pad":  "81804",
		"neg":       "-81804",
		"double ws": "081  804",
	} {
		g := newGuard(100)
		err := totp.CheckAt(context.Background(), g, seed, secret.New(in), t0)
		if name == "double ws" {
			// Spaces are tolerated, so this one is a valid code.
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, totp.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
		if g.hits != 1 || g.lastStep != nil || g.resets != 0 {
			t.Errorf("%s: hits %d, spent %v, resets %d: want one hit and nothing else", name, g.hits, g.lastStep, g.resets)
		}
	}
}

func TestInputFormsOfAValidCode(t *testing.T) {
	for _, in := range []string{"081804", "081 804", "081-804", " 081804 ", "۰۸۱۸۰۴", "٠٨١٨٠٤", "０８１８０４"} {
		g := newGuard(5)
		if err := totp.CheckAt(context.Background(), g, seed, secret.New(in), t0); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestReplayIsRefused(t *testing.T) {
	g := newGuard(100)
	code := secret.New("081804")
	if err := totp.CheckAt(context.Background(), g, seed, code, t0); err != nil {
		t.Fatal(err)
	}
	hitsAfterOK := g.hits
	// The same code again, a moment later, in the same step.
	err := totp.CheckAt(context.Background(), g, seed, code, t0.Add(5*time.Second))
	if !errors.Is(err, totp.ErrStepReused) {
		t.Fatalf("second use: %v, want ErrStepReused", err)
	}
	if g.hits != hitsAfterOK+1 || g.resets != 1 {
		t.Errorf("a replay must cost an attempt and must not reset: hits %d resets %d", g.hits, g.resets)
	}
	// An older step still inside the window is also spent: the rule is "less than".
	older := gen(t0.Add(-30 * time.Second))
	if err := totp.CheckAt(context.Background(), g, seed, older, t0); !errors.Is(err, totp.ErrStepReused) {
		t.Errorf("code of an earlier step after a later one: %v", err)
	}
	// The next step's code is fresh.
	if err := totp.CheckAt(context.Background(), g, seed, gen(t0.Add(30*time.Second)), t0.Add(30*time.Second)); err != nil {
		t.Errorf("next step: %v", err)
	}
}

// TestParallelSameCodeOnePasses is the abuse test of 18.5: the same code twice
// in parallel, exactly one passes.
func TestParallelSameCodeOnePasses(t *testing.T) {
	for range 20 {
		g := newGuard(1000)
		var ok, reused, other atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				switch err := totp.CheckAt(context.Background(), g, seed, secret.New("081804"), t0); {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, totp.ErrStepReused):
					reused.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if ok.Load() != 1 || reused.Load() != 15 || other.Load() != 0 {
			t.Fatalf("ok %d reused %d other %d", ok.Load(), reused.Load(), other.Load())
		}
	}
}

func TestThrottleComesFirst(t *testing.T) {
	g := newGuard(2)
	for range 2 {
		if err := totp.CheckAt(context.Background(), g, seed, secret.New("000000"), t0); !errors.Is(err, totp.ErrInvalid) {
			t.Fatal(err)
		}
	}
	// The third attempt carries the right code and is still refused, before
	// anything is compared or spent.
	err := totp.CheckAt(context.Background(), g, seed, secret.New("081804"), t0)
	var tm *totp.TooManyError
	if !errors.Is(err, totp.ErrTooMany) || !errors.As(err, &tm) || tm.RetryAfter != 7*time.Minute {
		t.Fatalf("err = %v", err)
	}
	if g.lastStep != nil {
		t.Error("a throttled call spent a step")
	}
	if strings.Contains(strings.Join(g.order[len(g.order)-1:], ""), "spend") {
		t.Error("a throttled call reached Spend")
	}
}

func TestGuardFailuresPropagate(t *testing.T) {
	boom := errors.New("db down")
	g := newGuard(5)
	g.hitErr = boom
	if err := totp.CheckAt(context.Background(), g, seed, secret.New("081804"), t0); !errors.Is(err, boom) {
		t.Errorf("hit error: %v", err)
	}
	g = newGuard(5)
	g.spendErr = boom
	err := totp.CheckAt(context.Background(), g, seed, secret.New("081804"), t0)
	if !errors.Is(err, boom) || errors.Is(err, totp.ErrStepReused) {
		t.Errorf("spend error: %v", err)
	}
	if g.resets != 0 {
		t.Error("reset after a failed spend")
	}
	// An empty seed never verifies (a user whose seed could not be opened).
	if err := totp.CheckAt(context.Background(), newGuard(5), secret.Bytes{}, secret.New("081804"), t0); !errors.Is(err, totp.ErrInvalid) {
		t.Errorf("empty seed: %v", err)
	}
}

// TestClockStepOf90Seconds is 18.3: after the server clock jumps 90 s, a code
// inside the window passes, and a replay of it is still refused.
func TestClockStepOf90Seconds(t *testing.T) {
	g := newGuard(100)
	code := gen(t0)
	if err := totp.CheckAt(context.Background(), g, seed, code, t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(90 * time.Second) // clock stepped forward: the old code is 3 steps back
	if err := totp.CheckAt(context.Background(), g, seed, code, later); !errors.Is(err, totp.ErrInvalid) {
		t.Errorf("a code 3 steps old: %v", err)
	}
	back := t0.Add(-90 * time.Second) // clock stepped back: the code is 3 steps ahead
	if err := totp.CheckAt(context.Background(), g, seed, code, back); !errors.Is(err, totp.ErrInvalid) {
		t.Errorf("a code 3 steps ahead: %v", err)
	}
	// Within the window after a smaller step: valid code, but spent.
	if err := totp.CheckAt(context.Background(), g, seed, code, t0.Add(-25*time.Second)); !errors.Is(err, totp.ErrStepReused) {
		t.Errorf("replay after a clock step back: %v", err)
	}
}

func TestSecretAndURI(t *testing.T) {
	s, err := totp.NewSecret()
	if err != nil || s.Len() != totp.SecretSize {
		t.Fatalf("NewSecret: %d %v", s.Len(), err)
	}
	s2, _ := totp.NewSecret()
	if s.Equal(s2) {
		t.Error("two secrets are equal")
	}
	b32 := totp.Base32(secret.NewBytes([]byte("12345678901234567890")))
	if b32.Reveal() != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" { // RFC 4648 / RFC 6238 test key
		t.Errorf("Base32 = %s", b32.Reveal())
	}
	if strings.Contains(b32.Reveal(), "=") {
		t.Error("padding")
	}
	u := totp.URI(secret.NewBytes([]byte("12345678901234567890")), "+98912***4567").Reveal()
	want := "otpauth://totp/Ctrl%20Z:%2B98912%2A%2A%2A4567?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Ctrl%20Z&period=30&digits=6&algorithm=SHA1"
	if u != want {
		// The label escaping of "*" and "+" may differ between encoders; what
		// the spec fixes is the shape, so accept either spelling of the label.
		alt := strings.Replace(want, "%2A%2A%2A", "***", 1)
		if u != alt {
			t.Errorf("URI = %s\nwant  %s", u, want)
		}
	}
	for _, bad := range []string{"&", " ", "\n"} {
		if strings.Contains(totp.URI(s, "a"+bad+"b").Reveal(), "a"+bad+"b") {
			t.Errorf("label %q not escaped", bad)
		}
	}
	if fmt.Sprint(totp.URI(s, "x")) != secret.Redacted || fmt.Sprint(b32) != secret.Redacted {
		t.Error("URI or Base32 prints")
	}
}

// TestGenerateMatchesApps: any code made by Generate for the current step is
// accepted by Check, over many random secrets and times.
func TestGenerateRoundTrip(t *testing.T) {
	for i := range 50 {
		sd, _ := totp.NewSecret()
		now := time.Unix(1_700_000_000+int64(i)*7919, 0)
		if err := totp.CheckAt(context.Background(), newGuard(5), sd, secret.New(totp.Generate(sd, now)), now); err != nil {
			t.Fatalf("round trip %d: %v", i, err)
		}
	}
}
