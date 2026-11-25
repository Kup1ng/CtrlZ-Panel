package password_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// fast keeps the suite quick; the cost parameters are not what these tests are
// about. The default parameters are exercised by the benchmark and one test.
var fast = password.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func newHasher(t testing.TB, p password.Params, slots int) *password.Hasher {
	t.Helper()
	h, err := password.NewHasher(p, password.NewGate(slots, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func pw(s string) secret.String { return secret.New(s) }

func TestHashVerify(t *testing.T) {
	ctx := context.Background()
	h := newHasher(t, fast, 2)
	hash, err := h.Hash(ctx, pw("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash.Reveal(), "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Errorf("not the PHC format of 4.1: %q", strings.SplitN(hash.Reveal(), "$", 5)[:4])
	}
	parts := strings.Split(hash.Reveal(), "$")
	if salt, _ := base64.RawStdEncoding.DecodeString(parts[4]); len(salt) != 16 {
		t.Errorf("salt is %d bytes, want 16", len(salt))
	}
	if sum, _ := base64.RawStdEncoding.DecodeString(parts[5]); len(sum) != 32 {
		t.Errorf("hash is %d bytes, want 32", len(sum))
	}
	if ok, err := h.Verify(ctx, pw("correct horse battery staple"), hash); !ok || err != nil {
		t.Errorf("right password: %v, %v", ok, err)
	}
	for _, wrong := range []string{"correct horse battery stapl", "Correct horse battery staple", "", " correct horse battery staple"} {
		if ok, err := h.Verify(ctx, pw(wrong), hash); ok || err != nil {
			t.Errorf("wrong password %q: %v, %v", wrong, ok, err)
		}
	}
	other, _ := h.Hash(ctx, pw("correct horse battery staple"))
	if other.Reveal() == hash.Reveal() {
		t.Error("two hashes of one password are equal: the salt is not random")
	}
	if got := fmt.Sprintf("%v %+v", hash, struct{ H secret.String }{hash}); strings.Contains(got, "argon2id") {
		t.Errorf("the hash prints: %s", got)
	}
}

// TestArgon2idVector verifies a published Argon2id value through the real PHC
// parser. The vector is the reference implementation's, as carried in
// golang.org/x/crypto/argon2's own tests: password "password", salt "somesalt",
// t=2, m=64 KiB, p=1, 24 bytes.
func TestArgon2idVector(t *testing.T) {
	sum, _ := hex.DecodeString("068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7")
	enc := base64.RawStdEncoding
	stored := pw("$argon2id$v=19$m=64,t=2,p=1$" + enc.EncodeToString([]byte("somesalt")) + "$" + enc.EncodeToString(sum))
	h := newHasher(t, fast, 1)
	if ok, err := h.Verify(context.Background(), pw("password"), stored); !ok || err != nil {
		t.Fatalf("the published vector did not verify: %v, %v", ok, err)
	}
	if ok, _ := h.Verify(context.Background(), pw("passwore"), stored); ok {
		t.Error("a wrong password verified against the vector")
	}
	// Different parameters from the current ones, and a 24-byte output: rehash.
	if !h.NeedsRehash(stored) {
		t.Error("an old-parameter hash must need a rehash")
	}
}

func TestNeedsRehash(t *testing.T) {
	ctx := context.Background()
	old := newHasher(t, password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, 1)
	cur := newHasher(t, password.Params{MemoryKiB: 128, Time: 2, Threads: 1}, 1)
	hash, _ := old.Hash(ctx, pw("a long enough password"))
	if old.NeedsRehash(hash) {
		t.Error("a fresh hash needs no rehash")
	}
	if !cur.NeedsRehash(hash) {
		t.Error("memory and time differ: rehash")
	}
	if !cur.NeedsRehash(pw("garbage")) || !cur.NeedsRehash(secret.String{}) {
		t.Error("an unreadable hash needs a rehash")
	}
	// The old hash still verifies under the new hasher (it reads its own parameters).
	if ok, err := cur.Verify(ctx, pw("a long enough password"), hash); !ok || err != nil {
		t.Errorf("old parameters: %v, %v", ok, err)
	}
}

// TestOneArgonRunOnEveryPath is the 4.5 requirement: a known user, an unknown
// phone (empty hash), an OTP-only account, a malformed stored hash and an
// over-long input all cost exactly one Argon2 run.
func TestOneArgonRunOnEveryPath(t *testing.T) {
	ctx := context.Background()
	h := newHasher(t, fast, 2)
	good, _ := h.Hash(ctx, pw("a long enough password"))
	for name, c := range map[string]struct {
		pw, stored secret.String
		wantOK     bool
		wantErr    error
	}{
		"known user, right":    {pw("a long enough password"), good, true, nil},
		"known user, wrong":    {pw("another password!!"), good, false, nil},
		"unknown phone":        {pw("a long enough password"), secret.String{}, false, nil},
		"unknown, empty input": {secret.String{}, secret.String{}, false, nil},
		"malformed hash":       {pw("a long enough password"), pw("$argon2id$v=19$m=x"), false, nil},
		"huge input":           {pw(strings.Repeat("x", 1<<20)), good, false, nil},
		"too many characters":  {pw(strings.Repeat("x", 129)), good, false, nil},
		"invalid UTF-8":        {pw("abc\xff\xfe"), good, false, nil},
	} {
		before := h.Runs()
		ok, err := h.Verify(ctx, c.pw, c.stored)
		if ok != c.wantOK || !errors.Is(err, c.wantErr) {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
		if got := h.Runs() - before; got != 1 {
			t.Errorf("%s: %d Argon2 runs, want exactly 1", name, got)
		}
	}
}

func TestStoredHashBounds(t *testing.T) {
	// A budget of 64 MiB in one slot: a row may ask for 64 MiB and not a KiB more.
	h, err := password.NewHasher(fast, password.NewGateBudget(1, time.Second, 64))
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawStdEncoding
	salt, sum := enc.EncodeToString(make([]byte, 16)), enc.EncodeToString(make([]byte, 32))
	for name, s := range map[string]string{
		"argon2i":     "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + sum,
		"old version": "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + sum,
		"huge memory": "$argon2id$v=19$m=4194304,t=1,p=1$" + salt + "$" + sum,
		// 256 MiB parses, but it is as large as the api container: primitives-r1-7.
		"container-sized memory": "$argon2id$v=19$m=262144,t=1,p=1$" + salt + "$" + sum,
		"just over the bound":    "$argon2id$v=19$m=65537,t=1,p=1$" + salt + "$" + sum,
		"huge time":              "$argon2id$v=19$m=64,t=999,p=1$" + salt + "$" + sum,
		"too many threads":       "$argon2id$v=19$m=640,t=1,p=99$" + salt + "$" + sum,
		"zero time":              "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + sum,
		"memory too low":         "$argon2id$v=19$m=4,t=1,p=1$" + salt + "$" + sum,
		"wrong order":            "$argon2id$v=19$t=1,m=64,p=1$" + salt + "$" + sum,
		"plus sign":              "$argon2id$v=19$m=+64,t=1,p=1$" + salt + "$" + sum,
		"short salt":             "$argon2id$v=19$m=64,t=1,p=1$" + enc.EncodeToString(make([]byte, 4)) + "$" + sum,
		"short hash":             "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + enc.EncodeToString(make([]byte, 8)),
		"padded base64":          "$argon2id$v=19$m=64,t=1,p=1$" + salt + "==$" + sum,
		"extra field":            "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + sum + "$x",
		"empty parts":            "$$$$$",
	} {
		unread := h.Unreadable()
		before := h.Runs()
		ok, err := h.Verify(context.Background(), pw("password"), pw(s))
		if ok || err != nil || h.Unreadable() != unread+1 {
			t.Errorf("%s: ok=%v err=%v, want a wrong password counted as unreadable", name, ok, err)
		}
		if h.Runs()-before != 1 {
			t.Errorf("%s: want one Argon2 run on the dummy", name)
		}
	}
}

// TestStoredMemoryIsBoundedByTheBudget: the most a stored hash may ask for is one
// slot of the process's budget (rule argon2-memory-budget), whatever the current
// setting is. A lowered setting still verifies the old rows as long as they fit.
func TestStoredMemoryIsBoundedByTheBudget(t *testing.T) {
	enc := base64.RawStdEncoding
	salt, sum := enc.EncodeToString(make([]byte, 16)), enc.EncodeToString(make([]byte, 32))
	row := func(m int) secret.String {
		return pw(fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=1$%s$%s", m, salt, sum))
	}
	for name, c := range map[string]struct {
		slots     int
		budgetMiB uint64
		rowKiB    int
		malformed bool
	}{
		"one slot of 64 MiB at the ceiling":     {1, 64, 65536, false},
		"one slot of 64 MiB, one KiB over":      {1, 64, 65537, true},
		"two slots share the budget":            {2, 128, 65536, false},
		"four slots make each one smaller":      {4, 128, 65536, true},
		"a row far below the setting is read":   {1, 64, 64, false},
		"a container-sized row, a big budget":   {1, 192, 262144, true},
		"the whole budget is one row, one slot": {1, 192, 196608, false},
	} {
		// The hasher itself is at 64 KiB: the bound is the budget, not twice the setting.
		h, err := password.NewHasher(fast, password.NewGateBudget(c.slots, time.Second, c.budgetMiB))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ok, err := h.Verify(context.Background(), pw("password"), row(c.rowKiB))
		if ok || err != nil || (h.Unreadable() == 1) != c.malformed {
			t.Errorf("%s: ok=%v err=%v, malformed wanted %v", name, ok, err, c.malformed)
		}
	}
}

// TestNewHasherIsNotLargerThanOneSlot: a hasher whose own cost does not fit a slot
// of the budget is refused at build time (the same rule from the other side).
func TestNewHasherIsNotLargerThanOneSlot(t *testing.T) {
	p := password.Params{MemoryKiB: 47104, Time: 2, Threads: 1}
	if _, err := password.NewHasher(p, password.NewGateBudget(2, time.Second, 92)); err != nil {
		t.Errorf("2 slots of 46 MiB in 92 MiB: %v", err)
	}
	if _, err := password.NewHasher(p, password.NewGateBudget(2, time.Second, 91)); err == nil {
		t.Error("2 slots of 46 MiB in 91 MiB accepted")
	}
	if _, err := password.NewHasher(p, password.NewGateBudget(5, time.Second, 192)); err == nil {
		t.Error("5 slots of 46 MiB in 192 MiB accepted")
	}
}

func TestNormalizeAndLimits(t *testing.T) {
	// The same text typed two ways: NFKC makes the compatibility forms equal.
	a, err := password.Normalize(pw("ｐａｓｓｗｏｒｄ１２３４５"))
	if err != nil || a.Reveal() != "password12345" {
		t.Fatalf("fullwidth: %q %v", a.Reveal(), err)
	}
	if b, _ := password.Normalize(pw(strings.Repeat("e"+string(rune(0x301)), 10))); b.Reveal() != strings.Repeat("é", 10) {
		t.Errorf("composition: %q", b.Reveal())
	}
	// The half-space is dropped, and what is left is in NFKC: "e", half-space, acute accent and the
	// same word typed without the half-space are one password (primitives-r19-5).
	withZWNJ, _ := password.Normalize(pw("e‌́tudiant99"))
	without, _ := password.Normalize(pw("étudiant99"))
	if withZWNJ.Reveal() != without.Reveal() || without.Reveal() != "étudiant99" {
		t.Errorf("half-space before a combining mark: %q and %q", withZWNJ.Reveal(), without.Reveal())
	}
	// Arabic ي and ك stay what they are: no folding to Persian ی and ک.
	if got, _ := password.Normalize(pw("يك")); got.Reveal() != "يك" {
		t.Errorf("Arabic letters were folded: %q", got.Reveal())
	}
	// And the hash agrees across the two keyboards.
	ctx := context.Background()
	h := newHasher(t, fast, 1)
	hash, _ := h.Hash(ctx, pw("ｐａｓｓｗｏｒｄ１２３４５"))
	if ok, _ := h.Verify(ctx, pw("password12345"), hash); !ok {
		t.Error("NFKC pair does not verify")
	}

	for name, c := range map[string]struct {
		in   string
		kind password.Kind
		want error
	}{
		"user 9":           {strings.Repeat("a", 9), password.User, password.ErrTooShort},
		"user 10":          {strings.Repeat("a", 10), password.User, nil},
		"admin 13":         {strings.Repeat("a", 13), password.Admin, password.ErrTooShort},
		"admin 14":         {strings.Repeat("a", 14), password.Admin, nil},
		"128 characters":   {strings.Repeat("a", 128), password.User, nil},
		"129 characters":   {strings.Repeat("a", 129), password.User, password.ErrTooLong},
		"128 Persian":      {strings.Repeat("ض", 128), password.User, nil}, // 256 bytes
		"4-byte x128":      {strings.Repeat("😀", 128), password.User, nil},
		"4-byte x129":      {strings.Repeat("😀", 129), password.User, password.ErrTooLong},
		"1 MiB":            {strings.Repeat("a", 1<<20), password.User, password.ErrTooLong},
		"invalid UTF-8":    {"abcdefghij\xff", password.User, password.ErrInvalid},
		"counted after":    {strings.Repeat("ｐ", 9), password.User, password.ErrTooShort},                  // 9 code points
		"expands past max": {strings.Repeat(string(rune(0xfdfa)), 20), password.User, password.ErrTooLong}, // NFKC: 18 code points each
	} {
		_, err := password.Prepare(pw(c.in), c.kind)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	// Normalize alone has no minimum: login must compare short legacy passwords.
	if _, err := password.Normalize(pw("abc")); err != nil {
		t.Errorf("Normalize applied a minimum: %v", err)
	}
	if password.User.MinLength() != 10 || password.Admin.MinLength() != 14 {
		t.Error("minimums")
	}
}

func TestDefaultParamsAreSpec(t *testing.T) {
	p := password.DefaultParams()
	if p.MemoryKiB != 47104 || p.Time != 2 || p.Threads != 1 {
		t.Fatalf("%+v", p)
	}
	// One real hash at the real cost, to prove the parameters work end to end.
	h := newHasher(t, p, 1)
	hash, err := h.Hash(context.Background(), pw("a long enough password"))
	if err != nil || !strings.Contains(hash.Reveal(), "$m=47104,t=2,p=1$") {
		t.Fatalf("%v", err)
	}
	if h.NeedsRehash(hash) {
		t.Error("default hash flags itself")
	}
}

func TestNewHasherRefusesBadInput(t *testing.T) {
	g := password.NewGate(1, time.Second)
	for name, p := range map[string]password.Params{
		"zero":         {},
		"no time":      {MemoryKiB: 64, Threads: 1},
		"no threads":   {MemoryKiB: 64, Time: 1},
		"tiny memory":  {MemoryKiB: 4, Time: 1, Threads: 1},
		"huge memory":  {MemoryKiB: 1 << 30, Time: 1, Threads: 1},
		"huge time":    {MemoryKiB: 64, Time: 1000, Threads: 1},
		"threads vs m": {MemoryKiB: 16, Time: 1, Threads: 4},
	} {
		if _, err := password.NewHasher(p, g); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := password.NewHasher(fast, nil); err == nil {
		t.Error("nil gate accepted")
	}
}

func TestGate(t *testing.T) {
	g := password.NewGate(2, 100*time.Millisecond)
	if g.Size() != 2 {
		t.Fatalf("Size = %d", g.Size())
	}
	r1, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := g.Acquire(context.Background()); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("a full gate returned %v, want ErrBusy", err)
	}
	if d := time.Since(start); d < 90*time.Millisecond || d > 2*time.Second {
		t.Errorf("waited %v, want about 100ms", d)
	}
	r1()
	r3, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatalf("after a release: %v", err)
	}
	// A request that goes away stops waiting.
	ctx, cancel := context.WithCancel(context.Background())
	long := password.NewGate(1, time.Minute)
	hold, _ := long.Acquire(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := long.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	hold()
	r2()
	r3()
	if password.NewGate(0, 0).Size() != 1 {
		t.Error("a gate of 0 slots must be 1")
	}
}

// TestGateBoundsConcurrency: no more hashes run at once than the gate allows,
// and the rest are refused with ErrBusy, not queued without end.
func TestGateBoundsConcurrency(t *testing.T) {
	h, err := password.NewHasher(password.Params{MemoryKiB: 4096, Time: 2, Threads: 1}, password.NewGate(2, 5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var busy, ok atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.Hash(context.Background(), pw("a long enough password"))
			switch {
			case errors.Is(err, password.ErrBusy):
				busy.Add(1)
			case err == nil:
				ok.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() < 2 {
		t.Errorf("only %d hashes ran", ok.Load())
	}
	if int(ok.Load()+busy.Load()) != 12 {
		t.Errorf("ok %d + busy %d != 12", ok.Load(), busy.Load())
	}
	if h.Runs() != uint64(ok.Load()) {
		t.Errorf("Runs = %d, completed = %d: a refused call must not count", h.Runs(), ok.Load())
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	st, err := password.FromEnv(env(nil))
	if err != nil || st.Params != password.DefaultParams() || st.Gate().Size() != 2 {
		t.Fatalf("defaults: %+v %v", st, err)
	}
	st, err = password.FromEnv(env(map[string]string{"CTRLZ_ARGON2_M_KIB": "19456", "CTRLZ_ARGON2_T": "3", "CTRLZ_ARGON2_CONCURRENCY": "1"}))
	if err != nil || st.Params.MemoryKiB != 19456 || st.Params.Time != 3 || st.Gate().Size() != 1 {
		t.Fatalf("overrides: %+v %v", st, err)
	}
	for name, m := range map[string]map[string]string{
		"memory below OWASP":  {"CTRLZ_ARGON2_M_KIB": "1024"},
		"memory not a number": {"CTRLZ_ARGON2_M_KIB": "lots"},
		"memory huge":         {"CTRLZ_ARGON2_M_KIB": "99999999"},
		"time zero":           {"CTRLZ_ARGON2_T": "0"},
		"time huge":           {"CTRLZ_ARGON2_T": "999"},
		"concurrency zero":    {"CTRLZ_ARGON2_CONCURRENCY": "0"},
		"concurrency junk":    {"CTRLZ_ARGON2_CONCURRENCY": "-1"},
	} {
		_, err := password.FromEnv(env(m))
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		for _, v := range m {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: the error repeats the value: %v", name, err)
			}
		}
	}
	// OWASP's minimum pairs: the memory floor and the iteration floor are one
	// rule (primitives-r1-16). 19 MiB needs t=2, 46 MiB is enough with t=1.
	for name, m := range map[string]map[string]string{
		"19 MiB with t=1":           {"CTRLZ_ARGON2_M_KIB": "19456", "CTRLZ_ARGON2_T": "1"},
		"46 MiB minus one with t=1": {"CTRLZ_ARGON2_M_KIB": "47103", "CTRLZ_ARGON2_T": "1"},
		"defaults are accepted":     nil,
	} {
		_, err := password.FromEnv(env(m))
		if (m == nil) != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := password.FromEnv(env(map[string]string{"CTRLZ_ARGON2_M_KIB": "47104", "CTRLZ_ARGON2_T": "1"})); err != nil {
		t.Errorf("46 MiB with t=1 is OWASP's first pair: %v", err)
	}
	// Concurrency times memory stays inside the budget (primitives-r1-7).
	for name, m := range map[string]map[string]string{
		"5 hashes of 46 MiB":  {"CTRLZ_ARGON2_CONCURRENCY": "5"},
		"2 hashes of 256 MiB": {"CTRLZ_ARGON2_M_KIB": "262144", "CTRLZ_ARGON2_CONCURRENCY": "2"},
		"budget junk":         {"CTRLZ_ARGON2_BUDGET_MIB": "lots"},
	} {
		if _, err := password.FromEnv(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// 4 hashes of 46 MiB is the standard profile; a larger budget allows more.
	if _, err := password.FromEnv(env(map[string]string{"CTRLZ_ARGON2_CONCURRENCY": "4"})); err != nil {
		t.Errorf("standard profile refused: %v", err)
	}
	if _, err := password.FromEnv(env(map[string]string{"CTRLZ_ARGON2_CONCURRENCY": "8", "CTRLZ_ARGON2_BUDGET_MIB": "400"})); err != nil {
		t.Errorf("8 hashes with a 400 MiB budget: %v", err)
	}
	// The test environment may use the Argon2 minimum.
	st, err = password.FromEnv(env(map[string]string{"CTRLZ_ENV": "test", "CTRLZ_ARGON2_M_KIB": "64"}))
	if err != nil || st.Params.MemoryKiB != 64 {
		t.Errorf("test env: %+v %v", st, err)
	}
}

func TestFloor(t *testing.T) {
	var now time.Time = time.Unix(1000, 0)
	var slept time.Duration
	tm := password.Timing{
		Now:    func() time.Time { return now },
		Sleep:  func(_ context.Context, d time.Duration) error { slept += d; now = now.Add(d); return nil },
		Jitter: func() time.Duration { return 20 * time.Millisecond },
	}
	ctx := context.Background()

	// A fast call waits out the floor plus jitter.
	err := tm.Floor(ctx, 300*time.Millisecond, func(context.Context) error { now = now.Add(50 * time.Millisecond); return nil })
	if err != nil || slept != 270*time.Millisecond {
		t.Errorf("fast: slept %v err %v, want 270ms", slept, err)
	}
	// A slow call does not wait again.
	slept = 0
	_ = tm.Floor(ctx, 300*time.Millisecond, func(context.Context) error { now = now.Add(time.Second); return nil })
	if slept != 0 {
		t.Errorf("slow: slept %v", slept)
	}
	// A failing call keeps the floor ("Postgres down during Floor") and its error.
	slept = 0
	boom := errors.New("db down")
	if err := tm.Floor(ctx, 300*time.Millisecond, func(context.Context) error { return boom }); !errors.Is(err, boom) || slept != 320*time.Millisecond {
		t.Errorf("failing: slept %v err %v", slept, err)
	}
}

func TestRealFloor(t *testing.T) {
	start := time.Now()
	err := password.Floor(context.Background(), 60*time.Millisecond, func(context.Context) error { return nil })
	d := time.Since(start)
	if err != nil || d < 60*time.Millisecond || d > 60*time.Millisecond+password.MaxJitter+500*time.Millisecond {
		t.Errorf("took %v, err %v", d, err)
	}
	// A cancelled request does not sit out the floor.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	_ = password.Floor(ctx, time.Minute, func(context.Context) error { return nil })
	if time.Since(start) > 2*time.Second {
		t.Error("Floor ignored a cancelled context")
	}
	// Jitter stays under the bound over many draws.
	tm := password.RealTiming()
	var lo, hi time.Duration = time.Hour, 0
	for range 500 {
		j := tm.Jitter()
		lo, hi = min(lo, j), max(hi, j)
	}
	if lo < 0 || hi >= password.MaxJitter || hi == lo {
		t.Errorf("jitter range [%v, %v]", lo, hi)
	}
}

func TestNothingPrints(t *testing.T) {
	h := newHasher(t, fast, 1)
	hash, _ := h.Hash(context.Background(), pw("a long enough password"))
	var sb strings.Builder
	slog.New(slog.NewTextHandler(&sb, nil)).Info("x", "hash", hash, "h", h)
	if strings.Contains(sb.String(), "argon2id$") || strings.Contains(sb.String(), hash.Reveal()) {
		t.Errorf("slog printed the hash: %s", sb.String())
	}
}

// BenchmarkHash records the time of one hash at the parameters of 4.1 (D31).
// Target 150 to 300 ms on the small profile; if over 300 ms lower t, not m.
func BenchmarkHash(b *testing.B) {
	h := newHasher(b, password.DefaultParams(), 1)
	in := pw("a long enough password")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.Hash(context.Background(), in); err != nil {
			b.Fatal(err)
		}
	}
}

// A one-time hash is cheap, verifies while the gate is full, never asks for a
// rehash, and refuses a password that is not a generated one (review round 3,
// admin-r3-11).
func TestOneTimeHashTakesNoGateSlot(t *testing.T) {
	gate := password.NewGate(1, 30*time.Millisecond)
	h, err := password.NewHasher(password.Params{MemoryKiB: 64, Time: 1, Threads: 1}, gate)
	if err != nil {
		t.Fatal(err)
	}
	otp, err := password.NewOneTime()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.HashOneTime(otp)
	if err != nil {
		t.Fatal(err)
	}
	release, err := gate.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// Gate full: the gate-free check of the admin login still verifies, right and
	// wrong. It is the declared exception of the known-or-unknown rule (spec 10.2
	// step 2).
	if ok, err := h.VerifyGateFree(t.Context(), otp, hash); err != nil || !ok {
		t.Fatalf("right one-time password with a full gate: %v %v", ok, err)
	}
	if ok, err := h.VerifyGateFree(t.Context(), secret.New("ONETIMEPASSWORD000000000"), hash); err != nil || ok {
		t.Fatalf("wrong password with a full gate: %v %v", ok, err)
	}
	// Every other caller waits for a slot as an unknown phone does: whether a
	// request reaches the gate must not depend on how the password was made (round
	// 5, rule known-unknown-oracle).
	before := gate.Attempts()
	if _, err := h.Verify(t.Context(), otp, hash); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("Verify of a one-time hash with a full gate: %v, want ErrBusy", err)
	}
	if gate.Attempts() != before+1 {
		t.Errorf("Verify of a one-time hash made %d gate attempts, want 1", gate.Attempts()-before)
	}
	if h.NeedsRehash(hash) {
		t.Error("a one-time hash asked for a rehash")
	}
	// A normal hash of the same hasher still waits for the gate.
	if _, err := h.Hash(t.Context(), otp); !errors.Is(err, password.ErrBusy) {
		t.Fatalf("a full-cost hash with a full gate: %v, want ErrBusy", err)
	}
	// Only generated passwords: a chosen one must fail rather than get the cheap hash.
	if _, err := h.HashOneTime(secret.New("short but chosen")); !errors.Is(err, password.ErrNotOneTime) {
		t.Fatalf("a short password: %v, want ErrNotOneTime", err)
	}
	// primitives-r5-6: a chosen password of the right length used to get the cheap hash, which
	// the gate-free admin verify then trusts. Only the shape NewOneTime writes passes.
	for name, chosen := range map[string]string{
		"24 of one letter":         "aaaaaaaaaaaaaaaaaaaaaaaa",
		"upper, one letter":        "AAAAAAAAAAAAAAAAAAAAAAAA",
		"a phrase repeated":        "PASSWORDPASSWORDPASSWORD",
		"a typed sentence":         "Correct horse battery sta",
		"digits outside base32":    "012345678901234567890189",
		"one character too many":   otp.Reveal() + "A",
		"one character too few":    otp.Reveal()[1:],
		"lower case of a real one": strings.ToLower(otp.Reveal()),
	} {
		if _, err := h.HashOneTime(secret.New(chosen)); !errors.Is(err, password.ErrNotOneTime) {
			t.Errorf("%s: %v, want ErrNotOneTime", name, err)
		}
	}
}

// TestEveryGeneratedPasswordIsAcceptedByHashOneTime keeps the shape check honest in the other
// direction: it must never refuse what NewOneTime writes, or an admin command would fail at
// random. The gate of 8 distinct characters is far below the 17 a draw has on average.
func TestEveryGeneratedPasswordIsAcceptedByHashOneTime(t *testing.T) {
	h, err := password.NewOneTimeHasher()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3000; i++ {
		pw, err := password.NewOneTime()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.HashOneTime(pw); err != nil {
			t.Fatalf("a generated password was refused: %v", err)
		}
	}
}

func TestPrepareCountsTheShorterOfTypedAndNormalised(t *testing.T) {
	for _, pw := range []string{"ﷺ", "ﷺ1", "ﷺ﷽"} {
		for _, kind := range []password.Kind{password.User, password.Admin} {
			if _, err := password.Prepare(secret.New(pw), kind); !errors.Is(err, password.ErrTooShort) {
				t.Errorf("%q kind %v: %v, want ErrTooShort", pw, kind, err)
			}
		}
	}
	// Composition shrinks the other way: nine typed code points that NFKC leaves
	// at nine are still nine, and ten plain ones pass.
	if _, err := password.Prepare(secret.New("abcdefghij"), password.User); err != nil {
		t.Errorf("ten plain code points: %v", err)
	}
	// A decomposed letter plus mark is two typed code points and one normalised.
	dec := "e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301e\u0301" // nine letters, eighteen typed
	if _, err := password.Prepare(secret.New(dec), password.User); !errors.Is(err, password.ErrTooShort) {
		t.Errorf("nine composed letters: %v, want ErrTooShort", err)
	}
}

// TestAnUnreadableStoredHashIsAWrongPasswordOnBothVerifies is primitives-r8-5 at the primitive: the
// mapping is not left to the caller. Verify and VerifyGateFree both answer (false, nil) for a hash
// that is damaged or above the ceiling, count it, and tell the hook, which takes no argument and so
// cannot carry the hash anywhere.
func TestAnUnreadableStoredHashIsAWrongPasswordOnBothVerifies(t *testing.T) {
	h, err := password.NewHasher(fast, password.NewGateBudget(1, time.Second, 64))
	if err != nil {
		t.Fatal(err)
	}
	var told int
	h.OnUnreadable(func() { told++ })
	enc := base64.RawStdEncoding
	salt, sum := enc.EncodeToString(make([]byte, 16)), enc.EncodeToString(make([]byte, 32))
	for name, stored := range map[string]string{
		"damaged":   "not-a-hash",
		"oversized": "$argon2id$v=19$m=4194304,t=2,p=1$" + salt + "$" + sum,
	} {
		for vname, verify := range map[string]func(context.Context, secret.String, secret.String) (bool, error){
			"Verify": h.Verify, "VerifyGateFree": h.VerifyGateFree,
		} {
			before, hookBefore := h.Unreadable(), told
			ok, err := verify(context.Background(), pw("a long enough password"), pw(stored))
			if ok || err != nil || h.Unreadable() != before+1 || told != hookBefore+1 {
				t.Errorf("%s/%s: ok=%v err=%v counted=%d told=%d", name, vname, ok, err, h.Unreadable()-before, told-hookBefore)
			}
		}
	}
	// An account with no password at all is not an unreadable hash and is not counted.
	before := h.Unreadable()
	if ok, err := h.Verify(context.Background(), pw("a long enough password"), secret.String{}); ok || err != nil || h.Unreadable() != before {
		t.Errorf("empty stored hash: ok=%v err=%v counted=%d", ok, err, h.Unreadable()-before)
	}
}

// TestNoOrdinaryHasherWritesTheOneTimeParameters is primitives-r8-1. CTRLZ_ENV=test lowers the memory
// floor to 8 KiB and allows t=1, which used to let Hash write exactly the parameters that mean "console
// one-time hash": VerifyGateFree then took no slot for any admin password and NeedsRehash never
// upgraded it. The pair is reserved for HashOneTime, in every way a hasher is made.
func TestNoOrdinaryHasherWritesTheOneTimeParameters(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, err := password.FromEnv(env(map[string]string{"CTRLZ_ENV": "test", "CTRLZ_ARGON2_M_KIB": "8", "CTRLZ_ARGON2_T": "1"})); err == nil {
		t.Error("FromEnv accepted m=8, t=1 under CTRLZ_ENV=test")
	}
	if _, err := password.NewHasher(password.Params{MemoryKiB: 8, Time: 1, Threads: 1}, password.NewGate(1, time.Second)); err == nil {
		t.Error("NewHasher accepted the one-time parameters")
	}
	st := password.Settings{Params: password.Params{MemoryKiB: 8, Time: 1, Threads: 1}, Concurrency: 1, BudgetMiB: 64, Relaxed: true}
	if _, err := st.NewHasher(); err == nil {
		t.Error("Settings.NewHasher accepted the one-time parameters")
	}
	// The neighbours stay allowed in the test environment: t=2 at 8 KiB, and 16 KiB at t=1.
	for _, p := range []password.Params{{MemoryKiB: 8, Time: 2, Threads: 1}, {MemoryKiB: 16, Time: 1, Threads: 1}} {
		st.Params = p
		h, err := st.NewHasher()
		if err != nil {
			t.Errorf("%+v refused: %v", p, err)
			continue
		}
		// Whatever it writes is read as an ordinary hash: the gate is taken (a full gate answers busy).
		hash, err := h.Hash(context.Background(), pw("a long enough password"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(hash.Reveal(), "m=8,t=1,p=1") {
			t.Errorf("%+v wrote the one-time parameters", p)
		}
	}
	// The console hasher is the one maker and still works.
	oh, err := password.NewOneTimeHasher()
	if err != nil {
		t.Fatal(err)
	}
	otp, err := password.NewOneTime()
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := oh.HashOneTime(otp); err != nil || !strings.Contains(hash.Reveal(), "m=8,t=1,p=1") {
		t.Errorf("one-time hasher: %v", err)
	}
}

// TestThePaddingOfInvisibleCodePointsDoesNotReachTheFloor is primitives-r16-1 and -10. The strength
// gate scores the text with the invisible code points removed, so a minimum that counted them let
// eight visible characters (which score 3 or 4 as random text) pass the 14 of an admin password
// and seven pass the 10 of a user's. The class is digits.Invisible and nothing else: the test walks
// every code point of it, so a class that is narrowed later fails here, not only the three the
// finding named.
func TestThePaddingOfInvisibleCodePointsDoesNotReachTheFloor(t *testing.T) {
	var invisible []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if digits.Invisible(r) && utf8.ValidRune(r) {
			invisible = append(invisible, r)
		}
	}
	if len(invisible) < 300 {
		t.Fatalf("the invisible class has %d code points; the walk is not reading it", len(invisible))
	}
	for _, r := range invisible {
		pad := func(visible string, n int) secret.String { return secret.New(visible + strings.Repeat(string(r), n)) }
		if _, err := password.Prepare(pad("x7Qz!kPm", 6), password.Admin); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("U+%04X: 8 visible plus 6 padding was accepted as an admin password: %v", r, err)
		}
		if _, err := password.Prepare(pad("x7Qz!kP", 3), password.User); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("U+%04X: 7 visible plus 3 padding was accepted as a user password: %v", r, err)
		}
	}
	// The same characters between visible ones, the way a Persian keyboard types the ZWNJ.
	for _, pw := range []string{"x7Qz\u200c!kPm\u200c\u200c", "\u200bx7Qz!kP\u200b\u200b\u200b"} {
		if _, err := password.Prepare(secret.New(pw), password.User); !errors.Is(err, password.ErrTooShort) {
			t.Errorf("%q: %v, want ErrTooShort", pw, err)
		}
	}
	// Ten visible code points still pass with and without a separator inside.
	for _, pw := range []string{"x7Qz!kPm9a", "x7Qz!\u200ckPm9a"} {
		if _, err := password.Prepare(secret.New(pw), password.User); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
	if got := password.CountedLength(secret.New("ab\u200c\u2060cd")); got != 4 {
		t.Errorf("CountedLength counted %d, want 4", got)
	}
}

// TestAPasswordIsTheSameWithOrWithoutTheHalfSpace is primitives-r18-3 (D64 zwnj-fields). The Persian
// keyboard types U+200C inside words and a person does not remember whether it was typed, so the hashed
// form drops it: a password set with it verifies without it and the other way round, at set (Hash,
// Prepare) and at verify (Verify, which normalises the same way), for the user and the admin kind. Only
// U+200C is dropped: another invisible code point stays in the text.
func TestAPasswordIsTheSameWithOrWithoutTheHalfSpace(t *testing.T) {
	ctx := context.Background()
	h := newHasher(t, fast, 1)
	with, without := "می\u200cخواهم-خانه-بزرگ", "میخواهم-خانه-بزرگ"
	for _, c := range []struct{ set, try string }{{with, without}, {without, with}, {with, with}} {
		hash, err := h.Hash(ctx, pw(c.set))
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := h.Verify(ctx, pw(c.try), hash); err != nil || !ok {
			t.Errorf("set %q, verify %q: %v %v", c.set, c.try, ok, err)
		}
	}
	if n, _ := password.Normalize(pw(with)); n.Reveal() != without {
		t.Errorf("Normalize kept the half-space: %q", n.Reveal())
	}
	// Prepare counts and keeps the same text, for both kinds.
	for _, k := range []password.Kind{password.User, password.Admin} {
		a, errA := password.Prepare(pw(with+"-1234567"), k)
		b, errB := password.Prepare(pw(without+"-1234567"), k)
		if errA != nil || errB != nil || a.Normalized().Reveal() != b.Normalized().Reveal() || a.Counted() != b.Counted() {
			t.Errorf("kind %v: %v %v", k, errA, errB)
		}
	}
	// A zero-width space is another character: it stays in the hashed text.
	if n, _ := password.Normalize(pw("a\u200bb")); n.Reveal() != "a\u200bb" {
		t.Errorf("another invisible character was dropped: %q", n.Reveal())
	}
	// The half-space alone is nothing: a password of half-spaces does not pass the minimum.
	if _, err := password.Prepare(pw(strings.Repeat("\u200c", 14)), password.Admin); err == nil {
		t.Error("a password of half-spaces was accepted")
	}
}
