package budget_test

import (
	"sync"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
)

// TestRefusalsAreCountedPerBucketAndLoggedAtPowersOfTwo is tenant-r18-6 (D64 net-bucket-numbers): the data the
// network bucket numbers are set from. A line is due at 1, 2, 4, 8, ..., so a flood of refusals writes at most
// 64 lines per bucket and the last line shows its size.
func TestRefusalsAreCountedPerBucketAndLoggedAtPowersOfTwo(t *testing.T) {
	r := budget.NewRefusals()
	login, ok := budget.FindScope("login_net")
	if !ok {
		t.Fatal("login_net is not registered")
	}
	otp, _ := budget.FindScope("otp_verify_net")
	var due []uint64
	for i := 0; i < 20; i++ {
		if n, d := r.Note(login); d {
			due = append(due, n)
		}
	}
	want := []uint64{1, 2, 4, 8, 16}
	if len(due) != len(want) {
		t.Fatalf("lines were due at %v, want %v", due, want)
	}
	for i := range want {
		if due[i] != want[i] {
			t.Fatalf("lines were due at %v, want %v", due, want)
		}
	}
	// A second bucket has its own count.
	if n, d := r.Note(otp); n != 1 || !d {
		t.Errorf("the first refusal of another bucket = %d, due %v", n, d)
	}
}

// TestRefusalsHoldNothingButTheRegistry: a name that is not in the registry is not counted, so the map cannot
// grow with what a caller makes up, and a nil counter does nothing.
func TestRefusalsHoldNothingButTheRegistry(t *testing.T) {
	r := budget.NewRefusals()
	if n, d := r.Note(budget.Bucket{Layer: budget.Throttle, Name: "not-a-bucket"}); n != 0 || d {
		t.Errorf("an unregistered bucket was counted: %d %v", n, d)
	}
	var none *budget.Refusals
	if n, d := none.Note(budget.All()[0]); n != 0 || d {
		t.Errorf("a nil counter counted: %d %v", n, d)
	}
	for _, b := range budget.All() {
		if !b.LogName().Valid() {
			t.Errorf("%s is a bucket and its log name is not valid", b.Name)
		}
		if !b.KeyKind().Valid() {
			t.Errorf("%s has the key kind %q, which is not a source of the registry", b.Name, b.KeyKind())
		}
	}
	if budget.BucketName("anything else").Valid() || budget.KeyKind("1.2.3.0").Valid() {
		t.Error("a value that is not in the registry is a valid log value")
	}
}

func TestRefusalsAreExactUnderConcurrency(t *testing.T) {
	r := budget.NewRefusals()
	b, _ := budget.FindScope("login_net")
	var wg sync.WaitGroup
	var mu sync.Mutex
	last := uint64(0)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 16; j++ {
				n, _ := r.Note(b)
				mu.Lock()
				if n > last {
					last = n
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if last != 1024 {
		t.Errorf("the highest count seen is %d, want 1024: a count was lost", last)
	}
}

// TestRefusalsAreKeptApartPerService is tenant-r18-19: the two services each register a bucket called
// session-lookup, and one counter that both fed must not add them. The test reads the pairs from the registry, so
// a name a later edit registers for both services is judged without an entry here.
func TestRefusalsAreKeptApartPerService(t *testing.T) {
	byName := map[string][]budget.Bucket{}
	for _, b := range budget.All() {
		byName[b.Name] = append(byName[b.Name], b)
	}
	pairs := 0
	for name, bs := range byName {
		if len(bs) < 2 {
			continue
		}
		pairs++
		r := budget.NewRefusals()
		for _, b := range bs {
			if n, _ := r.Note(b); n != 1 {
				t.Errorf("%s of service %s counted %d on its first refusal: it shares a count with another service", name, b.Service, n)
			}
		}
	}
	if pairs == 0 {
		t.Fatal("no bucket name is registered for both services: the check judged nothing")
	}
}

// TestCapRefusalsAreCountedLikeBuckets is tenant-r18-19: the OTP caps are not buckets of the registry and refuse
// too, so they have a closed name of their own and the same rule for the line.
func TestCapRefusalsAreCountedLikeBuckets(t *testing.T) {
	r := budget.NewRefusals()
	var due []uint64
	for i := 0; i < 9; i++ {
		if n, d := r.NoteCap(budget.CapOTPIssue); d {
			due = append(due, n)
		}
	}
	if len(due) != 4 || due[0] != 1 || due[3] != 8 {
		t.Errorf("lines were due at %v, want [1 2 4 8]", due)
	}
	if n, d := r.NoteCap("something else"); n != 0 || d {
		t.Errorf("a cap that is not in the closed set was counted: %d %v", n, d)
	}
	var none *budget.Refusals
	if n, d := none.NoteCap(budget.CapOTPIssue); n != 0 || d {
		t.Errorf("a nil counter counted: %d %v", n, d)
	}
}
