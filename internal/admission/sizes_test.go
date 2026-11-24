package admission_test

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
)

// apiBase is what the api holds with nothing in flight (6.5 property 9, measured in B3 round 5).
const apiBase = 30 << 20

func envFile(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

func mib(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(strings.TrimSuffix(s, "MiB"), 10, 64)
	if err != nil || !strings.HasSuffix(s, "MiB") {
		t.Fatalf("%q is not a size in MiB", s)
	}
	return n << 20
}

// TestTheHeavyBudgetFitsTheContainer: the api holds, at most, what it holds with nothing in flight, its Argon2 runs, the
// work pool and the places of its clients, and that sum is under GOMEMLIMIT of each compose profile (6.5 property 9). The
// pools before this model were 144 MiB and left out Argon2, which made 266 MiB in a container of 256.
func TestTheHeavyBudgetFitsTheContainer(t *testing.T) {
	hash := int64(password.DefaultParams().MemoryKiB) << 10
	for _, profile := range []string{"small", "standard"} {
		env := envFile(t, "../../deploy/compose/profiles/"+profile+".env")
		slots, err := strconv.ParseInt(env["CTRLZ_API_ARGON2_CONCURRENCY"], 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", profile, err)
		}
		limit := mib(t, env["GOMEMLIMIT_API"])
		places := int64(admission.Places) * admission.PlaceBytes
		sum := apiBase + slots*hash + admission.Pool + places
		t.Logf("%s: base %d + argon2 %d x %d + work %d + places %d = %d MiB of %d", profile, apiBase>>20, slots, hash>>20, admission.Pool>>20, places>>20, sum>>20, limit>>20)
		if sum > limit {
			t.Errorf("%s: the api may hold %d MiB with its heavy operations at their bounds, GOMEMLIMIT is %d MiB", profile, sum>>20, limit>>20)
		}
	}
	// The three weights fit the pool, and the biggest one fills it, so an Import of 6 MiB can always be admitted alone.
	for _, w := range []int64{admission.WeightLarge, admission.WeightExport, admission.WeightSmall} {
		if w > admission.Pool {
			t.Errorf("a weight of %d MiB is above the pool of %d MiB", w>>20, admission.Pool>>20)
		}
	}
	// 128 files of at most AnswerBytes are 2 GiB of the volume, and the spilled answers of ordinary operations are 128 shares
	// of AnswerTenant on top of them: 2.5 GiB, which is what the spec says.
	if disk := int64(admission.Places)*admission.AnswerBytes + admission.AnswerPool; disk != 2<<30+512<<20 {
		t.Errorf("the spool is %d bytes at the most, the spec says 2.5 GiB", disk)
	}
	if admission.AnswerPool != int64(admission.Places)*admission.AnswerTenant {
		t.Errorf("the pool of spilled answers is not one share for each place")
	}
}
