package budget

import (
	"sync"
)

// BucketName is the name of a registered bucket as a log line may carry it. The names are in the registry, which
// is code, so the set is closed: Valid asks the registry, and a name that is not in it is logged as "invalid".
type BucketName string

// Valid reports whether n names a bucket of the registry (a rate class or a throttle scope, of either service).
func (n BucketName) Valid() bool {
	for _, b := range registryIndex().all {
		if b.Name == string(n) {
			return true
		}
	}
	return false
}

// LogName is the bucket's name as a BucketName.
func (b Bucket) LogName() BucketName { return BucketName(b.Name) }

// KeyKind is what a bucket's key is made from, as a log line may carry it: the source of the registry
// ("subject", "proof", "network"), and for a bucket that holds an address, "network". It never carries a key, an
// address or a phone number: it says only which kind of thing the refused requests were counted on.
type KeyKind string

// Valid reports whether k is one of the sources of the registry.
func (k KeyKind) Valid() bool { return k == "subject" || k == "proof" || k == "network" }

// KeyKind is the kind of key the bucket counts on.
func (b Bucket) KeyKind() KeyKind { return KeyKind(b.Source.String()) }

// refusalKey is the unit of the count: the service as well as the layer and the name, because the two services
// each have a bucket called session-lookup and a counter shared by both would add them (tenant-r18-19).
type refusalKey struct {
	service Service
	layer   Layer
	name    string
}

// CapName is a daily cap of the SMS counters, which is not a bucket of the registry (it lives in sms_counters and
// is checked inside auth_otp_issue, which says only that one of them refused). The set is closed and Valid asks
// it, so a cap is logged as a closed value (tenant-r18-19; D64 net-bucket-numbers names "the OTP caps" among the
// numbers to be set from data).
type CapName string

// CapOTPIssue is a code request that auth_otp_issue turned away: the resend cooldown, or one of the daily caps of
// spec 5.1 (the cap on a phone, the cap on a phone and network, the global soft and hard caps). The function says
// only "not allowed", so the data is the count of all of them together.
const CapOTPIssue CapName = "otp_issue"

// Valid reports whether c is a cap of the closed set.
func (c CapName) Valid() bool { return c == CapOTPIssue }

// Refusals counts the refusals of every bucket since the process started (tenant-r18-6; D64 net-bucket-numbers,
// whose deferral to the P4b gate holds only if the data exists: every per-/24 and per-/48 number is a guess until
// real carrier traffic says how many subscribers share a block). The count is per bucket and carries nothing
// else, so it holds no address, no phone number and no key, and its size is the size of the registry (and of the
// closed set of caps).
//
// It is read from the log, and the log line is not one per refusal. A flood of refusals is exactly the case
// where the line is wanted, and a line per refusal would then fill the disk, so Note says a line is due only
// when the count of its bucket reaches a power of two (1, 2, 4, 8, ...): the log holds at most 64 lines per
// bucket for the life of the process, each carrying the count so far, and a run that stops shows its size by
// the last line. There is no timer and no clock, so a restart that steps the clock back changes nothing.
//
// State: in memory, one per process, which is what an operator reading the lines of each process wants (a
// rolling restart or a second process starts from zero and says so by its own lines). When nothing counts
// (a nil *Refusals) nothing is lost but the line, so it fails open: a refusal is never made or undone by it.
type Refusals struct {
	mu   sync.Mutex
	n    map[refusalKey]uint64
	caps map[CapName]uint64
}

// NewRefusals returns an empty counter.
func NewRefusals() *Refusals {
	return &Refusals{n: map[refusalKey]uint64{}, caps: map[CapName]uint64{}}
}

// Note counts one refusal by the bucket and returns the count so far and whether a log line is due. A bucket that
// is not in the registry is not counted (its name could be anything, and the map must stay the size of the
// registry), and neither is a call on a nil counter.
func (r *Refusals) Note(b Bucket) (count uint64, due bool) {
	if r == nil || !BucketName(b.Name).Valid() {
		return 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := refusalKey{b.Service, b.Layer, b.Name}
	r.n[k]++
	count = r.n[k]
	return count, count&(count-1) == 0
}

// NoteCap counts one refusal by a daily cap, with the same rule for the line as Note. A cap that is not in the
// closed set is not counted.
func (r *Refusals) NoteCap(c CapName) (count uint64, due bool) {
	if r == nil || !c.Valid() {
		return 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.caps[c]++
	count = r.caps[c]
	return count, powerOfTwo(count)
}

// powerOfTwo says a count is 1, 2, 4, 8, ...: the points at which a line is due (NoteCap).
func powerOfTwo(n uint64) bool { return n&(n-1) == 0 }
