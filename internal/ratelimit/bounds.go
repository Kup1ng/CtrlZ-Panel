package ratelimit

// The bounds of one limiter call, as the Lua scripts enforce them (admin-r14-4). Both service users may
// EVALSHA the two scripts and their digests are public (the files are in the repository), so the
// scripts refuse any call the Go limiter would never send: a caller with a service credential cannot
// make them loop over thousands of keys, or give a key a lifetime of years. The numbers are written in
// lua/take.lua and lua/give.lua as constants; TestScriptBoundsAreThoseOfTheGoLimiter holds the two
// sides to each other and to every class of the budget registry, so a class that grew past them fails
// a test and not a request.
const (
	// scriptMaxSlots is the number of buckets one call may name, the index key not counted. The widest
	// class today names six (a proof, its network and its wide network, two limits each).
	scriptMaxSlots = 8
	// scriptMaxCap is the largest capacity of a bucket. The widest today is 300 per minute at the
	// proof factor times the wide factor, 30 000.
	scriptMaxCap = 100000
	// scriptMaxPerMs is the longest refill period: a week.
	scriptMaxPerMs = 7 * 24 * 60 * 60 * 1000
)
