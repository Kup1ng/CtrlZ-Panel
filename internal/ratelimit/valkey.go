package ratelimit

import (
	"context"
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The scripts are files (lua/), embedded here, because the Valkey container loads the very same
// files when it starts (deploy/compose/valkey/maintain.sh): neither service user may run EVAL, so a
// script that is not already loaded cannot be sent by a client, and a compromised service cannot
// submit a Lua loop that holds the server BUSY for every tenant (round 13, admin-r13-5). The
// client runs them by SHA. Against a Valkey with no such ACL (a development server, a test) the
// EVAL fallback of script.run still loads them.
//
// take.lua is the whole token bucket in one atomic call, so two instances
// cannot both spend the last token. It reads the server's clock (TIME), which
// keeps instances with skewed clocks in agreement.
//
// KEYS are the slots, plus, when the service keeps an index (ValkeyConfig.IndexKey), the
// index as the last key: ARGV then holds fewer than two entries per key, which is how the
// script tells it from a slot. ARGV holds, per slot, its capacity and its refill period
// in milliseconds. Every slot is checked before any is written: a request
// refused by the hourly bucket must not have spent the minute bucket.
//
// State is a hash of the tokens left and the time of the last refill. It
// expires after twice the refill period, by which time the bucket is full
// again and the key can go.
//
//go:embed lua/take.lua lua/give.lua
var luaFiles embed.FS

// lua returns one embedded script. The file names are fixed and in the embed pattern, so a missing one
// is a build error, never a runtime one.
func lua(name string) string {
	b, err := luaFiles.ReadFile("lua/" + name)
	if err != nil {
		panic("ratelimit: embedded script missing: " + name)
	}
	return string(b)
}

// give.lua returns one token to each slot, up to the capacity.

// ValkeyConfig says where Valkey is.
type ValkeyConfig struct {
	Addr string
	// Username is the ACL user the service signs in as (CTRLZ_VALKEY_USER). Empty means the
	// default user, for a development stack. In Compose each service has its own user, limited to
	// the keys and commands of its own limiter, so a compromised api cannot empty the admin's
	// login buckets (round 6, admin-r6-7).
	Username string
	Password secret.String // empty for none
	// DialTimeout bounds one connection attempt (default 1 s).
	DialTimeout time.Duration
	// Log is where the client cache says a dial that panics or keeps failing (cachex.Config.Log is
	// required, round 16, tenant-r16-12). Nil means slog.Default(): never silent. The lines carry the
	// cache name, a count and a class, never an address or an error text.
	Log *slog.Logger
	// IndexKey, when set, is a sorted set the scripts keep of every bucket key they write, scored
	// by the time the key expires, and the only way ResetIndexed finds keys to delete. It is set for
	// the admin service so that `ctrlz-admin unlock` can clear the admin's buckets without SCAN: SCAN
	// is not bound by the key patterns of an ACL user, so a user that may scan lists every key of the
	// instance, and the api's keys name a tenant user id and the network it signs in from
	// (round 7, admin-r7-6). Expired members are trimmed by every write, so the set holds the live
	// keys and no more.
	IndexKey string
}

// valkeyRetryAfter is the pause after a failed dial. The Limiter has its own
// cooldown after a failed call, so this only matters to a caller that has none.
const valkeyRetryAfter = time.Second

// Valkey is the Backend over a Valkey server. The client is dialled on first
// use and again after a failed dial, never at construction: a Valkey that is
// down when the service starts must not stop it (spec 17.2), and password login
// works without it. After the first connection the client reconnects by itself.
//
// The client is a cachex.Loader (rule cache-loader). valkey.NewClient takes no
// context and blocks for the dial timeout, so dialling under a mutex made N
// concurrent requests against a blackholed address wait 1, 2, ... N seconds in
// series (round 2, tenant-r2-1), and a cancelled request still paid for its dial.
// The loader dials once at a time, outside any lock, shares the dial with every
// caller that arrives while it is in flight, and lets each caller leave when its
// own context ends, so an outage costs each caller at most its call timeout, in
// parallel, and the Limiter's cooldown then keeps later requests away.
type Valkey struct {
	cfg  ValkeyConfig
	take script
	give script

	client *cachex.Loader[valkey.Client]

	// newClient is valkey.NewClient; a test swaps it for a dial that hangs, which
	// a loopback address cannot reproduce on every OS.
	newClient func(valkey.ClientOption) (valkey.Client, error)
}

// NewValkey returns a Backend. It opens no connection.
func NewValkey(cfg ValkeyConfig) *Valkey {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = time.Second
	}
	v := &Valkey{cfg: cfg, take: newScript(lua("take.lua")), give: newScript(lua("give.lua")), newClient: valkey.NewClient}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	v.client = cachex.New(cachex.Config[valkey.Client]{
		Load:       v.dial,
		Log:        log,
		RetryAfter: valkeyRetryAfter,
		// The dial does not take the context; this only frees the flight bookkeeping
		// of a driver that one day does.
		LoadTimeout: 2 * cfg.DialTimeout,
		// Close drops the client, and a dial that outlives the Close must not leave a
		// connection behind: the loader hands both to Release.
		Release: func(c valkey.Client) { c.Close() },
		Name:    cachex.NameValkey,
	})
	return v
}

// Errors are fixed strings: a driver error names the address it dialled and the
// failure of the AUTH command.
var (
	errDial    = errors.New("ratelimit: cannot connect to valkey")
	errBackend = errors.New("ratelimit: valkey call failed")
	errNoIndex = errors.New("ratelimit: this service keeps no index of its keys")
)

// conn returns the client, dialling it if there is none. Whatever went wrong is
// errDial: the loader's error is the dial's, and a driver error is never kept.
func (v *Valkey) conn(ctx context.Context) (valkey.Client, error) {
	c, err := v.client.Get(ctx)
	if err != nil {
		return nil, errDial
	}
	return c, nil
}

// dial makes the one shared connection attempt.
func (v *Valkey) dial(context.Context) (valkey.Client, error) {
	c, err := v.newClient(valkey.ClientOption{
		InitAddress:  []string{v.cfg.Addr},
		Username:     v.cfg.Username,
		Password:     v.cfg.Password.Reveal(),
		DisableCache: true,
		// The dial timeout bounds the background attempt, not any request.
		Dialer:           net.Dialer{Timeout: v.cfg.DialTimeout, KeepAlive: 30 * time.Second},
		ConnWriteTimeout: 2 * time.Second,
	})
	if err != nil {
		return nil, errDial
	}
	return c, nil
}

// Close releases the connection. The Valkey can be used again afterwards: the
// next call dials a new client.
func (v *Valkey) Close() { v.client.Reset() }

func (v *Valkey) args(slots []slot) (keys, argv []string) {
	keys = make([]string, len(slots), len(slots)+1)
	argv = make([]string, 0, 2*len(slots))
	for i, s := range slots {
		keys[i] = s.key
		argv = append(argv, strconv.Itoa(s.max), strconv.FormatInt(s.per.Milliseconds(), 10))
	}
	if v.cfg.IndexKey != "" {
		keys = append(keys, v.cfg.IndexKey)
	}
	return keys, argv
}

// Take implements Backend.
func (v *Valkey) Take(ctx context.Context, slots []slot) (bool, time.Duration, error) {
	c, err := v.conn(ctx)
	if err != nil {
		return false, 0, err
	}
	keys, argv := v.args(slots)
	arr, err := v.take.run(ctx, c, keys, argv).ToArray()
	if err != nil || len(arr) != 2 {
		return false, 0, errBackend
	}
	allowed, err1 := arr[0].AsInt64()
	waitMs, err2 := arr[1].AsInt64()
	if err1 != nil || err2 != nil {
		return false, 0, errBackend
	}
	return allowed == 1, time.Duration(waitMs) * time.Millisecond, nil
}

// Give implements Backend.
func (v *Valkey) Give(ctx context.Context, slots []slot) error {
	c, err := v.conn(ctx)
	if err != nil {
		return err
	}
	keys, argv := v.args(slots)
	if err := v.give.run(ctx, c, keys, argv).Error(); err != nil {
		return errBackend
	}
	return nil
}

// script is a Lua script run by SHA, with the text sent only when the server
// does not know it yet. valkey-go has its own wrapper for this, but its method is
// called Exec, and the module's SQL lint refuses every call named Exec that is
// not a constant SQL string; two lines of EVALSHA are cheaper than a lint
// exception.
type script struct {
	src string
	sha string
}

func newScript(src string) script {
	sum := sha1.Sum([]byte(src)) //nolint:gosec // the digest is the name Valkey gives a script, not a security use
	return script{src: src, sha: hex.EncodeToString(sum[:])}
}

// run sends the script by SHA. A server that does not know it answers NOSCRIPT, and the text is sent
// then. Production refuses EVAL to both service users (admin-r13-5), so there the second call fails
// with NOPERM and the caller gets errBackend, which every limiter handles as an outage: the
// maintenance loop of the Valkey container loads the scripts again within seconds of a restart.
func (s script) run(ctx context.Context, c valkey.Client, keys, argv []string) valkey.ValkeyResult {
	res := c.Do(ctx, c.B().Evalsha().Sha1(s.sha).Numkeys(int64(len(keys))).Key(keys...).Arg(argv...).Build())
	if err := res.Error(); err != nil {
		if verr, ok := valkey.IsValkeyErr(err); ok && verr.IsNoScript() {
			return c.Do(ctx, c.B().Eval().Script(s.src).Numkeys(int64(len(keys))).Key(keys...).Arg(argv...).Build())
		}
	}
	return res
}

// resetBatch is how many indexed keys ResetIndexed deletes per round trip.
const resetBatch = 500

// ResetIndexed deletes every bucket key the service has indexed, for `ctrlz-admin unlock`: the
// admin's login speed bumps live in Valkey, `unlock` used to clear only the Postgres scopes, and the
// owner locked out by a spent admin-login bucket had no way back from the console (round 6,
// admin-r6-7). It reads the index and not the keyspace: round 6 gave the admin user SCAN for this,
// and SCAN lists every key of the instance whatever the user's key patterns say, among them the
// api's, whose names carry a tenant user id and the network it signs in from (round 7, admin-r7-6).
// It needs ValkeyConfig.IndexKey. It works in batches, so a large index does not block Valkey
// behind one command, and removes a key from the index only after the key is deleted, so a failure
// in between leaves it to be found by the next run. It returns the number of keys removed.
func (v *Valkey) ResetIndexed(ctx context.Context) (int, error) {
	if v.cfg.IndexKey == "" {
		return 0, errNoIndex
	}
	c, err := v.conn(ctx)
	if err != nil {
		return 0, err
	}
	removed := 0
	for {
		members, err := c.Do(ctx, c.B().Zrange().Key(v.cfg.IndexKey).Min("0").Max(strconv.Itoa(resetBatch-1)).Build()).AsStrSlice()
		if err != nil {
			return removed, errBackend
		}
		if len(members) == 0 {
			return removed, nil
		}
		if err := c.Do(ctx, c.B().Unlink().Key(members...).Build()).Error(); err != nil {
			return removed, errBackend
		}
		if err := c.Do(ctx, c.B().Zrem().Key(v.cfg.IndexKey).Member(members...).Build()).Error(); err != nil {
			return removed, errBackend
		}
		removed += len(members)
	}
}
