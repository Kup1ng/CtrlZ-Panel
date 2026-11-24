package lint_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// Rule 29 says nothing a service credential may do to Valkey can keep the server busy OR FULL. The busy
// half had code and tests from round 13 and 14; this file is the full half (round 15, admin-r15-1 and
// admin-r15-4). The two service users hold HSET and PEXPIRE because the limiter's scripts run them, and
// Valkey checks the commands of a script against the caller's ACL, so a holder of the credential can send
// the same commands outside any script, with values of any size and keys of any lifetime. A key pattern
// bounds WHICH keys, not how much memory they use, and with noeviction and an append-only file the junk
// filled the instance, survived a restart and could not be removed by the service that wrote it (it holds
// no UNLINK) or by `ctrlz-admin unlock` (it reaches only the keys the admin's index lists). The fix is the
// container's: deploy/compose/valkey/sweep.lua, run by maintain.sh as the maintenance user, deletes every
// key a limiter script could not have written and keeps each service inside its own key budget.

// valkeyFill is what these tests share: the real start file of each zone's server with a small maxmemory, a
// client for each service user and the real limiter of each, which is the "victim" that has to keep writing.
// Since round 16 the two zones are two servers, so one zone's flood is a different process from the other's
// victim, and a test can say both "the other zone never noticed" and "this zone recovered".
type valkeyFill struct {
	zones map[string]*valkeyZone
}

// valkeyZone is one running zone server and its client.
type valkeyZone struct {
	name   string // the container
	addr   string
	client valkey.Client
	lim    *ratelimit.Limiter
}

func startValkeyFill(t *testing.T, maxmemory string, extra ...string) *valkeyFill {
	t.Helper()
	f := &valkeyFill{zones: map[string]*valkeyZone{}}
	for _, zone := range valkeyZones {
		pw := valkeyPasswords[zone]
		name, _, hostAddr := startValkeyACL(t, zone, pw, append([]string{"-e", "VK_MAXMEMORY=" + maxmemory}, extra...)...)
		z := &valkeyZone{name: name, addr: hostAddr()}
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{z.addr}, Username: zone, Password: pw, DisableCache: true})
		if err != nil {
			t.Fatalf("sign in as %q: %v", zone, err)
		}
		t.Cleanup(c.Close)
		z.client = c
		if zone == "api" {
			z.lim = ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, Backend: ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: z.addr, Username: "api", Password: secret.New(pw)})})
		} else {
			z.lim = ratelimit.New(ratelimit.Config{Service: ratelimit.Admin, Backend: ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: z.addr, Username: "admin", Password: secret.New(pw), IndexKey: ratelimit.IndexKey(ratelimit.Admin)})})
		}
		f.zones[zone] = z
	}
	return f
}

func (f *valkeyFill) client(service string) valkey.Client { return f.zones[service].client }

// limiterWorks asks the service's own limiter for one token. It is the victim's view: the write a
// tenant's SMS login or the owner's console login needs.
func (f *valkeyFill) limiterWorks(ctx context.Context, service, subject string) error {
	if service == "api" {
		c, _ := ratelimit.Lookup(ratelimit.Tenant, "sensitive")
		_, err := f.zones["api"].lim.Allow(ctx, c, ratelimit.Subject{Session: subject})
		return err
	}
	c, _ := ratelimit.Lookup(ratelimit.Admin, "admin-login")
	_, err := f.zones["admin"].lim.Allow(ctx, c, ratelimit.Subject{Network: subject})
	return err
}

// waitLimiter polls until the limiter of a service writes again, and fails with what the server said.
func (f *valkeyFill) waitLimiter(t *testing.T, service, subject string, within time.Duration) {
	t.Helper()
	var last error
	if testwait.Holds(within, 500*time.Millisecond, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		last = f.limiterWorks(ctx, service, subject)
		return last == nil
	}) {
		return
	}
	t.Fatalf("the %s limiter still cannot write %v after the flood (%v); log:\n%s", service, within, last, logsOf(f.zones[service].name))
}

// fillUntilFull writes junk as a service user, large values first and then smaller ones, until the server
// answers OOM, the way the reviewer reproduced it, and returns the names of the keys it wrote.
//
// The container's sweep runs a pass at least every MAINT_INTERVAL (2 s) and deletes this very junk, so the fill has to
// outrun it. Written one command at a time over Docker Desktop's port forward on a loaded machine, the
// 100 KB values went in at about 3 MB/s, the sweep removed them as fast as they came and the server never
// filled (the first full CI run of round 15 failed on exactly that: 1600 writes, no OOM). So the writes are
// pipelined in batches of about 4 MB, and a pass the sweep won is repeated: the key names repeat, so a swept
// key is simply written again. What the test must never do is pass without having seen the server full.
func fillUntilFull(t *testing.T, c valkey.Client, prefix string) []string {
	t.Helper()
	ctx := context.Background()
	var keys []string
	seen := map[string]bool{}
	full := false
	for pass := 0; pass < 6 && !full; pass++ {
		for _, size := range []int{100000, 10000, 1000, 100} {
			val := strings.Repeat("x", size)
			per := 4_000_000 / size
			oom := false
			for i := 0; i < 400 && !oom; i += per {
				n := min(per, 400-i)
				names := make([]string, n)
				cmds := make(valkey.Commands, n)
				for j := range cmds {
					names[j] = fmt.Sprintf("%sjunk:%d:%d", prefix, size, i+j)
					cmds[j] = c.B().Hset().Key(names[j]).FieldValue().FieldValue("f", val).Build()
				}
				for j, r := range c.DoMulti(ctx, cmds...) {
					if err := r.Error(); err != nil {
						if !strings.Contains(err.Error(), "OOM") {
							t.Fatalf("HSET as a service user: %v", err)
						}
						oom = true
						if size == 100000 {
							full = true
						}
						continue
					}
					if !seen[names[j]] {
						seen[names[j]] = true
						keys = append(keys, names[j])
					}
				}
			}
		}
	}
	if !full {
		t.Fatalf("%d writes in 6 passes did not fill the server: the test proves nothing", len(keys))
	}
	return keys
}

// hmgetNil reports whether every key in the list is gone (HMGET of a missing key is nil per field).
func missing(ctx context.Context, c valkey.Client, keys []string) (gone, left int) {
	cmds := make(valkey.Commands, 0, len(keys))
	for _, k := range keys {
		cmds = append(cmds, c.B().Hmget().Key(k).Field("f").Build())
	}
	for _, r := range c.DoMulti(ctx, cmds...) {
		arr, err := r.ToArray()
		if err != nil || len(arr) != 1 || arr[0].IsNil() {
			gone++
		} else {
			left++
		}
	}
	return gone, left
}

// TestValkeyServiceCredentialCannotFillTheServer is the reproduction of admin-r15-1 and admin-r15-4, run as
// each service against its own server: fill a 16 MB instance with HSET of large values and no
// lifetime, and require that the other zone never noticed (it is another server), and that the junk is gone and
// the attacked zone writes again within seconds. A second pass
// gives every junk key a lifetime of years (a direct PEXPIRE takes any), which the limiter never does.
func TestValkeyServiceCredentialCannotFillTheServer(t *testing.T) {
	// The sweep runs every MAINT_INTERVAL. At the default 2 s it races the fill on a slow host and can win it for ever
	// (admin-r16-10): the fill needs the server full, and the host decides how fast 16 MB goes in. So the container
	// sweeps once at start and then every 30 s, the fill has that long to land, and the recovery is waited for
	// over a few intervals. The loop is the production one, only slower.
	f := startValkeyFill(t, "16mb", "-e", "MAINT_INTERVAL=30")
	for _, attacker := range []string{"api", "admin"} {
		victim := map[string]string{"api": "admin", "admin": "api"}[attacker]
		t.Run(attacker+" fills", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 420*time.Second)
			defer cancel()
			c := f.client(attacker)
			prefix := "ctrlz:rl:" + attacker + ":"
			keys := fillUntilFull(t, c, prefix)
			// The other zone is another server with its own memory and its own client slots: whatever the attacker
			// did to its own, the victim writes at once (admin-r16-7, -13).
			f.waitLimiter(t, victim, "after-"+attacker, 3*time.Second)
			f.waitLimiter(t, attacker, "after-self", 100*time.Second)
			// The limiter writes as soon as there is room; the junk has to be gone altogether, because
			// what stays is the next flood's head start (and, with no lifetime, outlives every restart).
			left := 0
			if !testwait.Holds(100*time.Second, 500*time.Millisecond, func() bool {
				_, left = missing(ctx, c, keys)
				return left == 0
			}) {
				t.Fatalf("%d of %d junk keys are still there after 100 s", left, len(keys))
			}
			// A lifetime the limiter would never give: tiny, but kept for years, and tiny with none.
			c.Do(ctx, c.B().Hset().Key(prefix+"forever").FieldValue().FieldValue("f", "1").Build())
			c.Do(ctx, c.B().Pexpire().Key(prefix+"forever").Milliseconds(99999999999).Build())
			c.Do(ctx, c.B().Hset().Key(prefix+"nolife").FieldValue().FieldValue("f", "1").Build())
			waitLog(t, f.zones[attacker].name, "keyspace sweep deleted", 45*time.Second)
			testwait.UntilEvery(t, 100*time.Second, 500*time.Millisecond, "the sweep to delete the keys with no lifetime and with a lifetime of years", func() bool {
				_, left := missing(ctx, c, []string{prefix + "forever", prefix + "nolife"})
				return left == 0
			})
		})
	}
}

// TestValkeySweepKeepsTheKeysTheLimiterWrote is the other side: the sweep must not cost the services what the
// limiter writes. A bucket that was spent before a sweep is the same bucket after it (the key is there, with
// the same `at` and `tokens`: a key the sweep deleted would start full), and the admin index still lists its
// keys. The check reads the key and not the number of tokens the limiter lets through later, because that
// number moves with the clock (admin-login refills one token every 12 s) and a host that is slow between
// the spend and the read would fail it for nothing (admin-r16-10).
func TestValkeySweepKeepsTheKeysTheLimiterWrote(t *testing.T) {
	f := startValkeyFill(t, "64mb")
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if err := f.limiterWorks(ctx, "admin", "203.0.113.0"); err != nil {
			t.Fatal(err)
		}
		if err := f.limiterWorks(ctx, "api", "s-keep"); err != nil {
			t.Fatal(err)
		}
	}
	// The admin's buckets are listed by its own index, which is also what the limiter and `unlock` use.
	snapshot := func() map[string]string {
		c := f.client("admin")
		idx, err := c.Do(ctx, c.B().Zrange().Key(ratelimit.IndexKey(ratelimit.Admin)).Min("0").Max("-1").Build()).AsStrSlice()
		if err != nil || len(idx) == 0 {
			t.Fatalf("the admin index holds %d entries (%v): the sweep removed it or it was never written", len(idx), err)
		}
		out := map[string]string{}
		for _, k := range idx {
			arr, err := c.Do(ctx, c.B().Hmget().Key(k).Field("tokens", "at").Build()).ToArray()
			if err != nil || len(arr) != 2 || arr[0].IsNil() {
				t.Fatalf("key %q has no bucket (%v)", k, err)
			}
			tok, _ := arr[0].ToString()
			at, _ := arr[1].ToString()
			out[k] = tok + "/" + at
		}
		return out
	}
	before := snapshot()
	// Junk that makes the sweep log a deletion, so the test knows a sweep ran after the spend.
	f.client("api").Do(ctx, f.client("api").B().Hset().Key("ctrlz:rl:api:marker").FieldValue().FieldValue("f", "1").Build())
	f.client("admin").Do(ctx, f.client("admin").B().Hset().Key("ctrlz:rl:admin:marker").FieldValue().FieldValue("f", "1").Build())
	waitLog(t, f.zones["api"].name, "keyspace sweep deleted", 45*time.Second)
	waitLog(t, f.zones["admin"].name, "keyspace sweep deleted", 45*time.Second)
	after := snapshot()
	if len(before) == 0 {
		t.Fatal("the admin limiter wrote no bucket the test could read")
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("the bucket %q was %s before the sweep and %q after: the sweep touched a key the limiter wrote", k, v, after[k])
		}
	}
	if len(after) != len(before) {
		t.Errorf("the admin had %d buckets before the sweep and %d after", len(before), len(after))
	}
}

// luaConst reads `local NAME = <integer>` from a file of deploy/compose/valkey, so the test and the script
// cannot disagree about a bound.
func luaConst(t *testing.T, file, name string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", file))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		var v int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "local "+name+" = %d", &v); err == nil {
			return v
		}
	}
	t.Fatalf("%s has no `local %s = <integer>`", file, name)
	return 0
}

// smallestMaxmemory is the least VALKEY_MAXMEMORY any profile sets, in bytes.
func smallestMaxmemory(t *testing.T) int {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "deploy", "compose", "profiles", "*.env"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no profiles: %v", err)
	}
	least := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			var mb int
			if _, err := fmt.Sscanf(strings.TrimSpace(line), "VALKEY_MAXMEMORY=%dmb", &mb); err == nil {
				if v := mb << 20; least == 0 || v < least {
					least = v
				}
			}
		}
	}
	if least == 0 {
		t.Fatal("no profile sets VALKEY_MAXMEMORY")
	}
	return least
}

// TestValkeyRefusesMoreConnectionsThanItsLimit holds the connection half of the rule: maxclients is set,
// and the server answers a client past it with an error instead of keeping it. The sockets are plain TCP
// and never authenticate: that is all an attacker on the backend network needs to hold a slot.
func TestValkeyRefusesMoreConnectionsThanItsLimit(t *testing.T) {
	conf, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "valkey.conf"))
	if err != nil {
		t.Fatal(err)
	}
	var maxclients int
	var timeout int
	for _, line := range strings.Split(string(conf), "\n") {
		fmt.Sscanf(strings.TrimSpace(line), "maxclients %d", &maxclients)
		fmt.Sscanf(strings.TrimSpace(line), "timeout %d", &timeout)
	}
	if maxclients <= 0 || maxclients > 1024 {
		t.Fatalf("valkey.conf maxclients is %d, want a limit of at most 1024", maxclients)
	}
	if timeout < 30 || timeout > 600 {
		t.Fatalf("valkey.conf timeout is %d, want a close of idle clients between 30 s and 10 min", timeout)
	}
	f := startValkeyFill(t, "64mb")
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	refused := false
	for i := 0; i < maxclients+50 && !refused; i++ {
		c, err := net.DialTimeout("tcp", f.zones["api"].addr, 3*time.Second)
		if err != nil {
			refused = true
			break
		}
		conns = append(conns, c)
		// A refused client is told so and closed; one that was accepted says nothing until it asks.
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		buf := make([]byte, 128)
		if n, _ := c.Read(buf); n > 0 && strings.Contains(string(buf[:n]), "max number of clients") {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("%d idle connections were all accepted: maxclients is not in force", len(conns))
	}
}

// TestLimiterSurvivesTheServerClosingItsIdleConnection backs the `timeout` of valkey.conf: the client
// redials a connection the server closed for idleness, so closing idle clients costs the limiter nothing.
func TestLimiterSurvivesTheServerClosingItsIdleConnection(t *testing.T) {
	name, addr := maintainedValkeyWith(t, "", false, "--timeout 2")
	waitHealthy(t, name, maintMarker)
	_ = name
	l := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, Backend: ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: addr, Username: "loop", Password: secret.New("x")})})
	c, _ := ratelimit.Lookup(ratelimit.Tenant, "sensitive")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for round := 0; round < 3; round++ {
		if _, err := l.Allow(ctx, c, ratelimit.Subject{Session: "idle"}); err != nil {
			t.Fatalf("round %d: the limiter failed after the server closed its idle connection: %v", round, err)
		}
		// Wait for the server to have closed the limiter's idle connection (its `timeout 2`), which is the
		// condition the test is about, and not for a number of seconds that stands for it: the clients the
		// server lists for the user `loop` are this probe alone.
		testwait.UntilEvery(t, 30*time.Second, 500*time.Millisecond, "the server to close the limiter's idle connection", func() bool {
			out, err := deploy.Docker(ctx, "exec", name, "valkey-cli", "--no-auth-warning", "--user", "loop", "--pass", "x", "client", "list").CombinedOutput()
			return err == nil && strings.Count(string(out), "user=loop") == 1
		})
	}
}

// maintScanCount counts the keys that match a pattern, signed in as the container's maintenance user, whose
// password the start line wrote to the ACL file in the tmpfs. The test reads it the way an operator on the
// host could; the services cannot (they hold no SCAN).
func maintScanCount(t *testing.T, name, pattern string) int {
	t.Helper()
	out, err := deploy.Docker(context.Background(), "exec", name, "sh", "-c",
		`pw=$(sed -n 's/^user maint on >\([^ ]*\) .*/\1/p' /tmp/users.acl); REDISCLI_AUTH=$pw valkey-cli --user maint --no-auth-warning --scan --count 1000 --pattern '`+pattern+`' | wc -l`).CombinedOutput()
	if err != nil {
		t.Fatalf("scan as maint: %v\n%.300s", err, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("scan as maint answered %q", out)
	}
	return n
}

// floodKeys writes n keys that look exactly like the limiter's (a two field hash with a lifetime inside the
// bound) into a service's zone as that service, with `valkey-cli --pipe` from inside the container, and fails the
// test when any of them is refused (OOM included).
func floodKeys(t *testing.T, f *valkeyFill, service string, n int) {
	t.Helper()
	// RESP by hand: *argc, then $len and the argument for each. The lifetime is 30 minutes (1800000 ms),
	// inside the sweep's bound and long enough for the test even on a slow host: a container that a killed
	// test leaves behind then has a keyspace that expires, and its sweep goes idle by itself instead of
	// walking 50,000 keys for 11 days.
	prog := fmt.Sprintf(`BEGIN{for(i=0;i<%d;i++){k=sprintf("ctrlz:rl:%s:flood:%%d",i);`+
		`printf "*6\r\n$4\r\nHSET\r\n$%%d\r\n%%s\r\n$6\r\ntokens\r\n$1\r\n1\r\n$2\r\nat\r\n$1\r\n1\r\n",length(k),k;`+
		`printf "*3\r\n$7\r\nPEXPIRE\r\n$%%d\r\n%%s\r\n$7\r\n1800000\r\n",length(k),k}}`, n, service)
	out, err := deploy.Docker(context.Background(), "exec", "-e", "REDISCLI_AUTH="+valkeyPasswords[service], f.zones[service].name, "sh", "-c",
		"awk '"+prog+"' | valkey-cli --user "+service+" --no-auth-warning --pipe --pipe-timeout 1").CombinedOutput()
	// --pipe ends with an ECHO that the service users do not hold (and say so, once): the replies
	// of the flood itself are what is counted, and an OOM among them fails the test.
	var replies int
	if i := strings.LastIndex(string(out), "replies: "); i >= 0 {
		_, _ = fmt.Sscanf(string(out)[i:], "replies: %d", &replies)
	}
	if strings.Contains(string(out), "OOM") || replies < 2*n {
		t.Fatalf("%s: the flood was refused or did not run (%v, %d replies of %d): %.300s", service, err, replies, 2*n, out)
	}
}

// maintMemory reads used_memory and maxmemory of a zone's server, signed in as the container's maintenance user
// (which holds INFO for the sweep's pressure flag).
func maintMemory(t *testing.T, name string) (used, limit int) {
	t.Helper()
	out, err := deploy.Docker(context.Background(), "exec", name, "sh", "-c",
		`pw=$(sed -n 's/^user maint on >\([^ ]*\) .*/\1/p' /tmp/users.acl); REDISCLI_AUTH=$pw valkey-cli --user maint --no-auth-warning info memory`).CombinedOutput()
	if err != nil {
		t.Fatalf("info memory as maint: %v\n%.300s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		fmt.Sscanf(line, "used_memory:%d", &used)
		fmt.Sscanf(line, "maxmemory:%d", &limit)
	}
	if used == 0 || limit == 0 {
		t.Fatalf("info memory answered no used_memory or maxmemory: %.300s", out)
	}
	return used, limit
}

// TestValkeySweepCutsAFloodThatFillsTheInstanceWithoutPausing: a credential holder that fills the instance makes
// every limiter write answer OOM, so the sweep must not pace itself then (round 1, sweep-r1-correctness-1). The
// zone has a small maxmemory and the flood takes it most of the way to it, far past half and past the budget of
// 40,000 keys. The pressure flag is over half of maxmemory, so what the sweep owes is to bring the instance back
// UNDER half (the limiter then writes again, and what is left above the budget is cut at the paced speed); the loop
// must say it ran without pauses, and the instance must be under half within the time unpaced batches of 200
// keys need on this host. Paced, getting there takes the pass that scans the 40,000 keys it keeps and then deletes
// at a fifth of the server's time, about three times as long.
func TestValkeySweepCutsAFloodThatFillsTheInstanceWithoutPausing(t *testing.T) {
	// The sweep must not trim the zone while the flood is still coming in: on a fast host it keeps pace with it and the
	// instance never passes half. So the loop sits idle for a minute after its first pass, and the flood, which is written
	// in a few seconds, is what the next pass finds.
	const n = 90000
	f := startValkeyFill(t, "16mb", "-e", "MAINT_INTERVAL=60")
	cost, err := hostCallCost()
	if err != nil {
		t.Fatalf("measuring the host's redis.call cost: %v", err)
	}
	// Per batch of 200 keys: seven calls a deleted key at the host's cost, and 70 ms for the start of valkey-cli.
	batch := 70*time.Millisecond + time.Duration(200*7*cost)*time.Microsecond
	wait := time.Duration(n/200)*batch*3/2 + 60*time.Second + 60*time.Second // the idle minute before the pass
	floodKeys(t, f, "api", n)
	floodedAt := time.Now()
	name := f.zones["api"].name
	used, limit := maintMemory(t, name)
	t.Logf("after the flood: %d of %d bytes in use (%.0f%%)", used, limit, 100*float64(used)/float64(limit))
	if used*2 <= limit {
		t.Fatalf("the flood left the instance at %d of %d bytes, not over half: it does not test the pressure path", used, limit)
	}
	if !testwait.Holds(wait, 2*time.Second, func() bool {
		used, limit = maintMemory(t, name)
		return used*2 <= limit
	}) {
		t.Fatalf("the instance is still at %d of %d bytes after %v, over half; log:\n%s", used, limit, wait, logsOf(name))
	}
	if !strings.Contains(logsOf(name), "over half of its memory") {
		t.Errorf("the loop never said it ran without pauses; log:\n%s", logsOf(name))
	}
	t.Logf("the instance is back under half (%d of %d bytes) %v after the flood, within the %v this host is allowed", used, limit, time.Since(floodedAt).Round(time.Second), wait)
}

// TestValkeySweepKeepsEachServiceInsideItsKeyBudget floods a service with keys that look exactly like the
// limiter's (a two field hash with a lifetime inside the bound), more than MAX_KEYS of them. Valkey cannot
// tell them from real ones, so the budget is what bounds the instance: the keys past it are deleted, and the
// other service keeps writing. The flood is sent from inside the container with `valkey-cli --pipe`: the same
// commands one by one, over the host's port forward or from valkey-cli's line mode, run at a few hundred a
// second and a hundred thousand of them take minutes.
//
// How long the sweep takes to cut the flood is the host's: a pass is paced to a fifth of the server's time, so
// it lasts five times the work, and the work is about six redis.call a key at what a call costs here
// (sweepPassBudget), which is a minute or more on a VM with a slow clock and under a second on an ordinary host. The
// two zones are two servers, so the floods run side by side.
func TestValkeySweepKeepsEachServiceInsideItsKeyBudget(t *testing.T) {
	f := startValkeyFill(t, "64mb")
	maxKeys := luaConst(t, "sweep.lua", "MAX_KEYS")
	n := maxKeys + maxKeys/4
	wait := sweepPassBudget(t, n)
	t.Run("floods", func(t *testing.T) {
		for _, service := range []string{"api", "admin"} {
			t.Run(service, func(t *testing.T) {
				t.Parallel()
				floodKeys(t, f, service, n)
				// Wait until the sweep has cut the flood to its budget, and look at what is left.
				left := 0
				if !testwait.Holds(wait, 2*time.Second, func() bool {
					left = maintScanCount(t, f.zones[service].name, "ctrlz:rl:"+service+":flood:*")
					return left <= maxKeys
				}) {
					t.Fatalf("%s: %d flood keys are left after %v, the budget is %d", service, left, wait, maxKeys)
				}
				if left < maxKeys/2 {
					t.Errorf("%s: the sweep cut the flood down to %d keys, far below the budget of %d; log:\n%s", service, left, maxKeys, logsOf(f.zones[service].name))
				}
				t.Logf("%s: %d of %d flood keys left (budget %d)", service, left, n, maxKeys)
			})
		}
	})
	// Both services still write.
	f.waitLimiter(t, "api", "after-flood", 10*time.Second)
	f.waitLimiter(t, "admin", "after-flood", 10*time.Second)
	// The budget times the largest key, plus the index, fits the smallest profile: each zone has its own server now, so one
	// zone's budget has to fit one maxmemory.
	if need := maxKeys*luaConst(t, "sweep.lua", "MAX_KEY_BYTES") + luaConst(t, "sweep.lua", "MAX_INDEX_BYTES"); need >= smallestMaxmemory(t) {
		t.Errorf("a budget of %d keys of up to %d bytes and the index (%d bytes) do not fit the smallest maxmemory of the profiles (%d)",
			maxKeys, luaConst(t, "sweep.lua", "MAX_KEY_BYTES"), luaConst(t, "sweep.lua", "MAX_INDEX_BYTES"), smallestMaxmemory(t))
	}
}
