package lint_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
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

// valkeyFill is what these tests share: the real Compose start line with a small maxmemory, a client for
// each service user and the real limiter of each, which is the "victim" that has to keep writing.
type valkeyFill struct {
	name   string
	addr   string
	api    valkey.Client
	admin  valkey.Client
	apiLim *ratelimit.Limiter
	admLim *ratelimit.Limiter
}

func startValkeyFill(t *testing.T, maxmemory string) *valkeyFill {
	t.Helper()
	const apiPW, adminPW = "Zq3vNn7hQw1xKs9dApi", "Hk8mTr2vBc5yLp4wAdm"
	name, _, hostAddr := startValkeyACL(t, apiPW, adminPW, "-e", "VALKEY_MAXMEMORY="+maxmemory)
	f := &valkeyFill{name: name, addr: hostAddr()}
	connect := func(user, pw string) valkey.Client {
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{f.addr}, Username: user, Password: pw, DisableCache: true})
		if err != nil {
			t.Fatalf("sign in as %q: %v", user, err)
		}
		t.Cleanup(c.Close)
		return c
	}
	f.api, f.admin = connect("api", apiPW), connect("admin", adminPW)
	f.apiLim = ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, Backend: ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: f.addr, Username: "api", Password: secret.New(apiPW)})})
	f.admLim = ratelimit.New(ratelimit.Config{Service: ratelimit.Admin, Backend: ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: f.addr, Username: "admin", Password: secret.New(adminPW), IndexKey: ratelimit.IndexKey(ratelimit.Admin)})})
	return f
}

func (f *valkeyFill) client(service string) valkey.Client {
	if service == "api" {
		return f.api
	}
	return f.admin
}

// limiterWorks asks the service's own limiter for one token. It is the victim's view: the write a
// tenant's SMS login or the owner's console login needs.
func (f *valkeyFill) limiterWorks(ctx context.Context, service, subject string) error {
	if service == "api" {
		c, _ := ratelimit.Lookup(ratelimit.Tenant, "sensitive")
		_, err := f.apiLim.Allow(ctx, c, ratelimit.Subject{Session: subject})
		return err
	}
	c, _ := ratelimit.Lookup(ratelimit.Admin, "admin-login")
	_, err := f.admLim.Allow(ctx, c, ratelimit.Subject{Network: subject})
	return err
}

// waitLimiter polls until the limiter of a service writes again, and fails with what the server said.
func (f *valkeyFill) waitLimiter(t *testing.T, service, subject string, within time.Duration) {
	t.Helper()
	var last error
	for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		last = f.limiterWorks(ctx, service, subject)
		cancel()
		if last == nil {
			return
		}
	}
	t.Fatalf("the %s limiter still cannot write %v after the flood; log:\n%s", service, within, logsOf(f.name))
}

// fillUntilFull writes junk as a service user, large values first and then smaller ones, until the server
// answers OOM, the way the reviewer reproduced it, and returns the names of the keys it wrote.
//
// The container's sweep runs every MAINT_INTERVAL (2 s) and deletes this very junk, so the fill has to
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
// each service against the other and against itself: fill a 16 MB instance with HSET of large values and no
// lifetime, and require that the junk is gone and both limiters write again within seconds. A second pass
// gives every junk key a lifetime of years (a direct PEXPIRE takes any), which the limiter never does.
func TestValkeyServiceCredentialCannotFillTheServer(t *testing.T) {
	f := startValkeyFill(t, "16mb")
	for _, attacker := range []string{"api", "admin"} {
		victim := map[string]string{"api": "admin", "admin": "api"}[attacker]
		t.Run(attacker+" fills", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
			defer cancel()
			c := f.client(attacker)
			prefix := "ctrlz:rl:" + attacker + ":"
			keys := fillUntilFull(t, c, prefix)
			f.waitLimiter(t, victim, "after-"+attacker, 45*time.Second)
			f.waitLimiter(t, attacker, "after-self", 45*time.Second)
			// The limiter writes as soon as there is room; the junk has to be gone altogether, because
			// what stays is the next flood's head start (and, with no lifetime, outlives every restart).
			for end := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
				_, left := missing(ctx, c, keys)
				if left == 0 {
					break
				}
				if time.Now().After(end) {
					t.Fatalf("%d of %d junk keys are still there after 60 s", left, len(keys))
				}
			}
			// A lifetime the limiter would never give: tiny, but kept for years, and tiny with none.
			c.Do(ctx, c.B().Hset().Key(prefix+"forever").FieldValue().FieldValue("f", "1").Build())
			c.Do(ctx, c.B().Pexpire().Key(prefix+"forever").Milliseconds(99999999999).Build())
			c.Do(ctx, c.B().Hset().Key(prefix+"nolife").FieldValue().FieldValue("f", "1").Build())
			waitLog(t, f.name, "keyspace sweep deleted", 45*time.Second)
			for end := time.Now().Add(45 * time.Second); ; time.Sleep(500 * time.Millisecond) {
				if _, left := missing(ctx, c, []string{prefix + "forever", prefix + "nolife"}); left == 0 {
					break
				}
				if time.Now().After(end) {
					t.Fatal("a key with no lifetime or a lifetime of years survived the sweep")
				}
			}
		})
	}
}

// TestValkeySweepKeepsTheKeysTheLimiterWrote is the other side: the sweep must not cost the services what the
// limiter writes. Buckets spent before a sweep are still spent after it, the admin index still lists its
// keys, and `ctrlz-admin unlock` still clears them.
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
	// Junk that makes the sweep log a deletion, so the test knows a sweep has run after the spend.
	f.api.Do(ctx, f.api.B().Hset().Key("ctrlz:rl:api:marker").FieldValue().FieldValue("f", "1").Build())
	waitLog(t, f.name, "keyspace sweep deleted", 45*time.Second)
	time.Sleep(5 * time.Second) // two more rounds of the loop
	login, _ := ratelimit.Lookup(ratelimit.Admin, "admin-login")
	allowed := 0
	for i := 0; i < 20; i++ {
		d, err := f.admLim.Allow(ctx, login, ratelimit.Subject{Network: "203.0.113.0"})
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed {
			break
		}
		allowed++
	}
	if allowed != 2 {
		t.Errorf("after the sweep the admin-login bucket let %d more through, want the 2 that were left of 5", allowed)
	}
	idx, err := f.admin.Do(ctx, f.admin.B().Zrange().Key(ratelimit.IndexKey(ratelimit.Admin)).Min("0").Max("-1").Build()).AsStrSlice()
	if err != nil || len(idx) == 0 {
		t.Errorf("the admin index holds %d entries (%v): the sweep removed it or it was never written", len(idx), err)
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
		c, err := net.DialTimeout("tcp", f.addr, 3*time.Second)
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
		time.Sleep(5 * time.Second) // well past the server's 2 s idle timeout
	}
}

// maintScanCount counts the keys that match a pattern, signed in as the container's maintenance user, whose
// password the start line wrote to the ACL file in the tmpfs. The test reads it the way an operator on the
// host could; the services cannot (they hold no SCAN).
func maintScanCount(t *testing.T, name, pattern string) int {
	t.Helper()
	out, err := exec.Command("docker", "exec", name, "sh", "-c",
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

// TestValkeySweepKeepsEachServiceInsideItsKeyBudget floods a service with keys that look exactly like the
// limiter's (a two field hash with a lifetime inside the bound), more than MAX_KEYS of them. Valkey cannot
// tell them from real ones, so the budget is what bounds the instance: the keys past it are deleted, and the
// other service keeps writing. The flood is sent from inside the container with `valkey-cli --pipe`: the same
// commands one by one, over the host's port forward or from valkey-cli's line mode, run at a few hundred a
// second and a hundred thousand of them take minutes.
func TestValkeySweepKeepsEachServiceInsideItsKeyBudget(t *testing.T) {
	f := startValkeyFill(t, "64mb")
	maxKeys := luaConst(t, "sweep.lua", "MAX_KEYS")
	n := maxKeys + maxKeys/4
	pws := map[string]string{"api": "Zq3vNn7hQw1xKs9dApi", "admin": "Hk8mTr2vBc5yLp4wAdm"}
	for _, service := range []string{"api", "admin"} {
		// RESP by hand: *argc, then $len and the argument for each.
		prog := fmt.Sprintf(`BEGIN{for(i=0;i<%d;i++){k=sprintf("ctrlz:rl:%s:flood:%%d",i);`+
			`printf "*6\r\n$4\r\nHSET\r\n$%%d\r\n%%s\r\n$6\r\ntokens\r\n$1\r\n1\r\n$2\r\nat\r\n$1\r\n1\r\n",length(k),k;`+
			`printf "*3\r\n$7\r\nPEXPIRE\r\n$%%d\r\n%%s\r\n$10\r\n1000000000\r\n",length(k),k}}`, n, service)
		out, err := exec.Command("docker", "exec", "-e", "REDISCLI_AUTH="+pws[service], f.name, "sh", "-c",
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
		// Wait until the sweep has cut the flood to its budget, and look at what is left.
		left := 0
		for end := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
			if left = maintScanCount(t, f.name, "ctrlz:rl:"+service+":flood:*"); left <= maxKeys {
				break
			}
			if time.Now().After(end) {
				t.Fatalf("%s: %d flood keys are left, the budget is %d", service, left, maxKeys)
			}
		}
		if left < maxKeys/2 {
			t.Errorf("%s: the sweep cut the flood down to %d keys, far below the budget of %d; log:\n%s", service, left, maxKeys, logsOf(f.name))
		}
		t.Logf("%s: %d of %d flood keys left (budget %d)", service, left, n, maxKeys)
	}
	// Both services still write.
	f.waitLimiter(t, "api", "after-flood", 10*time.Second)
	f.waitLimiter(t, "admin", "after-flood", 10*time.Second)
	// The budget times the largest key, for both services, plus the index, fits the smallest profile.
	if need := 2*maxKeys*luaConst(t, "sweep.lua", "MAX_KEY_BYTES") + luaConst(t, "sweep.lua", "MAX_INDEX_BYTES"); need >= smallestMaxmemory(t) {
		t.Errorf("two budgets of %d keys of up to %d bytes and the index (%d bytes) do not fit the smallest maxmemory of the profiles (%d)",
			maxKeys, luaConst(t, "sweep.lua", "MAX_KEY_BYTES"), luaConst(t, "sweep.lua", "MAX_INDEX_BYTES"), smallestMaxmemory(t))
	}
}
