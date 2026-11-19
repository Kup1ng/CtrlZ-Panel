package lint_test

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Round 6, admin-r6-7 (rule role-reach, applied to Valkey). The api (internet facing) and the admin
// (meant to be its own trust zone) shared one Valkey password with full access, so a compromised api
// could empty the owner's admin-login buckets and keep them empty, and the console could not refill
// them. Each service has its own ACL user now. Two tests hold it: a static one over the Compose file
// (no Valkey secret is mounted into two services, each service signs in as its own user, the start
// line has no requirepass) and one that applies the very start line of the valkey service to a real
// Valkey and tries what a compromised service would try.

// valkeyView is what the static rule looks at in one service.
type valkeyView struct {
	Secrets []string
	Env     map[string]string
}

func valkeyViews(c compose) map[string]valkeyView {
	out := map[string]valkeyView{}
	for name, s := range c.Services {
		out[name] = valkeyView{Secrets: s.Secrets, Env: s.Environment}
	}
	return out
}

// valkeySecretProblems judges the services of a Compose file.
func valkeySecretProblems(svcs map[string]valkeyView) []string {
	var out []string
	users := map[string]string{}
	holders := map[string][]string{}
	serverHas := map[string]bool{}
	for name, s := range svcs {
		for _, sec := range s.Secrets {
			if !strings.HasPrefix(sec, "valkey_password") {
				continue
			}
			if name == "valkey" {
				serverHas[sec] = true
			} else {
				holders[sec] = append(holders[sec], name)
			}
		}
		if u := s.Env["CTRLZ_VALKEY_USER"]; u != "" {
			if other, dup := users[u]; dup {
				out = append(out, fmt.Sprintf("%s and %s both sign in to Valkey as %q", other, name, u))
			}
			users[u] = name
		}
		if f := s.Env["CTRLZ_VALKEY_PASSWORD_FILE"]; f != "" {
			if s.Env["CTRLZ_VALKEY_USER"] == "" {
				out = append(out, name+" signs in to Valkey as the default user: give it its own ACL user (CTRLZ_VALKEY_USER)")
			}
			held := false
			for _, sec := range s.Secrets {
				held = held || f == "/run/secrets/"+sec
			}
			if !held {
				out = append(out, name+" reads "+f+" and does not mount that secret")
			}
		}
	}
	for sec, who := range holders {
		sort.Strings(who)
		if len(who) > 1 {
			out = append(out, fmt.Sprintf("the Valkey secret %s is mounted into %s: one secret per service", sec, strings.Join(who, " and ")))
		}
		if !serverHas[sec] {
			out = append(out, "the valkey service does not mount "+sec+", so it cannot make that service's ACL user")
		}
	}
	sort.Strings(out)
	return out
}

func TestEachServiceHasItsOwnValkeyUser(t *testing.T) {
	c := loadCompose(t)
	if p := valkeySecretProblems(valkeyViews(c)); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
	script := strings.Join(c.Services["valkey"].Command, "\n")
	if !strings.Contains(script, "user default off") {
		t.Error("the valkey start line does not switch the default user off")
	}
	if strings.Contains(script, "requirepass") {
		t.Error("the valkey start line sets requirepass: one password with full access for everybody")
	}
	for _, sec := range c.Services["valkey"].Secrets {
		if !strings.Contains(script, "/run/secrets/"+sec) {
			t.Errorf("the valkey start line never reads %s", sec)
		}
	}
}

// TestValkeySecretLintCanFail plants the shapes the rule must refuse.
func TestValkeySecretLintCanFail(t *testing.T) {
	good := map[string]valkeyView{
		"valkey": {Secrets: []string{"valkey_password_api", "valkey_password_admin"}},
		"api":    {Secrets: []string{"valkey_password_api"}, Env: map[string]string{"CTRLZ_VALKEY_USER": "api", "CTRLZ_VALKEY_PASSWORD_FILE": "/run/secrets/valkey_password_api"}},
		"admin":  {Secrets: []string{"valkey_password_admin"}, Env: map[string]string{"CTRLZ_VALKEY_USER": "admin", "CTRLZ_VALKEY_PASSWORD_FILE": "/run/secrets/valkey_password_admin"}},
	}
	if p := valkeySecretProblems(good); len(p) != 0 {
		t.Fatalf("the good shape is refused: %v", p)
	}
	for name, mutate := range map[string]func(m map[string]valkeyView){
		"one secret in two services": func(m map[string]valkeyView) {
			a := m["admin"]
			a.Secrets = []string{"valkey_password_api"}
			a.Env = map[string]string{"CTRLZ_VALKEY_USER": "admin", "CTRLZ_VALKEY_PASSWORD_FILE": "/run/secrets/valkey_password_api"}
			m["admin"] = a
		},
		"both secrets in one service": func(m map[string]valkeyView) {
			a := m["api"]
			a.Secrets = []string{"valkey_password_api", "valkey_password_admin"}
			m["api"] = a
		},
		"the default user": func(m map[string]valkeyView) {
			a := m["api"]
			a.Env = map[string]string{"CTRLZ_VALKEY_PASSWORD_FILE": "/run/secrets/valkey_password_api"}
			m["api"] = a
		},
		"two services as one user": func(m map[string]valkeyView) {
			a := m["admin"]
			a.Env = map[string]string{"CTRLZ_VALKEY_USER": "api", "CTRLZ_VALKEY_PASSWORD_FILE": "/run/secrets/valkey_password_admin"}
			m["admin"] = a
		},
		"a secret the server does not hold": func(m map[string]valkeyView) {
			m["valkey"] = valkeyView{Secrets: []string{"valkey_password_api"}}
		},
		"a password file that is not mounted": func(m map[string]valkeyView) {
			a := m["api"]
			a.Secrets = nil
			m["api"] = a
		},
	} {
		m := map[string]valkeyView{}
		for k, v := range good {
			m[k] = valkeyView{Secrets: append([]string(nil), v.Secrets...), Env: v.Env}
		}
		mutate(m)
		if len(valkeySecretProblems(m)) == 0 {
			t.Errorf("%s: no problem reported", name)
		}
	}
}

// startValkeyACL runs the valkey service's own start line in the real image and returns the container.
// The api secret ends in CR LF on purpose: the start line has to drop it as the clients do.
//
// The container is the one of the Compose file in every respect the test can reproduce: the same start
// line, the same maintenance script and the same Lua files mounted where the file mounts them.
func startValkeyACL(t *testing.T, apiPW, adminPW string, dockerArgs ...string) (name, probe string, hostAddr func() string) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for this test (use -short to skip)")
	}
	v := loadCompose(t).Services["valkey"]
	if len(v.Command) != 3 || v.Command[0] != "/bin/sh" || v.Command[1] != "-c" || len(v.Healthcheck.Test) != 2 {
		t.Fatalf("valkey command %q, healthcheck %q", v.Command, v.Healthcheck.Test)
	}
	start := strings.ReplaceAll(v.Command[2], "$$", "$") // Compose writes a literal dollar as two
	probe = strings.ReplaceAll(v.Healthcheck.Test[1], "$$", "$")
	image := os.Getenv("VALKEY_IMAGE")
	if image == "" {
		image = "valkey/valkey:8.1"
	}
	conf, err := filepath.Abs(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "valkey.conf"))
	if err != nil {
		t.Fatal(err)
	}
	maint, err := filepath.Abs(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "maintain.sh"))
	if err != nil {
		t.Fatal(err)
	}
	lua, err := filepath.Abs(filepath.Join(repoRoot(t), "internal", "ratelimit", "lua"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	apiFile, adminFile := filepath.Join(dir, "valkey_password_api"), filepath.Join(dir, "valkey_password_admin")
	if err := os.WriteFile(apiFile, []byte(apiPW+"\r\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminFile, []byte(adminPW+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	sweep, err := filepath.Abs(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "sweep.lua"))
	if err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("ctrlz-valkey-acl-%016x", rand.Uint64())
	args := []string{"run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
		"--tmpfs", "/tmp:size=1m,mode=0700", "--tmpfs", "/data", "-p", "127.0.0.1::6379",
		"-v", apiFile + ":/run/secrets/valkey_password_api:ro", "-v", adminFile + ":/run/secrets/valkey_password_admin:ro",
		"-v", conf + ":/etc/valkey/valkey.conf:ro", "-v", maint + ":/etc/valkey/maintain.sh:ro", "-v", sweep + ":/etc/valkey/sweep.lua:ro",
		"-v", lua + ":/etc/valkey/lua:ro"}
	// dockerArgs is how a test sets what Compose sets from the profile (VALKEY_MAXMEMORY) without a copy of the start line.
	args = append(args, dockerArgs...)
	args = append(args, "--entrypoint", "/bin/sh", image, "-c", start)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	waitHealthy(t, name, probe)
	hostAddr = func() string {
		t.Helper()
		portOut, err := exec.Command("docker", "port", name, "6379/tcp").CombinedOutput()
		if err != nil {
			t.Fatalf("docker port: %v\n%s", err, portOut)
		}
		return strings.Replace(strings.TrimSpace(strings.Split(string(portOut), "\n")[0]), "0.0.0.0", "127.0.0.1", 1)
	}
	return name, probe, hostAddr
}

// waitHealthy runs the Compose healthcheck of the valkey service in the container until it passes. It
// now also waits for the marker that maintain.sh writes after loading the limiter scripts.
func waitHealthy(t *testing.T, name, probe string) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for {
		out, err := exec.Command("docker", "exec", name, "sh", "-c", probe).CombinedOutput()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", "--tail", "10", name).CombinedOutput()
			t.Fatalf("the healthcheck never passed (%v, %q); server log:\n%s", err, out, logs)
		}
		time.Sleep(time.Second)
	}
}

// TestValkeyACLUsersKeepToTheirOwnKeys tries what a compromised service would: read or write the other
// service's keys, flush, read the configuration, list every key. It also runs what the legitimate
// services do (the limiter's Lua scripts and the connection handshake of the client, `unlock`'s index
// read and unlink) so a rule that is too narrow breaks here and not in production.
func TestValkeyACLUsersKeepToTheirOwnKeys(t *testing.T) {
	const apiPW, adminPW = "Zq3vNn7hQw1xKs9dApi", "Hk8mTr2vBc5yLp4wAdm"
	_, _, hostAddr := startValkeyACL(t, apiPW, adminPW)
	addr := hostAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	raw := func(user, pw string) valkey.Client {
		t.Helper()
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Username: user, Password: pw, DisableCache: true})
		if err != nil {
			t.Fatalf("sign in as %q: %v", user, err)
		}
		t.Cleanup(c.Close)
		return c
	}
	denied := func(what string, res valkey.ValkeyResult) {
		t.Helper()
		if err := res.Error(); err == nil || !(strings.Contains(err.Error(), "NOPERM") || strings.Contains(err.Error(), "ACL failure in script")) {
			t.Errorf("%s: want a refusal by the ACL, got %v", what, err)
		}
	}

	// The default user is off: a client that signs in as nobody gets nowhere.
	if c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true}); err == nil {
		if err := c.Do(ctx, c.B().Ping().Build()).Error(); err == nil {
			t.Error("an unauthenticated PING succeeded: the default user is on")
		}
		c.Close()
	}

	api, admin := raw("api", apiPW), raw("admin", adminPW)
	// What the services do, through the real limiter and the real client handshake.
	apiLimiter := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, Backend: ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: addr, Username: "api", Password: secret.New(apiPW)})})
	adminValkey := ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: addr, Username: "admin", Password: secret.New(adminPW), IndexKey: ratelimit.IndexKey(ratelimit.Admin)})
	adminLimiter := ratelimit.New(ratelimit.Config{Service: ratelimit.Admin, Backend: adminValkey})
	sens, _ := ratelimit.Lookup(ratelimit.Tenant, "sensitive")
	login, _ := ratelimit.Lookup(ratelimit.Admin, "admin-login")
	spend := func(l *ratelimit.Limiter, c ratelimit.Class, s ratelimit.Subject) (allowed int) {
		for i := 0; i < 40; i++ {
			d, err := l.Allow(ctx, c, s)
			if err != nil {
				t.Fatalf("%s through its own user: %v", c.Name, err)
			}
			if !d.Allowed {
				return allowed
			}
			allowed++
		}
		return allowed
	}
	if n := spend(apiLimiter, sens, ratelimit.Subject{Session: "s-1"}); n != 10 {
		t.Fatalf("the api limiter let %d through a class of 10", n)
	}
	netw := ratelimit.Subject{Network: "203.0.113.0"}
	if n := spend(adminLimiter, login, netw); n != 5 {
		t.Fatalf("the admin limiter let %d through a class of 5", n)
	}

	// A compromised api.
	// HSET and HMGET are commands the api user holds (its limiter's script runs them), so these are
	// refused by the key pattern and by nothing else: the check that a pattern of ~* would break.
	denied("api writes an admin key", api.Do(ctx, api.B().Hset().Key("ctrlz:rl:admin:admin-login:n:x:60").FieldValue().FieldValue("tokens", "100").Build()))
	denied("api reads an admin key", api.Do(ctx, api.B().Hmget().Key("ctrlz:rl:admin:admin-login:n:203.0.113.0:60").Field("tokens", "at").Build()))
	denied("api EVAL HSET on an admin key", api.Do(ctx, api.B().Eval().Script("return redis.call('HSET', 'ctrlz:rl:admin:admin-login:n:203.0.113.0:60', 'tokens', '100')").Numkeys(0).Build()))
	denied("api deletes an admin key", api.Do(ctx, api.B().Del().Key("ctrlz:rl:admin:admin-login:n:203.0.113.0:60").Build()))
	denied("api EVAL on an admin key", api.Do(ctx, api.B().Eval().Script("return redis.call('SET', KEYS[1], '1')").Numkeys(1).Key("ctrlz:rl:admin:y").Build()))
	denied("api EVAL on an admin key reached inside the script", api.Do(ctx, api.B().Eval().Script("return redis.call('SET', 'ctrlz:rl:admin:z', '1')").Numkeys(0).Build()))
	denied("api FLUSHALL", api.Do(ctx, api.B().Flushall().Build()))
	denied("api CONFIG GET", api.Do(ctx, api.B().ConfigGet().Parameter("*").Build()))
	denied("api KEYS", api.Do(ctx, api.B().Keys().Pattern("*").Build()))
	denied("api ACL LIST", api.Do(ctx, api.B().AclList().Build()))
	denied("api SCAN", api.Do(ctx, api.B().Scan().Cursor(0).Build()))
	// A compromised admin.
	denied("admin writes an api key", admin.Do(ctx, admin.B().Hset().Key("ctrlz:rl:api:sensitive:s:s-1:60").FieldValue().FieldValue("tokens", "100").Build()))
	denied("admin EVAL HSET on an api key", admin.Do(ctx, admin.B().Eval().Script("return redis.call('HSET', 'ctrlz:rl:api:sensitive:s:s-1:60', 'tokens', '100')").Numkeys(0).Build()))
	denied("admin deletes an api key", admin.Do(ctx, admin.B().Unlink().Key("ctrlz:rl:api:sensitive:s:s-1:60").Build()))
	denied("admin EVAL inside the script on an api key", admin.Do(ctx, admin.B().Eval().Script("return redis.call('DEL', 'ctrlz:rl:api:sensitive:s:s-1:60')").Numkeys(0).Build()))
	denied("admin FLUSHALL", admin.Do(ctx, admin.B().Flushall().Build()))
	// The admin must not be able to list the api's keys, which name a tenant user id and the network it
	// signs in from (round 7, admin-r7-6). SCAN and KEYS are not bound by key patterns, so the user holds
	// neither; "a user that may SCAN with MATCH on its own prefix" is the very shape that leaked. The api
	// limiter has written keys by now, so a SCAN that worked would return them: the test asks for every
	// key and counts the api's.
	denied("admin SCAN", admin.Do(ctx, admin.B().Scan().Cursor(0).Count(1000).Build()))
	denied("admin SCAN with MATCH", admin.Do(ctx, admin.B().Scan().Cursor(0).Match("ctrlz:rl:api:*").Count(1000).Build()))
	denied("admin KEYS", admin.Do(ctx, admin.B().Keys().Pattern("ctrlz:rl:*").Build()))
	denied("admin RANDOMKEY", admin.Do(ctx, admin.B().Randomkey().Build()))
	denied("admin EVAL SCAN inside a script", admin.Do(ctx, admin.B().Eval().Script("return redis.call('SCAN', '0', 'COUNT', '1000')").Numkeys(0).Build()))
	denied("admin reads the api's keys through a set command", admin.Do(ctx, admin.B().Zrange().Key("ctrlz:rl:api:index").Min("0").Max("-1").Build()))
	if got, err := admin.Do(ctx, admin.B().Zrange().Key(ratelimit.IndexKey(ratelimit.Admin)).Min("0").Max("-1").Build()).AsStrSlice(); err != nil || len(got) == 0 {
		t.Errorf("the admin index holds %v (%v): the admin limiter wrote keys and unlock needs them listed", got, err)
	} else {
		for _, k := range got {
			if !strings.HasPrefix(k, ratelimit.KeyPrefix(ratelimit.Admin)) {
				t.Errorf("the admin index names a key outside the admin's prefix: %q", k)
			}
		}
	}
	// The health user can only PING.
	health := raw("health", "none")
	if err := health.Do(ctx, health.B().Ping().Build()).Error(); err != nil {
		t.Errorf("the health user cannot ping: %v", err)
	}
	denied("health reads a key", health.Do(ctx, health.B().Get().Key("ctrlz:rl:api:x").Build()))

	// `ctrlz-admin unlock` clears the admin's keys and nothing of the api's.
	if _, err := adminValkey.ResetIndexed(ctx); err != nil {
		t.Fatalf("unlock through the admin user: %v", err)
	}
	if n := spend(adminLimiter, login, netw); n != 5 {
		t.Errorf("after unlock the admin-login bucket let %d through, want a fresh 5", n)
	}
	if n := spend(apiLimiter, sens, ratelimit.Subject{Session: "s-1"}); n != 0 {
		t.Errorf("unlock of the admin gave the api a fresh bucket (%d through): it cleared keys that are not its own", n)
	}
}

// The rule for what an ACL user may run (round 7, admin-r7-6; the second round the topic drew after
// admin-r6-7): a Valkey key pattern binds only a command that NAMES a key, so a command that names none
// (SCAN, KEYS, RANDOMKEY, DBSIZE, INFO, MONITOR, CLIENT LIST...) answers about the whole instance whatever
// the user's `~pattern` says. Round 6 gave the admin SCAN with a MATCH on its own prefix, and the filter is
// applied after the scan, so the user got the name of every key. Each user therefore has a list of the
// commands it may hold, declared here with the reason, and a command that is not on it fails; none of them
// is a command that names no key except the handshake ones, which is stated in the table.
var valkeyUserCommands = map[string]map[string]string{
	"health": {"ping": "the healthcheck"},
	// The maintenance user of the container (maintain.sh): its password is made at start and is in no
	// file and no secret, so no service can sign in as it. It loads the limiter's scripts, so that
	// neither service needs EVAL or SCRIPT LOAD, and ends a script that holds the server (round 13,
	// admin-r13-5). Round 15 (admin-r15-1) gave it the keys of the limiter, ~ctrlz:rl:* and no other, and
	// the read-only commands and UNLINK that sweep.lua runs: a key that no limiter script wrote, or
	// that is over a size or count budget, is deleted, which is what keeps a service credential from
	// filling the instance. SCAN names no key, which is why only the maintenance user holds it and
	// why it runs a script of the container's own (a service never sees a key it does not own).
	"maint": {
		"ping": "the loop asks whether the server is up or BUSY", "script|load": "loads the limiter's two scripts and the sweep",
		"script|kill": "ends a script that holds the server", "shutdown": "the last resort for a script that has written and cannot be killed",
		"evalsha": "runs the sweep, whose digest the loop got from SCRIPT LOAD", "scan": "the sweep walks the limiter's keys in batches",
		"type": "the sweep checks a key is a hash (a zset for the index)", "pttl": "the sweep checks a key has a bounded lifetime",
		"hlen": "the sweep checks a hash has the two fields the limiter writes", "zcard": "the sweep bounds the admin's index",
		"memory|usage": "the sweep bounds the bytes of a key", "unlink": "the sweep deletes what is not a limiter key",
	},
	"api": limiterCommands(),
	"admin": withCommands(limiterCommands(), map[string]string{
		"zadd":             "the limiter's scripts list each key they write in the index (ctrlz:rl:admin:index)",
		"zremrangebyscore": "the scripts trim the index of keys that have expired",
		"zrange":           "`ctrlz-admin unlock` reads the index, in batches",
		"zrem":             "`unlock` removes a key from the index after it deleted the key",
		"unlink":           "`unlock` deletes the keys the index lists",
	}),
}

func limiterCommands() map[string]string {
	return map[string]string{
		"hello": "client handshake", "auth": "client handshake", "reset": "client handshake",
		"client|setinfo": "client handshake", "client|setname": "client handshake",
		// EVALSHA and not EVAL: a script a client sends is a script of its own, and key patterns limit
		// what a script touches and not how long it runs (round 13, admin-r13-5). The two scripts are
		// loaded by the maintenance user.
		"evalsha": "the limiter's Lua scripts, loaded at start", "time": "the scripts read the server clock",
		"hmget": "inside the scripts", "hset": "inside the scripts", "pexpire": "inside the scripts",
	}
}

func withCommands(base, extra map[string]string) map[string]string {
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// valkeyACLProblems reads the `user X on ...` lines of a start script and returns every command a user
// holds that its list does not name, and every user that is not listed.
func valkeyACLProblems(script string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(script, "\n") {
		i := strings.Index(line, "user ")
		if !strings.Contains(line, "printf") || i < 0 {
			continue
		}
		f := strings.Fields(line[i:])
		if len(f) < 3 {
			continue
		}
		user := f[1]
		seen[user] = true
		allowed, ok := valkeyUserCommands[user]
		if !ok {
			if user != "default" {
				out = append(out, "user "+user+" has no declared command list")
			}
			continue
		}
		for _, tok := range f[2:] {
			// The last token of a line carries the printf format's own ending (\n and the quote).
			if j := strings.IndexAny(tok, `\'`); j >= 0 {
				tok = tok[:j]
			}
			switch {
			case tok == "allkeys", tok == "~*", tok == "%RW~*", tok == "%R~*", tok == "%W~*":
				out = append(out, user+": every key ("+tok+") is not a pattern of its own limiter")
			case strings.HasPrefix(tok, "~") || strings.HasPrefix(tok, "%"):
				// A user may hold the keys of its own limiter and no other (the runtime test tries the
				// other service's); health holds none, and maint holds the whole limiter keyspace and
				// nothing outside it, which is what the sweep reads and deletes in.
				own := "~ctrlz:rl:" + user + ":*"
				if user == "maint" {
					own = "~ctrlz:rl:*"
				}
				if tok != own || user == "health" {
					out = append(out, user+": key pattern "+tok+" is not its own limiter's")
				}
			case strings.HasPrefix(tok, "+@"), tok == "allcommands", tok == "+*":
				out = append(out, user+": a whole category of commands ("+tok+") is not a list")
			case strings.HasPrefix(tok, "+"):
				cmd := strings.TrimPrefix(tok, "+")
				if _, ok := allowed[cmd]; !ok {
					out = append(out, user+": +"+cmd+" is not on the user's declared list")
				}
			}
		}
	}
	for u := range valkeyUserCommands {
		if !seen[u] {
			out = append(out, "the start script never defines "+u)
		}
	}
	return out
}

func TestValkeyUsersHoldOnlyDeclaredCommands(t *testing.T) {
	script := strings.Join(loadCompose(t).Services["valkey"].Command, "\n")
	if p := valkeyACLProblems(script); len(p) != 0 {
		t.Fatalf("%s", strings.Join(p, "\n"))
	}
}

func TestValkeyCommandListCanFail(t *testing.T) {
	good := loadComposeScript(t)
	for name, mutate := range map[string]func(string) string{
		"the admin gets SCAN back": func(s string) string {
			return strings.Replace(s, "+zrem +unlink", "+zrem +unlink +scan", 1)
		},
		"the api gets KEYS": func(s string) string { return strings.Replace(s, `+hset +pexpire\n`, `+hset +pexpire +keys\n`, 1) },
		"the api gets a category": func(s string) string {
			return strings.Replace(s, `+hset +pexpire\n`, `+hset +pexpire +@read\n`, 1)
		},
		"the health user gets GET": func(s string) string { return strings.Replace(s, "+ping", "+ping +get", 1) },
		// admin-r13-5: one EVAL of a loop keeps Valkey BUSY for every tenant.
		"the api gets EVAL back": func(s string) string {
			return strings.Replace(s, "+client|setname +evalsha", "+client|setname +eval +evalsha", 1)
		},
		"the admin gets EVAL back": func(s string) string { return strings.Replace(s, "+pexpire +zadd", "+pexpire +eval +zadd", 1) },
		"the api gets SCRIPT LOAD": func(s string) string {
			return strings.Replace(s, "+client|setname +evalsha", "+client|setname +script|load +evalsha", 1)
		},
		"the api gets FUNCTION": func(s string) string {
			return strings.Replace(s, "+client|setname +evalsha", "+client|setname +function|load +fcall +evalsha", 1)
		},
		"the maint user gets every key": func(s string) string {
			return strings.Replace(s, "user maint on >%s ~ctrlz:rl:* -@all", "user maint on >%s ~* -@all", 1)
		},
		"the maint user gets GET":  func(s string) string { return strings.Replace(s, "+unlink\\n", "+unlink +get\\n", 1) },
		"the maint user gets EVAL": func(s string) string { return strings.Replace(s, "+shutdown +evalsha", "+shutdown +eval +evalsha", 1) },
		"the maint user gets FLUSHALL": func(s string) string {
			return strings.Replace(s, "+shutdown +evalsha", "+shutdown +flushall +evalsha", 1)
		},
		"the health user gets a key": func(s string) string {
			return strings.Replace(s, "user health on nopass resetkeys", "user health on nopass ~ctrlz:rl:* resetkeys", 1)
		},
		"the api sees every key": func(s string) string { return strings.Replace(s, "~ctrlz:rl:api:*", "~*", 1) },
		"the api sees the admin's": func(s string) string {
			return strings.Replace(s, "~ctrlz:rl:api:*", "~ctrlz:rl:api:* ~ctrlz:rl:admin:*", 1)
		},
	} {
		if p := valkeyACLProblems(mutate(good)); len(p) == 0 {
			t.Errorf("%s: no problem reported", name)
		}
	}
}

func loadComposeScript(t *testing.T) string {
	t.Helper()
	return strings.Join(loadCompose(t).Services["valkey"].Command, "\n")
}

// luaSHA is the name Valkey gives a script: the SHA-1 of its text.
func luaSHA(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "ratelimit", "lua", name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(b) //nolint:gosec // the digest is the name Valkey gives a script
	return hex.EncodeToString(sum[:])
}

// TestValkeyServicesCannotSubmitAScript is admin-r13-5. Key patterns limit what a Lua script touches and not
// how long it runs, so a service that may EVAL could keep Valkey BUSY for every tenant with one
// `while true do end`. The api and the admin user hold EVALSHA only, the container's maintenance user loads
// the two limiter scripts, and a restart brings them back without any service's help.
func TestValkeyServicesCannotSubmitAScript(t *testing.T) {
	const apiPW, adminPW = "Zq3vNn7hQw1xKs9dApi", "Hk8mTr2vBc5yLp4wAdm"
	name, probe, hostAddr := startValkeyACL(t, apiPW, adminPW)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	connect := func(user, pw string) valkey.Client {
		t.Helper()
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{hostAddr()}, Username: user, Password: pw, DisableCache: true})
		if err != nil {
			t.Fatalf("sign in as %q: %v", user, err)
		}
		t.Cleanup(c.Close)
		return c
	}
	refused := func(what string, res valkey.ValkeyResult) {
		t.Helper()
		if err := res.Error(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("%s: want NOPERM, got %v", what, err)
		}
	}
	take := luaSHA(t, "take.lua")
	runTake := func(c valkey.Client) error {
		return c.Do(ctx, c.B().Evalsha().Sha1(take).Numkeys(1).Key("ctrlz:rl:api:probe:60").Arg("5", "60000").Build()).Error()
	}

	api, admin := connect("api", apiPW), connect("admin", adminPW)
	for who, c := range map[string]valkey.Client{"api": api, "admin": admin} {
		refused(who+" EVAL of a loop", c.Do(ctx, c.B().Eval().Script("while true do end").Numkeys(0).Build()))
		refused(who+" SCRIPT LOAD", c.Do(ctx, c.B().ScriptLoad().Script("while true do end").Build()))
		refused(who+" FUNCTION LOAD", c.Do(ctx, c.B().Arbitrary("FUNCTION", "LOAD").Args("#!lua name=x\nredis.register_function('f', function() return 1 end)").Build()))
		refused(who+" SCRIPT KILL", c.Do(ctx, c.B().ScriptKill().Build()))
		refused(who+" SHUTDOWN", c.Do(ctx, c.B().Shutdown().Build()))
	}
	// Nobody signs in as the maintenance user: its password is in no file and no secret.
	if c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{hostAddr()}, Username: "maint", Password: "maint", DisableCache: true}); err == nil {
		if c.Do(ctx, c.B().Ping().Build()).Error() == nil {
			t.Error("signed in as the maintenance user with a guess")
		}
		c.Close()
	}
	// The server was never held: the healthcheck's PING, and the services' own scripts, run at once.
	waitHealthy(t, name, probe)
	if err := runTake(api); err != nil {
		t.Fatalf("the api cannot run the limiter script the container loaded: %v", err)
	}

	// A restart empties the script cache. The maintenance loop loads the scripts again and the healthcheck
	// reports healthy only after that, so a service that waits for it never races the first load.
	if out, err := exec.Command("docker", "restart", "-t", "2", name).CombinedOutput(); err != nil {
		t.Fatalf("docker restart: %v\n%s", err, out)
	}
	waitHealthy(t, name, probe)
	deadline := time.Now().Add(40 * time.Second)
	for {
		c := connect("api", apiPW)
		err := runTake(c)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after a restart the api still cannot run the limiter script: %v", err)
		}
		time.Sleep(time.Second)
	}
}

// maintainedValkey runs maintain.sh against a server that, unlike the Compose one, lets a user EVAL, which is
// what the tests below need to plant a script that holds the server. `loop` may EVAL (the thing the Compose users
// cannot) and `maint` is what the loop signs in as, with the password handed over the way the Compose start line
// does it: a file in the tmpfs that maintain.sh reads once and deletes. restart gives the container the policy of
// the Compose file, for the case where the loop ends the server with SHUTDOWN.
func maintainedValkey(t *testing.T, luaDir string, restart bool) (name, addr string) {
	t.Helper()
	return maintainedValkeyWith(t, luaDir, restart, "")
}

// composeMaintACL is the permissions of the maintenance user as the Compose start line writes them, so the
// test servers below give the loop what production gives it and a copy cannot drift.
func composeMaintACL(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`user maint on >%s (.*?)\\n'`).FindStringSubmatch(loadComposeScript(t))
	if m == nil {
		t.Fatal("the start line has no maint user")
	}
	return m[1]
}

// maintainedValkeyWith is maintainedValkey with more arguments for valkey-server (a smaller maxmemory, a
// short idle timeout).
func maintainedValkeyWith(t *testing.T, luaDir string, restart bool, serverArgs string) (name, addr string) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: container tests skipped")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required for this test (use -short to skip)")
	}
	image := os.Getenv("VALKEY_IMAGE")
	if image == "" {
		image = "valkey/valkey:8.1"
	}
	maint, err := filepath.Abs(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "maintain.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if luaDir == "" {
		luaDir = filepath.Join(repoRoot(t), "internal", "ratelimit", "lua")
	}
	luaDir, err = filepath.Abs(luaDir)
	if err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("ctrlz-valkey-maint-%016x", rand.Uint64())
	start := `printf 'user default off\nuser loop on nopass ~* +@all\nuser maint on >maintpw ` + composeMaintACL(t) + `\n' > /tmp/users.acl
printf maintpw > /tmp/maint.pw
MAINT_USER=maint MAINT_INTERVAL=1 sh /etc/valkey/maintain.sh &
exec valkey-server --aclfile /tmp/users.acl --busy-reply-threshold 500 --appendonly no --save "" ` + serverArgs
	sweep, err := filepath.Abs(filepath.Join(repoRoot(t), "deploy", "compose", "valkey", "sweep.lua"))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL", "--tmpfs", "/tmp:size=1m,mode=0700",
		"--tmpfs", "/data", "-p", "127.0.0.1::6379", "-v", maint + ":/etc/valkey/maintain.sh:ro", "-v", sweep + ":/etc/valkey/sweep.lua:ro", "-v", luaDir + ":/etc/valkey/lua:ro"}
	if restart {
		args = append(args, "--restart", "unless-stopped")
	}
	args = append(args, "--entrypoint", "/bin/sh", image, "-c", start)
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	portOut, err := exec.Command("docker", "port", name, "6379/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("docker port: %v\n%s", err, portOut)
	}
	addr = strings.Replace(strings.TrimSpace(strings.Split(string(portOut), "\n")[0]), "0.0.0.0", "127.0.0.1", 1)
	return name, addr
}

const maintMarker = "test -f /tmp/limiter-scripts-loaded"

// logsOf is the container's log, for a failure message and for the lines the loop prints.
func logsOf(name string) string {
	out, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
	return string(out)
}

// waitLog waits for the container's log to hold a line.
func waitLog(t *testing.T, name, want string, within time.Duration) {
	t.Helper()
	for end := time.Now().Add(within); ; time.Sleep(300 * time.Millisecond) {
		if strings.Contains(logsOf(name), want) {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("the log never said %q; log:\n%s", want, logsOf(name))
		}
	}
}

// TestValkeyMaintenanceKillsAScriptThatHoldsTheServer runs maintain.sh against a server that, unlike the
// Compose one, lets a user EVAL, starts a script that never ends and requires the loop to end it. The
// Compose ACL makes that impossible for a service; this is the second line, for a stuck script of any
// origin (admin-r13-5).
func TestValkeyMaintenanceKillsAScriptThatHoldsTheServer(t *testing.T) {
	name, addr := maintainedValkey(t, "", false)
	waitHealthy(t, name, maintMarker)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Username: "loop", Password: "x", DisableCache: true})
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	defer c.Close()
	// The loop is up first: the scripts it loads are known to the server.
	if n, err := c.Do(ctx, c.B().Arbitrary("SCRIPT", "EXISTS").Args(luaSHA(t, "take.lua"), luaSHA(t, "give.lua")).Build()).AsIntSlice(); err != nil || len(n) != 2 || n[0] != 1 || n[1] != 1 {
		t.Fatalf("SCRIPT EXISTS = %v (%v): maintain.sh did not load both scripts", n, err)
	}
	evalEnded := make(chan error, 1)
	go func() {
		// Never answers by itself; it ends when the server kills the script.
		evalEnded <- c.Do(ctx, c.B().Eval().Script("while true do end").Numkeys(0).Build()).Error()
	}()
	// A client with its own connection sees BUSY, and then PONG once the loop has ended the script.
	// The BUSY window is the time between the server's busy threshold (500 ms) and the next tick of
	// the loop (1 s), so it is anywhere from a few milliseconds to a second wide, and a probe every
	// 300 ms missed it in about three runs in ten (round 13, CI run: the log showed the script killed
	// 32 ms after the threshold). BUSY seen by a probe is therefore not what the test depends on.
	// What it proves is read from what cannot be missed: the script's own EVAL ends with a kill, the
	// server's log names the slow script (the moment it starts answering BUSY), and a client gets
	// PONG afterwards. The probe still runs, quickly, and reports what it saw.
	probe := func() string {
		d, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Username: "loop", Password: "x", DisableCache: true, DisableRetry: true})
		if err != nil {
			return "dial: " + err.Error()
		}
		defer d.Close()
		if err := d.Do(ctx, d.B().Ping().Build()).Error(); err != nil {
			return err.Error()
		}
		return "PONG"
	}
	deadline := time.After(30 * time.Second)
	sawBusy := false
	var evalErr error
wait:
	for {
		select {
		case evalErr = <-evalEnded:
			break wait
		case <-deadline:
			t.Fatalf("the script was never killed (saw BUSY: %v); log:\n%s", sawBusy, logsOf(name))
		case <-time.After(20 * time.Millisecond):
			if strings.Contains(probe(), "BUSY") {
				sawBusy = true
			}
		}
	}
	if evalErr == nil || !strings.Contains(strings.ToLower(evalErr.Error()), "kill") {
		t.Fatalf("the script ended with %v, want it killed by the loop", evalErr)
	}
	if !strings.Contains(logsOf(name), "Slow script detected") {
		t.Errorf("the server never reported the script as slow, so it never held the server; log:\n%s", logsOf(name))
	}
	released := false
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && !released; time.Sleep(100 * time.Millisecond) {
		released = probe() == "PONG"
	}
	if !released {
		t.Fatalf("the server did not answer PONG after the script was killed (saw BUSY: %v)", sawBusy)
	}
	t.Logf("script killed by the loop; a probe saw BUSY: %v", sawBusy)
}

// TestValkeyMaintenanceRestartsAServerThatHoldsAScriptThatHasWritten is admin-r14-1 and admin-r14-5.
// SCRIPT KILL cannot stop a script that has written: the server answers UNKILLABLE, and valkey-cli
// exits 0 on that reply, so a loop that judged the exit status never reached SHUTDOWN NOSAVE and the
// server stayed BUSY until the script ended by itself, which a Lua loop does not. The script here
// writes first and then spins. The loop has to read the reply and shut the server down, and the
// container, which has the restart policy of the Compose file, has to come back with its scripts.
func TestValkeyMaintenanceRestartsAServerThatHoldsAScriptThatHasWritten(t *testing.T) {
	name, addr := maintainedValkey(t, "", true)
	waitHealthy(t, name, maintMarker)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Username: "loop", Password: "x", DisableCache: true, DisableRetry: true})
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	defer c.Close()
	evalEnded := make(chan error, 1)
	go func() {
		evalEnded <- c.Do(ctx, c.B().Eval().Script("redis.call('SET','held','1') while true do end").Numkeys(0).Build()).Error()
	}()
	select {
	case err := <-evalEnded:
		// The server went away under the call: a closed connection, not a kill (a script that has
		// written cannot be killed, so an answer that names a kill would be another case).
		if err == nil {
			t.Fatal("the spinning script returned a value")
		}
		if strings.Contains(strings.ToLower(err.Error()), "killed") {
			t.Fatalf("a script that has written was killed (%v); the case under test is the unkillable one", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatalf("the server was never restarted; log:\n%s", logsOf(name))
	}
	if !strings.Contains(logsOf(name), "cannot be killed") {
		t.Errorf("the loop did not report the unkillable script; log:\n%s", logsOf(name))
	}
	var restarts string
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(300 * time.Millisecond) {
		out, _ := exec.Command("docker", "inspect", "-f", "{{.RestartCount}}", name).CombinedOutput()
		if restarts = strings.TrimSpace(string(out)); restarts != "" && restarts != "0" {
			break
		}
	}
	if restarts == "" || restarts == "0" {
		t.Fatalf("the container was not restarted (RestartCount %q); log:\n%s", restarts, logsOf(name))
	}
	// The fresh server loads the scripts again and answers.
	waitHealthy(t, name, maintMarker)
}

// TestValkeyMaintenanceDoesNotCallBrokenScriptsLoaded is the other half of admin-r14-1: a SCRIPT LOAD that
// the server answers with an error exits 0 as well, so the loop wrote its marker, and the container went
// healthy, with a script unknown. A directory holding one file that does not compile must keep the
// marker away and say which file, and the marker must come once the file is gone.
func TestValkeyMaintenanceDoesNotCallBrokenScriptsLoaded(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"take.lua", "give.lua"} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "ratelimit", "lua", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bad := filepath.Join(dir, "bad.lua")
	if err := os.WriteFile(bad, []byte("this is not lua ("), 0o644); err != nil {
		t.Fatal(err)
	}
	name, _ := maintainedValkey(t, dir, false)
	waitLog(t, name, "did not load: bad.lua", 30*time.Second)
	// Several rounds of the loop (one second each) pass and the marker still is not there.
	time.Sleep(4 * time.Second)
	if err := exec.Command("docker", "exec", name, "sh", "-c", maintMarker).Run(); err == nil {
		t.Fatalf("the marker exists although bad.lua does not load; log:\n%s", logsOf(name))
	}
	if strings.Contains(logsOf(name), "limiter scripts are loaded") {
		t.Fatalf("the loop said the scripts are loaded; log:\n%s", logsOf(name))
	}
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}
	waitHealthy(t, name, maintMarker)
}

// TestMaintainScriptKeepsItsPasswordOutOfEveryLongRunningProcess reads what the container shows of the
// maintenance password once the loop is running (admin-r14-8): not the command line of any process, not
// the environment of any process but a valkey-cli that lives for one command, and not the file it was
// handed over in. The bracket in the pattern keeps this very command from matching itself.
func TestMaintainScriptKeepsItsPasswordOutOfEveryLongRunningProcess(t *testing.T) {
	name, _ := maintainedValkey(t, "", false)
	waitHealthy(t, name, maintMarker)
	out, err := exec.Command("docker", "exec", name, "sh", "-c",
		`for p in /proc/[0-9]*; do
  tr '\0' ' ' 2>/dev/null < $p/cmdline | grep -q 'maint[p]w' && echo "cmdline $p"
  if tr '\0' '\n' 2>/dev/null < $p/environ | grep -q 'maint[p]w'; then echo "environ $p $(tr '\0' ' ' 2>/dev/null < $p/cmdline)"; fi
done
test -e /tmp/maint.pw && echo "file left"
true`).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec: %v\n%s", err, out)
	}
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case ln == "":
		case strings.HasPrefix(ln, "environ ") && strings.Contains(ln, "valkey-cli"):
			// A valkey-cli of the loop, caught in the one command it lives for.
		default:
			t.Errorf("the maintenance password is exposed: %s", ln)
		}
	}
}

// TestValkeyServicesCannotHoldTheServerWithEvalsha is admin-r14-4. Round 13 took EVAL away from both
// service users, but they still run take.lua and give.lua by SHA, the digests are public, and the
// scripts looped over as many keys as the caller sent: a caller with a service credential could keep Valkey
// BUSY for seconds per call, with no way to kill it once it had written, or give keys a lifetime of years.
// The scripts now refuse a call outside the bounds of the Go limiter before they read anything, for both users
// and both scripts, and the refusal costs next to nothing.
func TestValkeyServicesCannotHoldTheServerWithEvalsha(t *testing.T) {
	const apiPW, adminPW = "Zq3vNn7hQw1xKs9dApi", "Hk8mTr2vBc5yLp4wAdm"
	name, probe, hostAddr := startValkeyACL(t, apiPW, adminPW)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, who := range []struct{ user, pw string }{{"api", apiPW}, {"admin", adminPW}} {
		c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{hostAddr()}, Username: who.user, Password: who.pw, DisableCache: true})
		if err != nil {
			t.Fatalf("sign in as %q: %v", who.user, err)
		}
		defer c.Close()
		for _, file := range []string{"take.lua", "give.lua"} {
			sha := luaSHA(t, file)
			call := func(keys, argv []string) (time.Duration, error) {
				start := time.Now()
				err := c.Do(ctx, c.B().Evalsha().Sha1(sha).Numkeys(int64(len(keys))).Key(keys...).Arg(argv...).Build()).Error()
				return time.Since(start), err
			}
			prefix := "ctrlz:rl:" + who.user + ":flood:"
			var keys, argv []string
			for i := 0; i < 20000; i++ {
				keys = append(keys, prefix+fmt.Sprint(i))
				argv = append(argv, "100", "60000")
			}
			for name, tc := range map[string]struct{ keys, argv []string }{
				"twenty thousand keys":      {keys, argv},
				"a huge period":             {keys[:1], []string{"100", "9999999999999"}},
				"a huge capacity":           {keys[:1], []string{"999999999", "60000"}},
				"arguments that fall short": {keys[:3], argv[:2]},
			} {
				took, err := call(tc.keys, tc.argv)
				if err == nil || !strings.Contains(err.Error(), "limiter") {
					t.Errorf("%s %s %s: the call was not refused by the script: %v", who.user, file, name, err)
				}
				// A script that had looped over the keys would have held the server for seconds.
				if took > 2*time.Second {
					t.Errorf("%s %s %s: the refusal took %v", who.user, file, name, took)
				}
			}
			// A call of the size the limiter sends still works, and the server answers at once after the flood.
			if _, err := call([]string{prefix + "ok"}, []string{"5", "60000"}); err != nil {
				t.Errorf("%s %s: a call inside the bounds was refused: %v", who.user, file, err)
			}
		}
	}
	waitHealthy(t, name, probe)
}
