package deploy

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
)

// The janitor of the test containers. A test that starts a container removes it in t.Cleanup, and a test
// binary that is killed, or that hits `go test -timeout`, never runs that. The containers then stay, and the
// Valkey ones kept sweeping their keyspace for days (13 of them were found at 100 to 119 percent CPU), which
// is also what made later timing tests flaky. The containers carry a lifetime of their own now (see
// internal/lint, startValkeyACL), but a container made before that, or by a helper that cannot carry one
// (the testcontainers ones), still needs somebody to remove it, and the next test run on the machine is the
// one that is there.
//
// This machine is shared: other runs start containers with the same names and labels at the same time. So
// every rule has an age floor, and a container younger than its floor is never touched, whatever it is named.

const (
	// A container that never ran or that has stopped is of no use to anybody after a quarter of an hour: a
	// helper that creates one starts it at once, and a test that reads a stopped one does so within a minute.
	staleStopped = 15 * time.Minute
	// A running one is removed only after a time longer than any test run on this machine (the whole of
	// internal/lint takes under an hour), so a container that a live run still uses is not taken from it.
	staleRunning = 3 * time.Hour
)

// testContainer is one line of `docker ps -a`, as far as the janitor reads it.
type testContainer struct {
	ID, Name, State, Labels string
	Created                 time.Time
	// Stopped is when an exited or dead container stopped, read from `docker inspect` (State.FinishedAt). The zero
	// time means it is not known. Created is no measure of a stopped container's age: internal/testpg stops a
	// Postgres container that is already many minutes old and starts it again a few seconds later, and for those
	// seconds it is "exited" with an old creation time.
	Stopped time.Time
}

// psFormat is the template the janitor asks `docker ps` for: one tab-separated line per container.
const psFormat = "{{.ID}}\t{{.Names}}\t{{.State}}\t{{.CreatedAt}}\t{{.Labels}}"

// parseContainers reads the lines of `docker ps -a --format psFormat`. A line it cannot read is skipped: the
// janitor removes only what it understood.
func parseContainers(out string) []testContainer {
	var cs []testContainer
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) < 5 {
			continue
		}
		// CreatedAt reads "2026-11-23 01:23:25 +0330 +0330": the zone is written twice, once as an offset and
		// once as the abbreviation, and the abbreviation of a zone with none is the offset again, which time.Parse
		// does not take. The first three fields are all there is to read.
		parts := strings.Fields(f[3])
		if len(parts) < 3 {
			continue
		}
		created, err := time.Parse("2006-01-02 15:04:05 -0700", strings.Join(parts[:3], " "))
		if err != nil {
			continue
		}
		cs = append(cs, testContainer{ID: f[0], Name: f[1], State: f[2], Created: created, Labels: f[4]})
	}
	return cs
}

// helperName is the exact shape of the names the helpers of internal/lint give their containers (acl, maint,
// pace, cal and 16 hex digits). A prefix would also match ctrlz-valkey-api-1 and ctrlz-valkey-admin-1, the names
// Compose gives the real Valkey servers of the stack (project ctrlz, services valkey-api and valkey-admin), which
// a developer who runs the stack and the tests on one machine must never lose to a janitor.
var helperName = regexp.MustCompile(`^ctrlz-valkey-(acl|maint|pace|cal)-[0-9a-f]{16}$`)

// isTestContainer says whether the container is one a test helper starts: by the exact name a helper gives, by
// the label the helpers of internal/lint put on the ones that cannot be --rm, or by the label testcontainers puts
// on its own. A container that belongs to a Compose project is never one: whatever its name or labels say, it is
// somebody's stack and not a leftover.
func isTestContainer(c testContainer) bool {
	labelled := false
	for _, l := range strings.Split(c.Labels, ",") {
		switch {
		case strings.HasPrefix(l, "com.docker.compose."):
			return false
		case l == "ctrlz.test=valkey" || l == "org.testcontainers=true":
			labelled = true
		}
	}
	return labelled || helperName.MatchString(c.Name)
}

// stoppedState says whether the container has run and stopped, which is the state whose age is the time since it
// stopped and not the time since it was made.
func stoppedState(c testContainer) bool { return c.State == "exited" || c.State == "dead" }

// staleContainers returns the ids the janitor removes at the time now: the containers of the test helpers that
// are created and older than staleStopped, or exited or dead and stopped longer ago than staleStopped, or in any
// other state (running, paused, restarting) and older than staleRunning. A stopped container whose stop time
// is not known is kept: removing a live run's container is worse than leaving a dead one for the next sweep.
func staleContainers(cs []testContainer, now time.Time) []string {
	var ids []string
	for _, c := range cs {
		if !isTestContainer(c) {
			continue
		}
		age := now.Sub(c.Created)
		floor := staleRunning
		switch {
		case stoppedState(c):
			if c.Stopped.IsZero() {
				continue
			}
			age, floor = now.Sub(c.Stopped), staleStopped
		case c.State == "created":
			floor = staleStopped
		}
		if age >= floor {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// inspectFormat prints the full id and the stop time of a container, tab-separated.
const inspectFormat = "{{.ID}}\t{{.State.FinishedAt}}"

// parseStopped reads the lines of `docker inspect --format inspectFormat` into the stop time of each id.
// FinishedAt is RFC 3339 with nanoseconds; "0001-01-01T00:00:00Z" is Docker's word for "never", and it, like a
// line that cannot be read, leaves the id out.
func parseStopped(out string) map[string]time.Time {
	m := map[string]time.Time{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) != 2 {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, f[1])
		if err != nil || t.Year() < 2000 {
			continue
		}
		m[f[0]] = t
	}
	return m
}

// withStopTimes fills Stopped of the test containers that are exited or dead and old enough by creation to be
// candidates at all (a container younger than the floor cannot have been stopped longer than it), with one
// `docker inspect` for all of them. An inspect that fails leaves them at zero, so they are kept.
func withStopTimes(ctx context.Context, cs []testContainer, now time.Time) {
	var ids []string
	for _, c := range cs {
		if isTestContainer(c) && stoppedState(c) && now.Sub(c.Created) >= staleStopped {
			ids = append(ids, c.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	// A container that vanished between ps and inspect makes inspect exit non-zero, but the others are printed.
	out, _ := Docker(ctx, append([]string{"inspect", "--format", inspectFormat}, ids...)...).Output()
	stopped := parseStopped(string(out))
	for i := range cs {
		cs[i].Stopped = stopped[cs[i].ID]
	}
}

// RemoveStaleTestContainers removes the leftovers of test runs that ended without cleaning up. It runs once
// in a process (the first helper that starts a container calls it) and is best effort: it says nothing and
// fails nothing, because a test that needs a container must not be stopped by the tidying of earlier ones. It
// uses only the verbs Docker allows (ps and rm). It takes no context: it is once for the process, so no
// caller's deadline may bound it, and it keeps its own (a minute).
func RemoveStaleTestContainers() { _ = staleSweep() }

// staleSweep is the once. A sync.OnceValue and not a Once in a variable: the rule against package-level mutable
// state lets a value made once stand, and the sweep has nothing to return.
var staleSweep = sync.OnceValue(func() struct{} {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := Docker(ctx, "ps", "-a", "--no-trunc", "--format", psFormat).Output()
	if err != nil {
		return struct{}{}
	}
	now := appclock.Now()
	cs := parseContainers(string(out))
	withStopTimes(ctx, cs, now)
	// -v takes the anonymous volumes a Postgres container declares (testcontainers removes them on Terminate; a
	// leaked one would otherwise leave them behind). It never takes a named volume or a bind mount.
	if ids := staleContainers(cs, now); len(ids) > 0 {
		_ = Docker(ctx, append([]string{"rm", "-f", "-v"}, ids...)...).Run()
	}
	return struct{}{}
})
