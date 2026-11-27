package deploy

import (
	"strings"
	"testing"
	"time"
)

// TestStaleContainersKeepsEveryYoungOneAndAnythingThatIsNotATestContainer: this machine runs several test
// runs at once and they use the same names and labels, so the janitor's only protection for a live run is the
// age floor of each rule. A container that is young for its state must never be listed, whatever it is called.
func TestStaleContainersKeepsEveryYoungOneAndAnythingThatIsNotATestContainer(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02 15:04:05 -0700 MST") }
	line := func(id, name, state string, age time.Duration, labels string) string {
		return strings.Join([]string{id, name, state, ago(age), labels}, "\t")
	}
	out := strings.Join([]string{
		line("c1", "ctrlz-valkey-acl-0123456789abcdef", "created", time.Hour, ""),           // created, old: removed
		line("c2", "ctrlz-valkey-acl-00000000000000a2", "created", time.Minute, ""),         // created, 1 minute: kept
		line("c3", "ctrlz-valkey-maint-00000000000000b3", "running", 30*time.Minute, ""),    // running 30 minutes: kept
		line("c4", "ctrlz-valkey-maint-00000000000000c4", "running", 4*time.Hour, ""),       // running 4 hours: removed
		line("c5", "postgres-keep", "exited", 10*24*time.Hour, "a=b"),                       // unrelated name: kept
		line("c6", "restarter", "exited", 2*time.Hour, "x=y,ctrlz.test=valkey"),             // label, exited, stop time unknown here: kept (see TestStaleContainersJudgesAStoppedOneByWhenItStopped)
		line("c7", "restarter2", "running", time.Hour, "ctrlz.test=valkey"),                 // label, running 1 hour: kept
		line("c8", "reaper_abc", "created", 20*time.Minute, "org.testcontainers=true"),      // testcontainers, created, old: removed
		line("c9", "reaper_def", "created", 5*time.Minute, "org.testcontainers=true"),       // testcontainers, young: kept
		line("c10", "magical_yonath", "running", 52*time.Minute, "org.testcontainers=true"), // running 52 minutes: kept
		line("c11", "other", "exited", 9*time.Hour, "org.testcontainers.sessionId=1"),       // a label that only starts like one: kept
		// The Compose stack's own Valkey servers (project ctrlz): old, running or stopped, they are never listed, by name
		// or with a test label on them.
		line("c13", "ctrlz-valkey-api-1", "running", 30*24*time.Hour, "com.docker.compose.project=ctrlz,com.docker.compose.service=valkey-api"), // the real server: kept
		line("c14", "ctrlz-valkey-admin-1", "exited", 3*time.Hour, "com.docker.compose.project=ctrlz"),                                          // the real server, stopped: kept
		line("c15", "ctrlz-valkey-admin-2", "running", 4*time.Hour, ""),                                                                         // a prefix and not a helper's name: kept
		line("c16", "x", "exited", 3*time.Hour, "ctrlz.test=valkey,com.docker.compose.project=other"),                                           // compose label wins over the test label: kept
		"garbage without tabs",
		"c12\tname\texited\tnot a date\torg.testcontainers=true",
	}, "\n")
	got := strings.Join(staleContainers(parseContainers(out), now), " ")
	if want := "c1 c4 c8"; got != want {
		t.Errorf("removed %q, want %q", got, want)
	}
}

// TestParseContainersReadsTheCreatedAtOfDocker: the zone is written twice by docker ("+0330 +0330").
func TestParseContainersReadsTheCreatedAtOfDocker(t *testing.T) {
	cs := parseContainers("abc\tn\texited\t2026-11-23 01:23:25 +0330 +0330\tk=v\n")
	if len(cs) != 1 {
		t.Fatalf("parsed %d containers", len(cs))
	}
	if want := time.Date(2026, 11, 22, 21, 53, 25, 0, time.UTC); !cs[0].Created.Equal(want) {
		t.Errorf("created %v, want %v", cs[0].Created, want)
	}
}

// TestStaleContainersJudgesAStoppedOneByWhenItStopped: internal/testpg stops a Postgres container that is many
// minutes old and starts it again seconds later. For those seconds it is exited with an old creation time, and
// another run's janitor must not take it (admin-r23-1). Before the fix the age was the creation age.
func TestStaleContainersJudgesAStoppedOneByWhenItStopped(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Hour)
	cs := []testContainer{
		{ID: "a", Name: "x", State: "exited", Labels: "org.testcontainers=true", Created: old, Stopped: now.Add(-4 * time.Second)},  // a fault test's stop window: kept
		{ID: "b", Name: "x", State: "exited", Labels: "org.testcontainers=true", Created: old, Stopped: now.Add(-20 * time.Minute)}, // stopped long ago: removed
		{ID: "c", Name: "x", State: "dead", Labels: "org.testcontainers=true", Created: old},                                        // stop time unknown: kept
		{ID: "d", Name: "x", State: "dead", Labels: "org.testcontainers=true", Created: old, Stopped: now.Add(-time.Hour)},          // dead for an hour: removed
	}
	if got, want := strings.Join(staleContainers(cs, now), " "), "b d"; got != want {
		t.Errorf("removed %q, want %q", got, want)
	}
}

// TestParseStoppedReadsFinishedAt: Docker prints RFC 3339 with nanoseconds, and a year 1 time for "never".
func TestParseStoppedReadsFinishedAt(t *testing.T) {
	m := parseStopped("id1\t2026-11-23T08:30:25.123456789Z\nid2\t0001-01-01T00:00:00Z\nid3\tgarbage\nbad line\n")
	if len(m) != 1 {
		t.Fatalf("parsed %v", m)
	}
	if want := time.Date(2026, 11, 23, 8, 30, 25, 123456789, time.UTC); !m["id1"].Equal(want) {
		t.Errorf("id1 stopped %v, want %v", m["id1"], want)
	}
}
