package lint_test

import (
	"context"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
)

// What every Valkey container of these tests carries so that none outlives its test (the leak that left 13
// containers sweeping at full CPU for days). t.Cleanup is the first line, and it does not run when the test
// binary is killed or hits `go test -timeout`; the other three are made so that it does not have to:
//   - --rm, where the test does not need the stopped container, removes the container when it ends;
//     (a restart policy cannot have it, and `timeout` ending its command only restarts it: that variant has the
//     label and the janitor, and its keyspace is empty after each start);
//   - testLifetime is a lifetime inside the container: the command runs under `timeout`, which ends its
//     process group (the server and the maintenance loop) after that many seconds, so the container stops an
//     hour after it started whatever happened to the test binary;
//   - testContainerLabel marks the ones that cannot be --rm (a restart policy, a container read after it
//     stopped) for deploy.RemoveStaleTestContainers, which the next test run starts with.
const (
	testContainerLabel = "ctrlz.test=valkey"
	testLifetime       = "3600"
)

// removeOnCleanup registers the removal of a container before it is started: a docker run that fails after
// the daemon created the container (a port that would not bind, a CLI timeout) still leaves one to remove,
// and a cleanup registered after the error check never saw it. Removing what does not exist is an error that
// is ignored.
func removeOnCleanup(t *testing.T, name string) {
	t.Helper()
	t.Cleanup(func() { _ = deploy.Docker(context.Background(), "rm", "-f", name).Run() })
}
