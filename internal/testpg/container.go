package testpg

import (
	"context"
	"io"

	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

// CopyIn writes a file into the server's container, for the test that runs a script of
// deploy/compose/postgres the way the container does.
func (c *Cluster) CopyIn(ctx context.Context, path string, content []byte, mode int64) error {
	return c.container.CopyToContainer(ctx, content, path, mode)
}

// Exec runs a command in the server's container as user (empty is the image's user), with extra
// variables for the process ("NAME=value"), and returns its output (stdout and stderr together) and
// exit code. It is for the scripts the Compose file runs beside Postgres, which no Go code reaches.
func (c *Cluster) Exec(ctx context.Context, user string, vars []string, cmd ...string) (string, int, error) {
	opts := []tcexec.ProcessOption{tcexec.Multiplexed()}
	if user != "" {
		opts = append(opts, tcexec.WithUser(user))
	}
	if len(vars) > 0 {
		opts = append(opts, tcexec.WithEnv(vars))
	}
	code, r, err := c.container.Exec(ctx, cmd, opts...)
	if err != nil {
		return "", code, err
	}
	b, err := io.ReadAll(r)
	return string(b), code, err
}
