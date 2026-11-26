package testpg

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"
)

// Wiring is a Postgres container started the way deploy/compose/docker-compose.yml starts the postgres
// service: the real entrypoint override, the real watchdog script and SQL, the real postgresql.conf and
// pg_hba.conf, at the paths the Compose file mounts them to. It exists because the wiring was the one part
// of the watchdog that no test ran (db-r16-4, db-r16-10): the script and the SQL were tested with
// `docker exec` in a plain server, and everything that decides whether the process runs in production
// (the entrypoint, the signal handling, the healthcheck, the socket and the peer rule) was read, not run.
//
// What differs from Compose, on purpose: the files are copied in rather than mounted, the secrets and
// the initdb hook are left out (POSTGRES_PASSWORD takes their place; the watchdog needs no ctrlz role),
// and the container is not on a network of its own.
type Wiring struct {
	c testcontainers.Container
}

// StartWiring starts the container with env added to the environment the Compose file gives it. repoRoot
// is the root of this repository (the files are read from deploy/compose/postgres).
func StartWiring(ctx context.Context, repoRoot string, env map[string]string) (*Wiring, error) {
	// The reaper testcontainers starts beside this container holds the Docker socket and is named by tag alone:
	// make the local copy of that tag the reviewed bytes first (admin-r17-2, -8).
	deploy.RemoveStaleTestContainers()
	if err := deploy.PinReaper(ctx); err != nil {
		return nil, err
	}
	// The image the rest of the harness starts (testpg.start): the pin by digest has one source, deploy.Image.
	image := DefaultImage()
	var files []testcontainers.ContainerFile
	add := func(host, inContainer string) error {
		b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(host)))
		if err != nil {
			return err
		}
		files = append(files, testcontainers.ContainerFile{Reader: bytes.NewReader(b), ContainerFilePath: inContainer, FileMode: 0o644})
		return nil
	}
	for host, in := range map[string]string{
		"deploy/compose/postgres/entrypoint.sh":   "/ctrlz-postgres/entrypoint.sh",
		"deploy/compose/postgres/watchdog.sh":     "/ctrlz-postgres/watchdog.sh",
		"deploy/compose/postgres/postgresql.conf": "/etc/postgresql/postgresql.conf",
		"deploy/compose/postgres/pg_hba.conf":     "/etc/postgresql/pg_hba.conf",
	} {
		if err := add(host, in); err != nil {
			return nil, err
		}
	}
	sqlText, err := pgmigrations.Bootstrap.ReadFile("bootstrap/watchdog.sql")
	if err != nil {
		return nil, err
	}
	files = append(files, testcontainers.ContainerFile{Reader: bytes.NewReader(sqlText), ContainerFilePath: "/ctrlz-bootstrap/watchdog.sql", FileMode: 0o644})

	vars := map[string]string{"POSTGRES_PASSWORD": randHex(16), "POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres"}
	for k, v := range env {
		vars[k] = v
	}
	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Entrypoint: []string{"sh", "/ctrlz-postgres/entrypoint.sh"},
			Cmd:        []string{"postgres", "-c", "config_file=/etc/postgresql/postgresql.conf"},
			Env:        vars,
			Files:      files,
		},
		Started: true,
	})
	if err != nil {
		if ctr != nil {
			terminateFresh(ctx, ctr)
		}
		return nil, fmt.Errorf("start wiring container: %w", err)
	}
	return &Wiring{c: ctr}, nil
}

// Exec runs a command in the container as user (empty is root, which is what Compose's healthcheck
// runs as) and returns its output and exit code.
func (w *Wiring) Exec(ctx context.Context, user string, cmd ...string) (string, int, error) {
	opts := []tcexec.ProcessOption{tcexec.Multiplexed()}
	if user != "" {
		opts = append(opts, tcexec.WithUser(user))
	}
	code, r, err := w.c.Exec(ctx, cmd, opts...)
	if err != nil {
		return "", code, err
	}
	b, err := io.ReadAll(r)
	return string(b), code, err
}

// Logs returns everything the container has written.
func (w *Wiring) Logs(ctx context.Context) (string, error) {
	rd, err := w.c.Logs(ctx)
	if err != nil {
		return "", err
	}
	defer rd.Close()
	b, err := io.ReadAll(rd)
	return string(b), err
}

// Stop stops the container the way `docker compose stop` does (the image's stop signal, then a kill after
// timeout) and returns the exit code and how long it took.
func (w *Wiring) Stop(ctx context.Context, timeout time.Duration) (int, time.Duration, error) {
	t0 := time.Now()
	if err := w.c.Stop(ctx, &timeout); err != nil {
		return 0, 0, err
	}
	st, err := w.c.State(ctx)
	if err != nil {
		return 0, 0, err
	}
	return st.ExitCode, time.Since(t0), nil
}

// Running reports whether the container is still running, and its exit code when it is not.
func (w *Wiring) Running(ctx context.Context) (bool, int, error) {
	st, err := w.c.State(ctx)
	if err != nil {
		return false, 0, err
	}
	return st.Running, st.ExitCode, nil
}

// Terminate removes the container.
func (w *Wiring) Terminate(ctx context.Context) error { return w.c.Terminate(ctx) }
