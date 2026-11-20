// Package testvalkey starts a real Valkey in a container for tests of the rate
// limiter. Like testpg it fakes nothing: the token bucket is a Lua script, and
// only the real server can say whether it is atomic and whether the clock it
// reads is the server's.
package testvalkey

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
)

// Image is the Valkey under test: the reference docker-compose.yml pins, read through deploy.Image so
// this package keeps no tag of its own (round 16, admin-r16-15).
func Image() string { return deploy.Image("VALKEY_IMAGE") }

// Server is a running container.
type Server struct {
	c    testcontainers.Container
	Addr string // host:port reachable from the test
}

// startAttempts: see testpg.PortTaken, which explains why a port that was free
// when freePort looked can be gone when Docker binds it. The check is repeated
// here rather than imported: testpg pulls in the store and the migrator, which
// a rate limiter test has no business linking.
const startAttempts = 5

func portTaken(err error) bool {
	if err == nil {
		return false
	}
	m := err.Error()
	return strings.Contains(m, "address already in use") || strings.Contains(m, "port is already allocated")
}

// Start runs Valkey and waits until it answers. A host port taken between the
// choice and the bind is retried with another one.
func Start(ctx context.Context) (*Server, error) {
	var err error
	for attempt := 0; attempt < startAttempts; attempt++ {
		var s *Server
		if s, err = start(ctx); err == nil || !portTaken(err) {
			return s, err
		}
	}
	return nil, err
}

func start(ctx context.Context) (*Server, error) {
	// A fixed host port, as testpg does: a stopped container that is started
	// again keeps its address, so a client built before the outage finds the
	// server where it was (the "Valkey back" row of spec 18.3).
	hostPort, err := freePort()
	if err != nil {
		return nil, err
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        Image(),
			ExposedPorts: []string{"6379/tcp"},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.PortBindings = network.PortMap{network.MustParsePort("6379/tcp"): {{HostPort: strconv.Itoa(hostPort)}}}
			},
			WaitingFor: wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		if c != nil {
			_ = c.Terminate(ctx)
		}
		return nil, err
	}
	host, err := c.Host(ctx)
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, err
	}
	if host == "localhost" { // see testpg: the resolver is slow under load
		host = "127.0.0.1"
	}
	port, err := c.MappedPort(ctx, "6379/tcp")
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, err
	}
	_ = port
	return &Server{c: c, Addr: fmt.Sprintf("%s:%d", host, hostPort)}, nil
}

// Stop and Resume simulate an outage without losing the address: the container
// is paused, so connections hang the way they do when a host drops packets.
func (s *Server) Stop(ctx context.Context) error {
	d := 5 * time.Second
	return s.c.Stop(ctx, &d)
}

// Resume starts a stopped server again on the same address.
func (s *Server) Resume(ctx context.Context) error {
	if err := s.c.Start(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", s.Addr, time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("valkey did not come back: %w", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Terminate removes the container.
func (s *Server) Terminate(ctx context.Context) error { return s.c.Terminate(ctx) }

// RunMain is a TestMain body: it starts Valkey unless -short is set, hands it to
// use, runs the tests and removes the container. A missing Docker is a failure.
func RunMain(m *testing.M, use func(*Server)) int {
	flag.Parse()
	if testing.Short() {
		return m.Run()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	s, err := Start(ctx)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testvalkey: cannot start Valkey (Docker is required; use -short to skip): %v\n", err)
		return 1
	}
	use(s)
	code := m.Run()
	tctx, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer tcancel()
	_ = s.Terminate(tctx)
	return code
}
