package store_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestOpenCallsASilentServerUnreachable: a server that accepts the TCP connection
// and never answers the startup packet (a stopped container behind a port proxy
// does exactly this on some hosts) must read as ErrConnection, the same as a
// refused connection. The service starts lazily on ErrConnection (spec 18.3,
// "Postgres down at start"); before this the connect timeout surfaced as a bare
// context.DeadlineExceeded, the service exited, and TestPostgresDownAtStart failed
// in the one CI run where Docker's proxy hung instead of refusing.
func TestOpenCallsASilentServerUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer func() { close(done) }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { <-done; c.Close() }()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	cfg := store.Config{
		Host:           "127.0.0.1",
		Port:           uint16(addr.Port),
		Database:       "ctrlz",
		Role:           store.RoleTenant,
		Password:       secret.New("x"),
		ConnectTimeout: 300 * time.Millisecond,
	}
	start := time.Now()
	_, err = store.Open(context.Background(), cfg)
	if err == nil {
		t.Fatal("Open succeeded against a server that never answers")
	}
	if !errors.Is(err, store.ErrConnection) {
		t.Errorf("a silent server is not ErrConnection: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("Open took %v with a 300 ms connect timeout", time.Since(start))
	}

	// The caller's own deadline or cancel is not the server's fault and must stay as it was.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Open(ctx, cfg); errors.Is(err, store.ErrConnection) {
		t.Errorf("a cancelled caller was reported as a database outage: %v", err)
	}
}
