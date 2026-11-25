package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Version is the build label reported by /healthz. A real release label
// arrives with the installer in P7.
const Version = "p0"

// Options are the parts of a process's surroundings that tests replace.
type Options struct {
	Getenv Getenv
	Stdout io.Writer
	// Ready, if set, receives the listen address once the server is up.
	Ready chan<- string
}

// Run starts a role and returns when ctx is cancelled or the role fails.
func Run(ctx context.Context, role Role, opts Options) error {
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	// JSON logs on stdout, where Docker rotates them. There is no access log
	// and no request URL is ever logged: a URL can carry a token (R21).
	log := slog.New(slog.NewJSONHandler(opts.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With(logattr.Enum("role", role))

	cfg, err := LoadConfig(role, opts.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if role == RoleMigrate {
		return runMigrate(ctx, cfg, log)
	}
	// Before anything connects: a process that would serve only the unauthenticated health mux does
	// not listen where a peer or the internet can reach it (admin-r10-4).
	if err := requireLoopbackIfHealthOnly(cfg, cfg.DBHost != ""); err != nil {
		return err
	}

	rt, err := newRuntime(cfg, log, false)
	if err != nil {
		return err
	}
	// rt.Keys and rt.Hasher reach the api and admin routers in serviceHandler; the
	// worker takes its keys in startWorker.

	var st, compiler *store.Store
	if cfg.DBHost != "" {
		lazy := false
		st, err = store.Open(ctx, cfg.storeConfig(store.Role(role.dbRole()), cfg.DBPassword))
		if err != nil && errors.Is(err, store.ErrConnection) && role != RoleWorker {
			// The database is down or still starting. The HTTP roles stay up and
			// answer 503 (readyz too) until it returns, instead of exiting into a
			// restart loop that hides the cause (spec 18.3). A wrong password or
			// the wrong role is not ErrConnection and still stops here. The worker
			// keeps exiting: its loops need the database from their first pass, and
			// Compose restarts it.
			log.Warn("database unreachable at start; serving 503 until it returns", logattr.Enum("db_role", role.dbRole()))
			st, err = store.OpenLazy(ctx, cfg.storeConfig(store.Role(role.dbRole()), cfg.DBPassword))
			lazy = true
		}
		if err != nil {
			return fmt.Errorf("database: %w", err)
		}
		defer st.Close()
		// One line for what happened. The lazy open made no connection, and the line above already
		// said so; a second one that said "connected" was false and was read as a start signal by
		// operators and by scripts/compose-smoke.sh (round 5, admin-r5-8).
		if lazy {
			log.Info("database not connected yet; the pool connects on first use", logattr.Enum("db_role", role.dbRole()))
		} else {
			log.Info("database connected", logattr.Enum("db_role", role.dbRole()))
		}
		if role == RoleWorker && !cfg.CompilerPassword.IsZero() {
			compiler, err = store.Open(ctx, cfg.storeConfig(store.RoleCompiler, cfg.CompilerPassword))
			if err != nil {
				return fmt.Errorf("compiler database: %w", err)
			}
			defer compiler.Close()
			log.Info("compiler pool connected", logattr.Enum("db_role", dbRoleName("ctrlz_compiler")))
		}
	} else {
		log.Warn("no database configured; running as a stub")
	}
	if role == RoleWorker && st != nil {
		stop, err := startWorker(ctx, cfg, rt, st, compiler, log)
		if err != nil {
			return fmt.Errorf("worker: %w", err)
		}
		defer stop(cfg.ShutdownTimeout)
	}

	// The api and admin roles serve their routes through the request pipeline of
	// spec 2.3; every other role serves the health mux alone.
	handler, closeHTTP, err := serviceHandler(cfg, rt, st, log, healthMux(role, st))
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer closeHTTP()

	srv := &http.Server{
		Handler:           recoverer(log, handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// The server's own error log would print request lines and peer
		// addresses on a bad request; this one keeps only the class of each.
		ErrorLog: httpx.ErrorLog(log),
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	log.Info("started", logattr.Addr("listen", listenAddr(ln)), logattr.Release(Version))
	if opts.Ready != nil {
		opts.Ready <- ln.Addr().String()
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("stopped")
	return nil
}

// recoverer turns a panic into a 500 without logging the request: a URL or a
// header could hold a token. The panic value is not logged either, since it
// may embed request data.
func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("handler panicked")
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func runMigrate(ctx context.Context, cfg Config, log *slog.Logger) error {
	db, err := migrate.Open(migrate.Config{
		Host: cfg.DBHost, Port: cfg.DBPort, Database: cfg.DBName,
		User: string(cfg.Role.dbRole()), Password: cfg.DBPassword.Reveal(), SSLMode: cfg.DBSSLMode,
	})
	if err != nil {
		return err
	}
	defer db.Close()
	// Roles start in no fixed order, and Postgres may still be finishing its
	// first-start initialisation. Wait for it instead of failing the stack.
	if err := migrate.WaitReady(ctx, db, 60*time.Second, func() { log.Info("waiting for the database") }); err != nil {
		return err
	}
	n, err := migrate.Up(ctx, db)
	if err != nil {
		return err
	}
	log.Info("migrations applied", logattr.Int("count", n))
	// The bootstrap's revokes run once, so an upgraded install is asked, on every start, whether
	// the database is closed the way the migrations assume (db-r15-2, db-r15-8).
	if err := migrate.CheckReach(ctx, db); err != nil {
		return err
	}
	return nil
}

// HealthCheck fetches url and reports whether it answered 200. The container
// healthcheck uses it, because the runtime image has no curl.
func HealthCheck(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.New("health check failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check: status %d", resp.StatusCode)
	}
	return nil
}

// listenAddr is the address a listener is bound to, as a number and a port. A
// listener that is not TCP has none, and the zero value logs as "invalid AddrPort".
func listenAddr(ln net.Listener) netip.AddrPort {
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		return a.AddrPort()
	}
	return netip.AddrPort{}
}
