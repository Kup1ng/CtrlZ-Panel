package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// healthMux builds the one health mux of a process: /healthz names the role and the release, and
// /readyz takes a connection of the role's pool. Neither has authentication or a rate limit, so the
// mux leaves this function only as an httpx.Health, whose one way out is behind the peer check (rule
// 28, admin-r12-2). It is also the only place in the module that registers these paths; the lint
// TestHealthMuxHasOneExposureGate fails for a second one.
func healthMux(role Role, st *store.Store) httpx.Health {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","role":%q,"version":%q}`+"\n", string(role), Version)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			http.Error(w, "no database configured", http.StatusServiceUnavailable)
			return
		}
		pctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Ping(pctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
	})
	return httpx.NewHealth(mux)
}
