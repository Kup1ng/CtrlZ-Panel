package adminapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The overview, the free DNS counters and the free DNS and domain settings (p4-nodes 9.2, 10.4; Plan T-339, T-556).
// Handlers decode, judge and call the store; every write is one transaction with its audit row. None writes
// policy_outbox (T-081): the compiler reads free_dns_settings.version, and the hub and the worker read domain_settings.

const (
	// maxFreeQPS is the ceiling of Plan T-374 until it is measured. The database CHECK allows wire.MaxFreeQPS (50000),
	// so raising the ceiling later is a change of this constant and not of a migration.
	maxFreeQPS = 2000
	// counterWindow is the longest span GET /free-dns/counters answers, a day over the 30 days the worker keeps rows.
	counterWindow = 31 * 24 * time.Hour
	// defaultCounterSpan is the window when `from` is not given.
	defaultCounterSpan = 24 * time.Hour
	counterDefaultPage = 200
	counterMaxPage     = 500
	// defaultTransitionDays is the transition of a zone change when the request names none (D31).
	defaultTransitionDays = 30
	jobDomainChange       = "domain_change"
)

func errQPS() *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeQPSOutOfRange).WithFields(httpx.FieldError{Name: "qps", Code: "out_of_range"})
}

func errDomain(field string) *httpx.Error {
	return httpx.New(http.StatusUnprocessableEntity, httpx.CodeDomainInvalid).WithFields(httpx.FieldError{Name: field, Code: "invalid"})
}

func freeDNSView(f store.FreeDNS) gen.FreeDnsSettings {
	return gen.FreeDnsSettings{Enabled: f.Enabled, Qps: f.QPS, Version: f.Version}
}

// GetOverview is GET /overview.
func (s *Server) GetOverview(ctx context.Context, _ gen.GetOverviewRequestObject) (gen.GetOverviewResponseObject, error) {
	out := gen.Overview{Nodes: []gen.NodeView{}}
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.NodesPage(uuid.Nil, 16)
		if err != nil {
			return err
		}
		if out.ConfigHead, err = g.ConfigHead(); err != nil {
			return err
		}
		f, err := g.FreeDNSGet()
		if err != nil {
			return err
		}
		out.FreeDns = freeDNSView(f)
		for _, r := range rows {
			out.Nodes = append(out.Nodes, nodeView(r))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Qps, out.CacheHitPermille = globalRates(out.Nodes)
	return gen.GetOverview200JSONResponse(out), nil
}

// globalRates are the QPS summed over the active nodes that reported it, and the cache hit rate weighted by each node's
// QPS (a node that answers nothing does not drag the rate), or a plain mean when no node reports a QPS. Both are nil
// until some node has sent a Heartbeat that carries them.
func globalRates(nodes []gen.NodeView) (qps, hit *int) {
	// hitQPS is the QPS of the nodes that also carry a hit rate: the weights of the mean must sum over those nodes only,
	// or a node that reports a QPS and no rate would drag the rate toward zero.
	var sumQPS, hitQPS, weighted, plain, plainN, reported int
	for _, n := range nodes {
		if n.Status != gen.NodeViewStatusActive {
			continue
		}
		if n.Qps != nil {
			sumQPS += *n.Qps
			reported++
		}
		if n.CacheHitPermille != nil {
			plain += *n.CacheHitPermille
			plainN++
			if n.Qps != nil {
				weighted += *n.CacheHitPermille * *n.Qps
				hitQPS += *n.Qps
			}
		}
	}
	if reported > 0 {
		qps = ptr(sumQPS)
	}
	switch {
	case plainN > 0 && hitQPS > 0:
		hit = ptr(weighted / hitQPS)
	case plainN > 0:
		hit = ptr(plain / plainN)
	}
	return qps, hit
}

// counterOutcome is the form of free_dns_counters.outcome (the table's own CHECK). A cursor is text a client chose, so a
// value outside it never reaches Postgres, which would refuse a NUL or invalid UTF-8 as a driver error and answer 500.
var counterOutcome = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// maxCursorSec is the last second of the year 9999: a bucket past it overflows what the driver encodes as a timestamptz.
const maxCursorSec = 253402300799

// counterCursor is the key of the last row of a page: the bucket in Unix seconds, the node, the transport, the outcome
// and the rcode, the five columns of the primary key in the order the page is sorted by.
func counterCursor(c *string) (*store.FreeCounterKey, error) {
	p, err := decodeKey(c, 5)
	if err != nil || p == nil {
		return nil, err
	}
	sec, e1 := strconv.ParseInt(p[0], 10, 64)
	id, e2 := uuid.Parse(p[1])
	rc, e3 := strconv.Atoi(p[4])
	if e1 != nil || e2 != nil || e3 != nil || rc < 0 || rc > 23 || (p[2] != "udp" && p[2] != "tcp") || !counterOutcome.MatchString(p[3]) || sec < 0 || sec > maxCursorSec {
		return nil, httpx.BadRequest()
	}
	return &store.FreeCounterKey{Bucket: time.Unix(sec, 0).UTC(), NodeID: id, Protocol: p[2], Outcome: p[3], RCode: rc}, nil
}

// ListFreeDnsCounters is GET /free-dns/counters.
func (s *Server) ListFreeDnsCounters(ctx context.Context, req gen.ListFreeDnsCountersRequestObject) (gen.ListFreeDnsCountersResponseObject, error) {
	now := s.now()
	to, from := now, time.Time{}
	if req.Params.To != nil {
		to = req.Params.To.UTC()
	}
	if req.Params.From != nil {
		from = req.Params.From.UTC()
	} else {
		from = to.Add(-defaultCounterSpan)
	}
	if !from.Before(to) {
		return nil, errValidation("from", "after_to")
	}
	if to.Sub(from) > counterWindow {
		return nil, errValidation("from", "window_too_long")
	}
	after, err := counterCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := counterDefaultPage
	if req.Params.Limit != nil {
		limit = min(max(*req.Params.Limit, 1), counterMaxPage)
	}
	var node uuid.UUID
	if req.Params.NodeId != nil {
		node = *req.Params.NodeId
	}
	out := gen.FreeCounterPage{Items: []gen.FreeCounterRow{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.FreeCounters(from, to, node, after, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			k := rows[len(rows)-1]
			out.NextCursor = ptr(encodeKey(strconv.FormatInt(k.Bucket.Unix(), 10), k.NodeID.String(), k.Protocol, k.Outcome, strconv.Itoa(k.RCode)))
		}
		for _, r := range rows {
			out.Items = append(out.Items, gen.FreeCounterRow{NodeId: r.NodeID, BucketStart: r.Bucket.UTC(), Transport: gen.FreeCounterRowTransport(r.Protocol),
				Outcome: r.Outcome, Rcode: r.RCode, Count: r.Count})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListFreeDnsCounters200JSONResponse(out), nil
}

// GetFreeDnsSettings is GET /settings/free-dns.
func (s *Server) GetFreeDnsSettings(ctx context.Context, _ gen.GetFreeDnsSettingsRequestObject) (gen.GetFreeDnsSettingsResponseObject, error) {
	var f store.FreeDNS
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		f, err = g.FreeDNSGet()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetFreeDnsSettings200JSONResponse(freeDNSView(f)), nil
}

// PutFreeDnsSettings is PUT /settings/free-dns (Plan T-556). The row is locked first so two admins are ordered and the
// audit row names the switch that was replaced. The same values change nothing and write nothing, so the version the
// nodes compare moves only for a real change.
func (s *Server) PutFreeDnsSettings(ctx context.Context, req gen.PutFreeDnsSettingsRequestObject) (gen.PutFreeDnsSettingsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if b.Qps < 1 || b.Qps > maxFreeQPS {
		return nil, errQPS()
	}
	var out store.FreeDNS
	err = s.global(ctx, func(g store.GlobalTx) error {
		cur, err := g.FreeDNSLock()
		if err != nil {
			return err
		}
		out = cur
		if cur.Enabled == b.Enabled && cur.QPS == b.Qps {
			return nil
		}
		if err := g.FreeDNSSet(b.Enabled, b.Qps); err != nil {
			return err
		}
		if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.FreeDNSChange{FromEnabled: cur.Enabled, ToEnabled: b.Enabled, QPS: b.Qps}); err != nil {
			return err
		}
		out, err = g.FreeDNSGet()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutFreeDnsSettings200JSONResponse(freeDNSView(out)), nil
}

// servedHost is the host a service answers on while no requested one is applied: the applied host, else the variable
// Caddy reads. "" when neither is known.
func (s *Server) servedHost(kind certcheck.Kind, d store.DomainSettings) string {
	applied, env := d.AppliedPanelHost, s.d.PanelHost
	if kind == certcheck.Admin {
		applied, env = d.AppliedAdminHost, s.d.AdminHost
	}
	for _, h := range []string{applied, httpx.HostName(env)} {
		if h != "" {
			return strings.ToLower(h)
		}
	}
	return ""
}

// hostForChoice is the host a panel or admin certificate must cover: the requested host, else the one served, else the
// variable Caddy reads (p4-nodes 3.2 item 6, AUTH 7.2).
func (s *Server) hostForChoice(kind certcheck.Kind, d store.DomainSettings) string {
	requested := d.PanelHost
	if kind == certcheck.Admin {
		requested = d.AdminHost
	}
	if requested != "" {
		return strings.ToLower(requested)
	}
	return s.servedHost(kind, d)
}

// chosenCert is the id of the row p4-nodes 4.3's choice rule picks for a kind now, or nil when it picks none.
func (s *Server) chosenCert(g store.GlobalTx, kind certcheck.Kind, d store.DomainSettings, now time.Time) (*uuid.UUID, error) {
	rows, err := g.CertsActive(string(kind))
	if err != nil {
		return nil, err
	}
	in := make([]certcheck.Row, len(rows))
	for i, r := range rows {
		in[i] = certcheck.Row{ID: r.ID, State: r.State, ChainPEM: r.ChainPEM}
	}
	row, _, ok := certcheck.Choose(in, kind, certcheck.Scope{Host: s.hostForChoice(kind, d)}, now, certcheck.Options{Roots: s.d.certRoots})
	if !ok {
		return nil, nil
	}
	return &row.ID, nil
}

func sameID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// domainView is the settings as the page shows them. apply_pending is true while what is served is not what is wanted: a
// requested host that differs from its applied one, or a certificate row the choice rule picks now that is not the one the
// last apply used (3.2 item 6).
func (s *Server) domainView(g store.GlobalTx, d store.DomainSettings, now time.Time) (gen.DomainSettings, error) {
	// An empty requested host asks for nothing new: the host served stays (hostForChoice), so it is no pending change.
	// Comparing it would keep the flag up for good once domain-apply has set an applied host (R34-r1-1, r1-9).
	pending := (d.PanelHost != "" && d.PanelHost != d.AppliedPanelHost) || (d.AdminHost != "" && d.AdminHost != d.AppliedAdminHost)
	for _, c := range []struct {
		kind    certcheck.Kind
		applied *uuid.UUID
	}{{certcheck.Panel, d.AppliedPanelCertID}, {certcheck.Admin, d.AppliedAdminCertID}} {
		id, err := s.chosenCert(g, c.kind, d, now)
		if err != nil {
			return gen.DomainSettings{}, err
		}
		if !sameID(id, c.applied) {
			pending = true
		}
	}
	v := gen.DomainSettings{DnsZone: nonEmpty(d.DNSZone), PanelHost: nonEmpty(d.PanelHost), AdminHost: nonEmpty(d.AdminHost), PrevDnsZone: nonEmpty(d.PrevDNSZone),
		AppliedPanelHost: nonEmpty(d.AppliedPanelHost), AppliedAdminHost: nonEmpty(d.AppliedAdminHost), ApplyPending: pending}
	// The previous zone and its end are shown only while they are live: after the transition they are history.
	if d.TransitionUntil != nil && now.Before(*d.TransitionUntil) {
		v.TransitionUntil = ptr(d.TransitionUntil.UTC())
	} else {
		v.PrevDnsZone = nil
	}
	return v, nil
}

// GetDomainSettings is GET /settings/domain.
func (s *Server) GetDomainSettings(ctx context.Context, _ gen.GetDomainSettingsRequestObject) (gen.GetDomainSettingsResponseObject, error) {
	var v gen.DomainSettings
	err := s.readGlobal(ctx, func(g store.GlobalTx) error {
		d, err := g.DomainGet()
		if err != nil {
			return err
		}
		v, err = s.domainView(g, d, s.now())
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetDomainSettings200JSONResponse(v), nil
}

// GetDomainImpact is GET /settings/domain/impact.
func (s *Server) GetDomainImpact(ctx context.Context, _ gen.GetDomainImpactRequestObject) (gen.GetDomainImpactResponseObject, error) {
	var out gen.DomainImpact
	err := s.readGlobal(ctx, func(g store.GlobalTx) (err error) {
		out.Endpoints, out.AppleProfiles, err = g.DomainImpact()
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetDomainImpact200JSONResponse(out), nil
}

func domainErr(err error, field string) error {
	switch {
	case errors.Is(err, nodeadmin.ErrTransition):
		return httpx.New(http.StatusConflict, httpx.CodeTransitionActive)
	case errors.Is(err, nodeadmin.ErrDomain):
		return errDomain(field)
	}
	return err
}

// whichDomainField names the value that failed, for the answer. The first that fails the grammar or the zone rule wins; a
// host under a zone names that host.
func whichDomainField(in nodeadmin.DomainInput, cur nodeadmin.DomainState, now time.Time) string {
	if f := nodeadmin.FailedDomainField(in, cur, now); f != "" {
		return f
	}
	return "admin_host"
}

// PutDomainSettings is PUT /settings/domain (10.4). One transaction: the unfinished domain_change job is superseded first
// (admin_jobs ranks before the settings rows), the row is locked, the rules judged against what the lock shows, the
// columns written, the job queued when the zone changed, and the audit row. A change of zone from one value to another
// starts the transition; a first set and a host-only edit start none.
func (s *Server) PutDomainSettings(ctx context.Context, req gen.PutDomainSettingsRequestObject) (gen.PutDomainSettingsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	b := *req.Body
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	// The grammar is lower case. The route lowers and trims first, so a capital typed by a person is not a refusal, and
	// whatever else is outside the grammar is.
	in := nodeadmin.DomainInput{DNSZone: strings.ToLower(strings.TrimSpace(b.DnsZone))}
	if b.PanelHost != nil {
		in.PanelHost = strings.ToLower(strings.TrimSpace(*b.PanelHost))
	}
	if b.AdminHost != nil {
		in.AdminHost = strings.ToLower(strings.TrimSpace(*b.AdminHost))
	}
	days := defaultTransitionDays
	if b.TransitionDays != nil {
		days = *b.TransitionDays
	}
	if days < 1 || days > 90 {
		return nil, errValidation("transition_days", "out_of_range")
	}
	var out gen.DomainSettings
	err = s.global(ctx, func(g store.GlobalTx) error {
		// A lock-free read decides whether this is a change of zone at all, so a request that repeats the zone ends no job.
		// The row is locked below and the decision confirmed: if another admin moved the zone between the two, this one
		// retries (the same shape as PutRegistration).
		pre, err := g.DomainGet()
		if err != nil {
			return err
		}
		s.d.betweenReadAndLock()
		if in.DNSZone != pre.DNSZone {
			if _, err := g.AdminJobsSupersede(jobDomainChange); err != nil {
				return err
			}
		}
		cur, err := g.DomainLock()
		if err != nil {
			return err
		}
		if cur.DNSZone != pre.DNSZone {
			return store.ErrConflict
		}
		now := s.now()
		state := nodeadmin.DomainState{DNSZone: cur.DNSZone, PrevDNSZone: cur.PrevDNSZone, TransitionUntil: cur.TransitionUntil,
			ServedPanel: s.servedHost(certcheck.Panel, cur), ServedAdmin: s.servedHost(certcheck.Admin, cur)}
		if err := nodeadmin.CheckDomain(in, state, now); err != nil {
			return domainErr(err, whichDomainField(in, state, now))
		}
		zoneChanged := in.DNSZone != cur.DNSZone
		hostsChanged := in.PanelHost != cur.PanelHost || in.AdminHost != cur.AdminHost
		if zoneChanged || hostsChanged {
			next := cur
			next.DNSZone, next.PanelHost, next.AdminHost = in.DNSZone, in.PanelHost, in.AdminHost
			started := 0
			if zoneChanged {
				next.ChangedAt = ptr(now)
				if cur.DNSZone != "" {
					next.PrevDNSZone = cur.DNSZone
					next.TransitionUntil = ptr(now.Add(time.Duration(days) * 24 * time.Hour))
					started = days
				}
			}
			if err := g.DomainSet(next); err != nil {
				return err
			}
			if zoneChanged {
				if _, err := g.AdminJobInsert(jobDomainChange, nil, p.AdminID); err != nil {
					return err
				}
			}
			if _, err := audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.DomainChange{
				FromZone: audit.DomainNameOf(cur.DNSZone), ToZone: audit.DomainNameOf(in.DNSZone), HostsChanged: hostsChanged, TransitionDays: started,
			}); err != nil {
				return err
			}
			cur = next
		}
		out, err = s.domainView(g, cur, now)
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.PutDomainSettings200JSONResponse(out), nil
}
