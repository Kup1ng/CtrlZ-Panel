package lint_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/deploy"
	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// The ClickHouse proof of P5 A1 (spec 3.4 and 11.1): the real image, the real wrapper, the real users.xml and
// ctrlz.xml, and the real migrations run by the real runner, then the two-tenant test of every table as each
// reader user, by raw SQL through the driver the reader will use. It runs on GitHub only (D69).
//
// The first thing it proves is the one 3.4 says the documentation does not: that SQL_tenant_id, a custom
// setting, is changeable under readonly 1 through the constraint, that a row policy reads it, and that the
// quota key reaches a quota keyed by client_key. If it fails, the fallback of 3.4 is readonly 2 for the two
// readers with the same grants and constraints, and the test says so.

const chFallbackNote = "if this is the custom-setting proof of 3.4 failing, the decided fallback is readonly 2 for ctrlz_api and ctrlz_preview in users.xml, with the same grants and constraints"

// chConn opens one connection as a user, the way the reader will: the native protocol, no settings of the
// connection's own.
func chConn(t *testing.T, addr, user, password string) clickhouse.Conn {
	t.Helper()
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:        []string{addr},
		Auth:        clickhouse.Auth{Database: "default", Username: user, Password: password},
		DialTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("open %s: %v", user, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// chTenantCtx is the context of a reader's query: the tenant as the custom setting and a quota key, with an
// optional deadline (which clickhouse-go turns into max_execution_time, the seconds plus 5) and settings.
func chTenantCtx(tenant uuid.UUID, key string, deadline time.Duration, settings clickhouse.Settings) (context.Context, context.CancelFunc) {
	s := clickhouse.Settings{}
	if tenant != uuid.Nil {
		s["SQL_tenant_id"] = clickhouse.CustomSetting{Value: tenant.String()}
	}
	for k, v := range settings {
		s[k] = v
	}
	ctx, cancel := context.Background(), context.CancelFunc(func() {})
	if deadline > 0 {
		ctx, cancel = context.WithTimeout(ctx, deadline)
	}
	opts := []clickhouse.QueryOption{clickhouse.WithSettings(s)}
	if key != "" {
		opts = append(opts, clickhouse.WithQuotaKey(key))
	}
	return clickhouse.Context(ctx, opts...), cancel
}

// wantServerRefusal says the error is the server's refusal and not a lost connection, which would make
// every "must fail" below pass for the wrong reason.
func wantServerRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: the server accepted it", what)
		return
	}
	var ex *clickhouse.Exception
	if !errors.As(err, &ex) {
		t.Errorf("%s: failed, but not with a server exception (a broken connection proves nothing): %v", what, err)
		return
	}
	t.Logf("%s: refused with code %d", what, ex.Code)
}

func chCount(t *testing.T, conn clickhouse.Conn, ctx context.Context, query string) uint64 {
	t.Helper()
	var n uint64
	if err := conn.QueryRow(ctx, query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// perTenant returns the number of rows of each tenant in a table, read as the migrator (the maintenance
// policy), which is the reference every reader's answer is compared with.
func perTenant(t *testing.T, conn clickhouse.Conn, table string) map[uuid.UUID]uint64 {
	t.Helper()
	rows, err := conn.Query(context.Background(), "SELECT tenant_id, count() FROM ctrlz."+table+" GROUP BY tenant_id")
	if err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	defer rows.Close()
	out := map[uuid.UUID]uint64{}
	for rows.Next() {
		var id uuid.UUID
		var n uint64
		if err := rows.Scan(&id, &n); err != nil {
			t.Fatal(err)
		}
		out[id] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestClickHouseTwoTenants(t *testing.T) {
	lab := newClickHouseLab(t)
	files := map[string][]byte{}
	pw := map[string]string{}
	for _, u := range chUserNames {
		pw[u] = "Pw" + uuid.NewString() + "-" + u
		files[u] = []byte(pw[u] + "\n")
	}
	name := lab.runWith(files, false, true)
	for _, u := range chUserNames {
		lab.wantReady(name, "ctrlz_"+u, pw[u])
	}
	addr := lab.nativeAddr(name)

	mig := chConn(t, addr, "ctrlz_migrator", pw["migrator"])
	ing := chConn(t, addr, "ctrlz_ingest", pw["ingest"])
	api := chConn(t, addr, "ctrlz_api", pw["api"])
	prev := chConn(t, addr, "ctrlz_preview", pw["preview"])
	jan := chConn(t, addr, "ctrlz_janitor", pw["janitor"])

	// The migrations, by the runner the one-shot uses. The first step stops after 0001, where a run that fails
	// or is killed would leave a real install: the table exists, the readers hold SELECT, and the row policies
	// must already be there (a table with no policy at all is read without a filter). Then the rest, and a
	// second run that applies nothing.
	mdb := migrate.OpenAnalytics(migrate.AnalyticsConfig{Addr: addr, User: "ctrlz_migrator", Password: pw["migrator"]})
	defer func() { _ = mdb.Close() }()
	mctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	n, err := migrate.UpAnalyticsTo(mctx, mdb, 1)
	if err != nil || n != 1 {
		t.Fatalf("the migrations up to 0001 applied %d (%v), want 1", n, err)
	}
	tenC := uuid.New()
	early, err := ing.PrepareBatch(context.Background(), "INSERT INTO ctrlz.dns_raw (tenant_id, ts, row_id, endpoint_id, qname_norm, qtype, rcode, action, decision_stage, ref_kind, decision_ref, protocol, source_country, answer_country, asn, traffic_cat, in_domains, ttl_days, ttl_months)")
	if err != nil {
		t.Fatalf("prepare the early row: %v", err)
	}
	if err := early.Append(tenC, time.Now().UTC().Truncate(time.Second), uint64(1), uuid.MustParse("00000000-0000-0000-0000-0000000000e1"), "early.example", uint16(1), uint16(0),
		"block", "filter", "filter", "filter:7", "doh", "DE", "US", uint32(13335), uint16(5), uint8(1), uint8(30), uint8(12)); err != nil {
		t.Fatalf("append the early row: %v", err)
	}
	if err := early.Send(); err != nil {
		t.Fatalf("send the early row: %v", err)
	}
	for user, conn := range map[string]clickhouse.Conn{"ctrlz_api": api, "ctrlz_preview": prev} {
		noTenant, cancelNT := chTenantCtx(uuid.Nil, "k-early", 0, nil)
		wantServerRefusal(t, user+" reading dns_raw after 0001 with no tenant", conn.QueryRow(noTenant, "SELECT count() FROM ctrlz.dns_raw").Scan(new(uint64)))
		cancelNT()
		for ten, wantRows := range map[uuid.UUID]uint64{tenC: 1, uuid.New(): 0} {
			c, cancelT := chTenantCtx(ten, "k-early", 0, nil)
			var got uint64
			if err := conn.QueryRow(c, "SELECT count() FROM ctrlz.dns_raw").Scan(&got); err != nil {
				t.Errorf("%s reading dns_raw after 0001 as %s: %v (%s)", user, ten, err, chFallbackNote)
			} else if got != wantRows {
				t.Errorf("%s reading dns_raw after 0001 as %s: %d rows, want %d: the row policy was not there when the table was", user, ten, got, wantRows)
			}
			cancelT()
		}
	}
	if n, err := migrate.UpAnalytics(mctx, mdb); err != nil || n != 2 {
		t.Fatalf("the rest of the migrations applied %d (%v), want 2", n, err)
	}
	if n, err := migrate.UpAnalytics(mctx, mdb); err != nil || n != 0 {
		t.Errorf("the second run applied %d migrations (%v), want 0", n, err)
	}

	tenA, tenB := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	// Seed through the hub's user: A and B share the name, the domain, the times and the protocol. The rollups
	// are filled by the views, so this also proves that a user with INSERT on three tables only writes all
	// seven (the definer of the views is the migrator).
	seed := func(tenant uuid.UUID, rows int) {
		b, err := ing.PrepareBatch(context.Background(), "INSERT INTO ctrlz.dns_raw (tenant_id, ts, row_id, endpoint_id, qname_norm, qtype, rcode, action, decision_stage, ref_kind, decision_ref, protocol, source_country, answer_country, asn, traffic_cat, in_domains, ttl_days, ttl_months)")
		if err != nil {
			t.Fatalf("prepare dns_raw: %v", err)
		}
		for i := 0; i < rows; i++ {
			if err := b.Append(tenant, now, uint64(i+1), uuid.MustParse("00000000-0000-0000-0000-0000000000e1"), "same.example", uint16(1), uint16(0),
				"block", "filter", "filter", "filter:7", "doh", "DE", "US", uint32(13335), uint16(5), uint8(1), uint8(30), uint8(12)); err != nil {
				t.Fatalf("append dns_raw: %v", err)
			}
		}
		if err := b.Send(); err != nil {
			t.Fatalf("send dns_raw: %v", err)
		}
		c, err := ing.PrepareBatch(context.Background(), "INSERT INTO ctrlz.counts_5m (tenant_id, ts, endpoint_id, protocol, action, ttl_months, queries)")
		if err != nil {
			t.Fatalf("prepare counts_5m: %v", err)
		}
		if err := c.Append(tenant, now, uuid.MustParse("00000000-0000-0000-0000-0000000000e1"), "doh", "block", uint8(12), uint64(5+rows)); err != nil {
			t.Fatalf("append counts_5m: %v", err)
		}
		if err := c.Send(); err != nil {
			t.Fatalf("send counts_5m: %v", err)
		}
		g, err := ing.PrepareBatch(context.Background(), "INSERT INTO ctrlz.agg_category (tenant_id, bucket, endpoint_id, action, traffic_cat, ttl_months, queries)")
		if err != nil {
			t.Fatalf("prepare agg_category: %v", err)
		}
		if err := g.Append(tenant, now, uuid.MustParse("00000000-0000-0000-0000-0000000000e1"), "block", uint16(5), uint8(12), uint64(3)); err != nil {
			t.Fatalf("append agg_category: %v", err)
		}
		if err := g.Send(); err != nil {
			t.Fatalf("send agg_category: %v", err)
		}
	}
	seed(tenA, 3)
	seed(tenB, 2)

	tables := []string{"dns_raw", "counts_5m", "agg_category", "agg_counts", "agg_reason", "agg_geo", "agg_domain"}
	want := map[string]map[uuid.UUID]uint64{}
	for _, tb := range tables {
		want[tb] = perTenant(t, mig, tb)
		if want[tb][tenA] == 0 || want[tb][tenB] == 0 {
			t.Fatalf("%s: the migrator sees A:%d B:%d rows; both tenants must have rows for the test to mean anything (the views feed the rollups)", tb, want[tb][tenA], want[tb][tenB])
		}
	}
	// The rollups sum to the rows: three raw rows of A are three queries of every reason row of A.
	if got := chCount(t, mig, context.Background(), fmt.Sprintf("SELECT sum(queries) FROM ctrlz.agg_reason WHERE tenant_id = toUUID('%s')", tenA)); got != 3 {
		t.Errorf("agg_reason sums to %d queries for A, want 3", got)
	}
	if got := chCount(t, mig, context.Background(), fmt.Sprintf("SELECT sum(queries) FROM ctrlz.agg_counts WHERE tenant_id = toUUID('%s')", tenB)); got != 7 {
		t.Errorf("agg_counts sums to %d queries for B, want 7", got)
	}

	readers := []struct {
		user     string
		conn     clickhouse.Conn
		tables   []string
		deadline time.Duration // the longest context that reaches the server under max_execution_time's maximum
		tooLong  time.Duration // one that does not
		maxExec  int
	}{
		{"ctrlz_api", api, tables, 10 * time.Second, 12 * time.Second, 15},
		{"ctrlz_preview", prev, []string{"dns_raw", "agg_counts", "agg_reason"}, 60 * time.Second, 68 * time.Second, 70},
	}
	for _, r := range readers {
		t.Run(r.user, func(t *testing.T) {
			granted := map[string]bool{}
			for _, tb := range r.tables {
				granted[tb] = true
			}
			for _, tb := range tables {
				for _, ten := range []uuid.UUID{tenA, tenB} {
					ctx, cancel := chTenantCtx(ten, "k-"+ten.String(), 0, nil)
					q := fmt.Sprintf("SELECT count(), countIf(tenant_id != toUUID('%s')) FROM ctrlz.%s", ten, tb)
					var total, foreign uint64
					err := r.conn.QueryRow(ctx, q).Scan(&total, &foreign)
					cancel()
					if !granted[tb] {
						wantServerRefusal(t, r.user+" reading "+tb+" (no grant)", err)
						continue
					}
					if err != nil {
						t.Errorf("%s reading %s as %s: %v (%s)", r.user, tb, ten, err, chFallbackNote)
						continue
					}
					if foreign != 0 || total != want[tb][ten] {
						t.Errorf("%s reading %s with the tenant %s: %d rows, %d of another tenant; want %d and 0", r.user, tb, ten, total, foreign, want[tb][ten])
					}
				}
				if !granted[tb] {
					continue
				}
				// No tenant, a value that is no UUID, and the empty value: the closed side.
				for what, ctx := range map[string]func() (context.Context, context.CancelFunc){
					"no tenant": func() (context.Context, context.CancelFunc) { return chTenantCtx(uuid.Nil, "k", 0, nil) },
					"a value that is no UUID": func() (context.Context, context.CancelFunc) {
						return chTenantCtx(uuid.Nil, "k", 0, clickhouse.Settings{"SQL_tenant_id": clickhouse.CustomSetting{Value: "not-a-uuid"}})
					},
					"the empty value": func() (context.Context, context.CancelFunc) {
						return chTenantCtx(uuid.Nil, "k", 0, clickhouse.Settings{"SQL_tenant_id": clickhouse.CustomSetting{Value: ""}})
					},
				} {
					c, cancel := ctx()
					var n uint64
					err := r.conn.QueryRow(c, "SELECT count() FROM ctrlz."+tb).Scan(&n)
					cancel()
					if err == nil && n != 0 {
						t.Errorf("%s reading %s with %s: %d rows came back", r.user, tb, what, n)
					} else if err == nil {
						t.Errorf("%s reading %s with %s: no error, 0 rows; the closed side is an error", r.user, tb, what)
					} else {
						wantServerRefusal(t, r.user+" reading "+tb+" with "+what, err)
					}
				}
			}

			// Writes, DDL, settings, other sources and objects: refused.
			// The system tables need a grant (select_from_system_db_requires_grant), except a fixed list that the
			// server grants to everyone (ContextAccess.cpp: tables, columns, settings, databases and others, which
			// hold no query text). processes and errors carry the text and the last error of other tenants'
			// queries, which no row policy covers, and are not on that list. system.tables and system.settings are
			// on it, so they are not expected to be refused; what a reader may see in system.tables is checked below.
			ctxA := func() (context.Context, context.CancelFunc) { return chTenantCtx(tenA, "k-denials", 0, nil) }
			for what, stmt := range map[string]string{
				"an INSERT":                    "INSERT INTO ctrlz.counts_5m (tenant_id, ts, endpoint_id, protocol, action, ttl_months, queries) VALUES (generateUUIDv4(), now(), generateUUIDv4(), 'doh', 'block', 12, 1)",
				"an ALTER":                     "ALTER TABLE ctrlz.dns_raw DELETE WHERE 1",
				"a lightweight DELETE":         "DELETE FROM ctrlz.dns_raw WHERE 1",
				"a CREATE TABLE":               "CREATE TABLE ctrlz.x (a UInt8) ENGINE = Memory",
				"SET readonly":                 "SET readonly = 0",
				"a view object":                "SELECT count() FROM ctrlz.mv_counts",
				"the goose table":              "SELECT count() FROM ctrlz_meta.schema_migrations",
				"system.users":                 "SELECT count() FROM system.users",
				"system.row_policies":          "SELECT count() FROM system.row_policies",
				"system.query_log":             "SELECT count() FROM system.query_log",
				"system.processes":             "SELECT count() FROM system.processes",
				"system.errors":                "SELECT count() FROM system.errors",
				"information_schema.tables":    "SELECT count() FROM information_schema.tables",
				"url()":                        "SELECT * FROM url('http://ctrlz-none.invalid/', 'CSV', 'x String')",
				"file()":                       "SELECT * FROM file('/etc/passwd', 'CSV', 'x String')",
				"a query SETTINGS clause":      "SELECT count() FROM ctrlz.dns_raw SETTINGS readonly = 0",
				"a limit in a SETTINGS clause": "SELECT count() FROM ctrlz.dns_raw SETTINGS max_rows_to_read = 1",
				"a SYSTEM statement":           "SYSTEM FLUSH LOGS",
				"a KILL":                       "KILL QUERY WHERE 1",
				"an OPTIMIZE":                  "OPTIMIZE TABLE ctrlz.dns_raw FINAL",
				"a TRUNCATE":                   "TRUNCATE TABLE ctrlz.dns_raw",
				"a DROP":                       "DROP TABLE ctrlz.dns_raw",
				"a GRANT":                      "GRANT SELECT ON *.* TO ctrlz_api",
				"a CREATE ROW POLICY":          "CREATE ROW POLICY p ON ctrlz.dns_raw USING 1 TO ctrlz_api",
				"a CREATE USER":                "CREATE USER x",
			} {
				ctx, cancel := ctxA()
				err := r.conn.Exec(ctx, stmt)
				cancel()
				wantServerRefusal(t, r.user+": "+what, err)
			}

			// system.tables is always readable, but its rows are the tables the user may see: the ones it is
			// granted, no view and nothing of the goose database. (The tenant value is chosen by the process on
			// every query and never SET on a pooled connection: the reader package holds that, R6.)
			ctxT, cancelT := chTenantCtx(tenA, "k-tables", 0, nil)
			trows, err := r.conn.Query(ctxT, "SELECT database, name FROM system.tables WHERE database IN ('ctrlz', 'ctrlz_meta')")
			if err != nil {
				t.Errorf("%s listing system.tables: %v", r.user, err)
			} else {
				seen := 0
				for trows.Next() {
					var db, tb string
					if err := trows.Scan(&db, &tb); err != nil {
						t.Fatal(err)
					}
					seen++
					if db != "ctrlz" || !granted[tb] {
						t.Errorf("%s sees the table %s.%s in system.tables, which it is not granted", r.user, db, tb)
					}
				}
				_ = trows.Close()
				if seen != len(r.tables) {
					t.Errorf("%s sees %d tables in system.tables, want its %d granted ones", r.user, seen, len(r.tables))
				}
			}
			cancelT()

			// Each limit of 6.3 changed by the client, and the one setting that may change within its maximum.
			for k, v := range map[string]any{
				"readonly": 0, "max_threads": 64, "max_memory_usage": int64(1) << 40, "max_memory_usage_for_user": int64(1) << 40,
				"max_bytes_before_external_group_by": 0, "max_bytes_before_external_sort": 0, "max_result_rows": 0,
				"max_result_bytes": 0, "max_rows_to_read": 0, "max_concurrent_queries_for_user": 0,
				"max_temporary_data_on_disk_size_for_query": 0, "max_temporary_data_on_disk_size_for_user": 0,
				"max_execution_time": r.maxExec + 1,
				// 0 means no limit: the constraint has a minimum so that it cannot be asked for.
				"max_execution_time (zero)": 0,
			} {
				if strings.HasSuffix(k, " (zero)") {
					ctx, cancel := chTenantCtx(tenA, "k-limits", 0, clickhouse.Settings{"max_execution_time": v})
					err := r.conn.QueryRow(ctx, "SELECT 1").Scan(new(uint8))
					cancel()
					wantServerRefusal(t, r.user+" turning its deadline off", err)
					continue
				}
				ctx, cancel := chTenantCtx(tenA, "k-limits", 0, clickhouse.Settings{k: v})
				err := r.conn.QueryRow(ctx, "SELECT 1").Scan(new(uint8))
				cancel()
				wantServerRefusal(t, r.user+" changing "+k, err)
			}
			// The deadline of a context reaches the server as seconds plus 5 (clickhouse-go): the longest honest
			// deadline is accepted and a longer one is not.
			ok, cancel := chTenantCtx(tenA, "k-deadline", r.deadline, nil)
			if err := r.conn.QueryRow(ok, "SELECT 1").Scan(new(uint8)); err != nil {
				t.Errorf("%s: a deadline of %s was refused: %v (%s)", r.user, r.deadline, err, chFallbackNote)
			}
			cancel()
			long, cancel := chTenantCtx(tenA, "k-deadline", r.tooLong, nil)
			wantServerRefusal(t, fmt.Sprintf("%s with a deadline of %s", r.user, r.tooLong), r.conn.QueryRow(long, "SELECT 1").Scan(new(uint8)))
			cancel()
		})
	}

	// The quota of 6.2: keyed by the key the client sends, and a query with no key is refused. The real
	// quota is 60 s of execution time a minute, which a test cannot spend, so the keying is proved on a
	// quota of one query an hour with the same KEYED BY, made for ctrlz_preview and removed afterwards.
	t.Run("quota keyed by the client key", func(t *testing.T) {
		ctx, cancel := chTenantCtx(tenA, "", 0, nil)
		wantServerRefusal(t, "ctrlz_api with no quota key", api.QueryRow(ctx, "SELECT 1").Scan(new(uint8)))
		cancel()
		if err := mig.Exec(context.Background(), "CREATE QUOTA IF NOT EXISTS ctrlz_test_one KEYED BY client_key FOR INTERVAL 1 hour MAX queries = 1 TO ctrlz_preview"); err != nil {
			t.Fatalf("create the test quota: %v", err)
		}
		t.Cleanup(func() { _ = mig.Exec(context.Background(), "DROP QUOTA IF EXISTS ctrlz_test_one") })
		pconn := chConn(t, addr, "ctrlz_preview", pw["preview"])
		run := func(key string) error {
			c, cancel := chTenantCtx(tenA, key, 0, nil)
			defer cancel()
			return pconn.QueryRow(c, "SELECT 1").Scan(new(uint8))
		}
		if err := run("qa"); err != nil {
			t.Fatalf("the first query of key qa: %v", err)
		}
		wantServerRefusal(t, "the second query of key qa", run("qa"))
		if err := run("qb"); err != nil {
			t.Errorf("the first query of key qb was refused although qa's quota is spent: %v", err)
		}
	})

	t.Run("the hub's user", func(t *testing.T) {
		ctx := context.Background()
		wantServerRefusal(t, "ctrlz_ingest reading dns_raw", ing.QueryRow(ctx, "SELECT count() FROM ctrlz.dns_raw").Scan(new(uint64)))
		wantServerRefusal(t, "ctrlz_ingest inserting into a rollup", ing.Exec(ctx, "INSERT INTO ctrlz.agg_counts (tenant_id, bucket, endpoint_id, protocol, action, ttl_months, queries) VALUES (generateUUIDv4(), now(), generateUUIDv4(), 'doh', 'block', 12, 1)"))
		wantServerRefusal(t, "ctrlz_ingest deleting", ing.Exec(ctx, "DELETE FROM ctrlz.dns_raw WHERE 1"))
		if got := chCount(t, ing, ctx, "SELECT count() FROM system.disks"); got == 0 {
			t.Error("ctrlz_ingest sees no disk: it could not judge the free space of 5.4")
		}
	})

	// The janitor removes one tenant's rows (7.3) and sees nothing else of the table.
	t.Run("the janitor", func(t *testing.T) {
		ctx := context.Background()
		wantServerRefusal(t, "ctrlz_janitor reading a name", jan.QueryRow(ctx, "SELECT count() FROM ctrlz.dns_raw WHERE qname_norm = 'same.example'").Scan(new(uint64)))
		wantServerRefusal(t, "ctrlz_janitor inserting", jan.Exec(ctx, "INSERT INTO ctrlz.counts_5m (tenant_id, ts, endpoint_id, protocol, action, ttl_months, queries) VALUES (generateUUIDv4(), now(), generateUUIDv4(), 'doh', 'block', 12, 1)"))
		del := fmt.Sprintf("DELETE FROM ctrlz.dns_raw WHERE tenant_id = toUUID('%s') AND ts < now() + INTERVAL 1 HOUR", tenA)
		if err := jan.Exec(ctx, del); err != nil {
			t.Fatalf("the janitor's lightweight delete: %v", err)
		}
		testwait.UntilEvery(t, 60*time.Second, 500*time.Millisecond, "the janitor's delete of tenant A to show", func() bool {
			return chCount(t, mig, ctx, fmt.Sprintf("SELECT count() FROM ctrlz.dns_raw WHERE tenant_id = toUUID('%s')", tenA)) == 0
		})
		if got := chCount(t, mig, ctx, fmt.Sprintf("SELECT count() FROM ctrlz.dns_raw WHERE tenant_id = toUUID('%s')", tenB)); got != want["dns_raw"][tenB] {
			t.Errorf("tenant B has %d raw rows after A's delete, want %d", got, want["dns_raw"][tenB])
		}
		if got := chCount(t, jan, ctx, "SELECT count() FROM system.mutations"); got > 1000 {
			t.Errorf("the janitor reads %d mutations", got)
		}
	})

	// No system log table is kept by the server (3.4). The ones with query text are removed so that a searched
	// name is not stored, and the others (metric_log and the rest) because none has a TTL and they would fill the
	// disk that Postgres shares. Every MergeTree table of the system database is a log table, and some query
	// has run by now, so one that is still on shows a part. The janitor is the user that may read system.parts.
	t.Run("no system log table", func(t *testing.T) {
		ctx := context.Background()
		rows, err := jan.Query(ctx, "SELECT DISTINCT table FROM system.parts WHERE database = 'system'")
		if err != nil {
			t.Fatalf("the janitor lists the parts of the system database: %v", err)
		}
		var kept []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			kept = append(kept, name)
		}
		_ = rows.Close()
		if len(kept) != 0 {
			t.Errorf("system log tables exist and fill the disk or keep query text: %v (remove each in ctrlz.xml)", kept)
		}
		if got := chCount(t, jan, ctx, "SELECT count() FROM system.parts WHERE database = 'ctrlz'"); got == 0 {
			t.Error("the janitor sees no part of ctrlz, so the check above looked at nothing")
		}
	})

	// The access entities are made again by every run of the runner, outside goose's record: a policy dropped
	// (a restore of the data without the access directory, a change by hand) is back after one run that applies
	// no migration, and the migrator holds the rights to do it.
	t.Run("access is repaired by a run", func(t *testing.T) {
		if err := mig.Exec(context.Background(), "DROP ROW POLICY tenant_only ON ctrlz.*"); err != nil {
			t.Fatalf("the migrator cannot drop a policy: %v", err)
		}
		if n, err := migrate.UpAnalytics(mctx, mdb); err != nil || n != 0 {
			t.Fatalf("the repairing run applied %d migrations (%v), want 0 and no error", n, err)
		}
		noTenant, cancelNT := chTenantCtx(uuid.Nil, "k-repair", 0, nil)
		wantServerRefusal(t, "ctrlz_api with no tenant after the repair", api.QueryRow(noTenant, "SELECT count() FROM ctrlz.dns_raw").Scan(new(uint64)))
		cancelNT()
		c, cancelB := chTenantCtx(tenB, "k-repair", 0, nil)
		defer cancelB()
		var total, foreign uint64
		if err := api.QueryRow(c, fmt.Sprintf("SELECT count(), countIf(tenant_id != toUUID('%s')) FROM ctrlz.dns_raw", tenB)).Scan(&total, &foreign); err != nil {
			t.Fatalf("ctrlz_api reading as B after the repair: %v", err)
		}
		if total != want["dns_raw"][tenB] || foreign != 0 {
			t.Errorf("after the repair ctrlz_api sees %d rows, %d of another tenant; want %d and 0", total, foreign, want["dns_raw"][tenB])
		}
	})

	// The server log holds no query text (3.4): by default a failed query is logged at Error with its whole
	// text, and the searched name is user data. One failed query of each kind carries a canary, and the canary
	// is in neither Docker's log nor any file of the server's own log directory.
	t.Run("no query text in the server log", func(t *testing.T) {
		canary := "canary" + strings.ReplaceAll(uuid.NewString(), "-", "")
		for what, q := range map[string]string{
			"a constraint violation": "SELECT count() FROM ctrlz.dns_raw WHERE qname_norm = '" + canary + "' SETTINGS max_rows_to_read = 1",
			"a syntax error":         "SELECT count() FROM ctrlz.dns_raw WHERE qname_norm = '" + canary + "' AND",
			"an error while running": "SELECT throwIf(qname_norm != '" + canary + "') FROM ctrlz.dns_raw",
			"a missing grant":        "SELECT count() FROM ctrlz.mv_counts WHERE qname = '" + canary + "'",
			"an unknown column":      "SELECT " + canary + " FROM ctrlz.dns_raw",
		} {
			ctx, cancel := chTenantCtx(tenB, "k-canary", 0, nil)
			wantServerRefusal(t, what, api.Exec(ctx, q))
			cancel()
		}
		logs, err := deploy.Docker(context.Background(), "logs", name).CombinedOutput()
		if err != nil {
			t.Fatalf("docker logs: %v", err)
		}
		if strings.Contains(string(logs), canary) {
			t.Error("the console log holds the text of a failed query")
		}
		files, err := deploy.Docker(context.Background(), "exec", name, "sh", "-c", "grep -rl "+canary+" /var/log/clickhouse-server 2>/dev/null; true").CombinedOutput()
		if err != nil {
			t.Fatalf("docker exec: %v", err)
		}
		if strings.TrimSpace(string(files)) != "" {
			t.Errorf("a file of the server's log directory holds the text of a failed query: %s", strings.TrimSpace(string(files)))
		}
	})
}
