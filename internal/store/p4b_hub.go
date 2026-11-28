package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// The database half of P4b's hub work (docs/specs/p4b-proxy.md 11): what it sends a node about the proxy, what the node
// reports back, the alerts it closes and the block page roots it gives a certificate. Migration 0105 is the whole boundary:
// the hub holds S on proxy_settings and block_roots (every row, by two named policies), S and I and U on
// node_location_config_state, S on node_location_configs and nodes, and EXECUTE on ctrlz_fn.node_alert_close. Nothing here
// is tenant-scoped except BlockRootEnsure, which is the tenant's.

// ProxySettings is the one row of proxy_settings.
type ProxySettings struct {
	GrantWidth string // exact, prefix24 or carrier
	ProbeURLs  []string
}

const qHubProxySettings = `SELECT grant_width, probe_urls FROM ctrlz.proxy_settings`

// HubProxySettings reads the settings every NodeConfig carries (grant_width and probe_urls).
func (s *Store) HubProxySettings(ctx context.Context) (p ProxySettings, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		return sanitize(g.tx.QueryRow(g.ctx, qHubProxySettings).Scan(&p.GrantWidth, &p.ProbeURLs))
	})
	return p, err
}

// NodeXray is what the hub reads of a node to know whether its configs changed: the counter that every write of a config
// steps (node_location_configs_limit) and the release the admin asked the node to fetch, empty for none.
type NodeXray struct {
	Rev          int64
	FetchVersion string
}

const qHubNodeRev = `SELECT xray_rev FROM ctrlz.nodes WHERE id = $1`

const qHubNodeXray = `SELECT xray_rev, COALESCE(xray_fetch_version, '') FROM ctrlz.nodes WHERE id = $1`

// HubNodeXray reads the counter and the fetch version of a node; found is false for a node that is gone. The hub reads the
// fragments again only when the counter moved.
func (s *Store) HubNodeXray(ctx context.Context, node uuid.UUID) (x NodeXray, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var e error
		found, e = notFound(g.tx.QueryRow(g.ctx, qHubNodeXray, node).Scan(&x.Rev, &x.FetchVersion))
		return e
	})
	return x, found, err
}

// NodeConfigRow is one enabled config of a node, as NodeConfig carries it. Fragment is the credential of an exit: it goes to
// the node and nowhere else, and no log, error or audit row holds it.
type NodeConfigRow struct {
	ID              uuid.UUID
	LocationID      uuid.UUID
	Tag             string
	Priority        int
	Fragment        []byte // the JSON text
	SchemaVersion   string
	AcceptedUnknown []string
}

const qHubNodeConfigs = `SELECT id, location_id, tag, priority, fragment::text, schema_version, accepted_unknown
FROM ctrlz.node_location_configs WHERE node_id = $1 AND enabled ORDER BY priority DESC, tag`

// HubNodeConfigs reads the enabled configs of a node, in the order of the picker: priority first, then the tag, together
// with the counter the configs were read at. Both come from one repeatable-read snapshot: a hub that cached the fragments
// under a counter read in another transaction could hold an older set under a newer counter, and would never read again
// (a credential the admin removed would stay on the node). The count and the size of the rows are bounded by the
// database (64 rows, 2 MiB), so the reply is whole.
func (s *Store) HubNodeConfigs(ctx context.Context, node uuid.UUID) (rev int64, out []NodeConfigRow, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true, Isolation: RepeatableRead}, func(g GlobalTx) error {
		// The counter first, in the snapshot the rows are then read from. A node that is gone has no counter and no rows.
		if _, e := notFound(g.tx.QueryRow(g.ctx, qHubNodeRev, node).Scan(&rev)); e != nil {
			return e
		}
		rows, err := g.tx.Query(g.ctx, qHubNodeConfigs, node)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var r NodeConfigRow
			var prio int32
			var frag string
			if err := rows.Scan(&r.ID, &r.LocationID, &r.Tag, &prio, &frag, &r.SchemaVersion, &r.AcceptedUnknown); err != nil {
				return sanitize(err)
			}
			r.Priority, r.Fragment = int(prio), []byte(frag)
			out = append(out, r)
		}
		return sanitize(rows.Err())
	})
	return rev, out, err
}

// ConfigState is one entry of Heartbeat.xray_configs.
type ConfigState struct {
	ConfigID       uuid.UUID
	FragmentSHA256 []byte // empty for none, else 32 bytes
	State          string // pending, applied, refused or last_good
	Error          string
	Healthy        *bool
	LatencyMS      *int32
}

// The statement joins the configs of the reporting node, so a report for a config of another node, or for one that is gone,
// writes nothing: the hub holds node_id as a plain column and this is where "a report for a config of another node is
// dropped" is decided (11).
const qHubConfigStates = `INSERT INTO ctrlz.node_location_config_state AS s (config_id, node_id, fragment_sha256, state, error, healthy, latency_ms, reported_at)
SELECT c.id, c.node_id, NULLIF(x.sha, '\x'::bytea), x.state, NULLIF(x.err, ''), x.healthy, x.latency, now()
FROM unnest($2::uuid[], $3::bytea[], $4::text[], $5::text[], $6::boolean[], $7::int[]) AS x(id, sha, state, err, healthy, latency)
JOIN ctrlz.node_location_configs c ON c.id = x.id AND c.node_id = $1
ORDER BY c.id
ON CONFLICT (config_id) DO UPDATE SET fragment_sha256 = EXCLUDED.fragment_sha256, state = EXCLUDED.state, error = EXCLUDED.error,
  healthy = EXCLUDED.healthy, latency_ms = EXCLUDED.latency_ms, reported_at = EXCLUDED.reported_at,
  node_id = EXCLUDED.node_id`

// HubConfigStates stores what a node reported of its configs and returns how many entries were of its own configs. The
// caller sends at most 64 (the validator of Heartbeat holds it), each at most every 30 s or on a change.
func (s *Store) HubConfigStates(ctx context.Context, node uuid.UUID, in []ConfigState) (written int, err error) {
	if len(in) == 0 {
		return 0, nil
	}
	ids := make([]uuid.UUID, len(in))
	shas := make([][]byte, len(in))
	states := make([]string, len(in))
	errs := make([]string, len(in))
	healthy := make([]*bool, len(in))
	latency := make([]*int32, len(in))
	for i, c := range in {
		ids[i], shas[i], states[i], errs[i], healthy[i], latency[i] = c.ConfigID, c.FragmentSHA256, c.State, c.Error, c.Healthy, c.LatencyMS
		if shas[i] == nil {
			shas[i] = []byte{}
		}
	}
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		tag, err := g.tx.Exec(g.ctx, qHubConfigStates, node, ids, shas, states, errs, healthy, latency)
		if err != nil {
			return sanitize(err)
		}
		written = int(tag.RowsAffected())
		return nil
	})
	return written, err
}

const qHubAlertClose = `SELECT ctrlz_fn.node_alert_close($1::text, $2::uuid)`

// HubAlertClose closes the open alert of a kind and a node, for the kinds of P4b 11 and no other, and says how many rows it
// closed (one or none). The hub raises with INSERT only and closes here.
func (s *Store) HubAlertClose(ctx context.Context, kind string, node uuid.UUID) (closed int, err error) {
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var n int32
		if err := g.tx.QueryRow(g.ctx, qHubAlertClose, kind, node).Scan(&n); err != nil {
			return sanitize(err)
		}
		closed = int(n)
		return nil
	})
	return closed, err
}

// BlockRoot is a row of block_roots as the hub reads it: the account, and the digest of its certificate's key, empty while
// the row has none.
type BlockRoot struct {
	Tenant uuid.UUID
	SPKI   []byte
}

const qHubBlockRoots = `SELECT tenant_id, spki_sha256 FROM ctrlz.block_roots ORDER BY tenant_id`

// HubBlockRoots lists every account's root, for the pass that gives an empty one its certificate and renews one whose key
// is of another block_root_key (10.3, 11).
func (s *Store) HubBlockRoots(ctx context.Context) (out []BlockRoot, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		rows, err := g.tx.Query(g.ctx, qHubBlockRoots)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var r BlockRoot
			if err := rows.Scan(&r.Tenant, &r.SPKI); err != nil {
				return sanitize(err)
			}
			out = append(out, r)
		}
		return sanitize(rows.Err())
	})
	return out, err
}

const qHubBlockRootsEmpty = `SELECT tenant_id FROM ctrlz.block_roots WHERE cert_der IS NULL ORDER BY tenant_id`

// HubBlockRootsEmpty lists the accounts whose root has no certificate yet, for the pass of every 5 s (11). It reads through
// the partial index block_roots_empty_idx, so the cost follows the rows that wait and not every account that has a block
// page; HubBlockRoots, which compares every digest, is for the pass at start.
func (s *Store) HubBlockRootsEmpty(ctx context.Context) (out []uuid.UUID, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		rows, err := g.tx.Query(g.ctx, qHubBlockRootsEmpty)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return sanitize(err)
			}
			out = append(out, id)
		}
		return sanitize(rows.Err())
	})
	return out, err
}

const qHubBlockRootSet = `UPDATE ctrlz.block_roots SET cert_der = $2, spki_sha256 = $3, not_before = $4, not_after = $5
WHERE tenant_id = $1 RETURNING tenant_id`

// HubBlockRootSet writes the certificate of an account's root; found is false for an account that is gone. The four columns
// come together (a CHECK), and the key of the certificate is derived again at each use and written nowhere.
func (s *Store) HubBlockRootSet(ctx context.Context, tenant uuid.UUID, der, spki []byte, notBefore, notAfter time.Time) (found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var id uuid.UUID
		var e error
		found, e = notFound(g.tx.QueryRow(g.ctx, qHubBlockRootSet, tenant, der, spki, notBefore, notAfter).Scan(&id))
		return e
	})
	return found, err
}

const qBlockRootEnsure = `INSERT INTO ctrlz.block_roots (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`

// BlockRootEnsure adds the account's empty block_roots row when there is none. Every writer of a block_pages row calls it in
// the same transaction (10.5), so the hub finds a row to give a certificate.
func (t Tx) BlockRootEnsure() error {
	if _, err := t.tx.Exec(t.ctx, qBlockRootEnsure, t.tenant); err != nil {
		return sanitize(err)
	}
	return nil
}
