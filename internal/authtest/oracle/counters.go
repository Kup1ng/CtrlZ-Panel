package oracle

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Snapshot is the two counter tables and the gateway breakers as the oracle compares them:
// per scope, never per key, because the keys of a phone with an account and of one without
// differ by construction. The breakers are in it because only a real row ever reaches a gateway,
// so what a send does to a breaker, and through it to the public sms_available flag, is a write
// the account selects (review round 6, sms-r6-4); the first version of the harness compared the
// counters and reset the gateways before every run, and never saw it.
type Snapshot struct {
	SMS      map[string]Tally `json:"sms"`
	Throttle map[string]Tally `json:"throttle"`
	// Gateways has five entries: "failures" (the sum of consecutive_failures), "open" (how many
	// breakers are open now), "held" (how many gateways carry the hold of a refused login), "blocked"
	// (how many cannot send for the credentials they have: held, judged unusable or with none, which is
	// what auth_public_config reads, sms-r15-5) and "public_sms_available" (1 when auth_public_config says the login
	// page offers an SMS code). Each is the Sum of its Tally.
	Gateways map[string]Tally `json:"gateways"`
}

// Take reads the tables and the public flag as the superuser.
//
// The SMS counters are read across every day, with the rows of a scope counted by key, and never
// for "today" only. The harness empties the table before every run, so every row in it belongs
// to the run, and a filter on the Tehran date made a run that straddled Tehran midnight lose its
// before-rows: the request that sent a code on one side of the boundary showed as a movement of
// minus one row and minus one in the sum, which the oracle read as a difference between a known
// and an unknown phone (round 13, CI run, TestOracleGateHeld/register/open). A key that is counted
// on two days is still one key, and the sum does not care which day a count is on.
func Take(t *testing.T, env *authtest.Env) Snapshot {
	t.Helper()
	// One query, one connection: a snapshot is taken twice per run.
	var raw string
	env.Scan(t, `SELECT jsonb_build_object(
	  'sms', (SELECT COALESCE(jsonb_object_agg(scope, jsonb_build_object('rows', n, 'sum', s, 'cost', c)), '{}')
	          FROM (SELECT scope, count(DISTINCT key) AS n, sum(count) AS s, (sum(cost) * 10000)::bigint AS c
	                FROM ctrlz.sms_counters WHERE (count > 0 OR cost > 0) GROUP BY scope) q),
	  'throttle', (SELECT COALESCE(jsonb_object_agg(scope, jsonb_build_object('rows', n, 'sum', s, 'cost', 0)), '{}')
	          FROM (SELECT scope, count(*) AS n, sum(count) AS s FROM ctrlz.auth_throttle GROUP BY scope) q),
	  'gateways', jsonb_build_object(
	    'failures', jsonb_build_object('rows', 0, 'sum', (SELECT COALESCE(sum(consecutive_failures), 0) FROM ctrlz.sms_gateways), 'cost', 0),
	    'open', jsonb_build_object('rows', 0, 'sum', (SELECT count(*) FROM ctrlz.sms_gateways WHERE breaker_open_until > now()), 'cost', 0),
	    'held', jsonb_build_object('rows', 0, 'sum', (SELECT count(*) FROM ctrlz.sms_gateways WHERE held_ct_sum IS NOT NULL), 'cost', 0),
	    'blocked', jsonb_build_object('rows', 0, 'sum', (SELECT count(*) FROM ctrlz.sms_gateways WHERE blocked_now), 'cost', 0),
	    'public_sms_available', jsonb_build_object('rows', 0, 'sum', (SELECT CASE WHEN sms_available THEN 1 ELSE 0 END FROM ctrlz_fn.auth_public_config()), 'cost', 0)))::text`, nil, &raw)
	var snap Snapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return snap
}

// Since is the movement from before to s. A scope that did not move is left out,
// so a scope only one side touched shows as a difference.
func (s Snapshot) Since(before Snapshot) (sms, thr, gw map[string]Tally) {
	return diffMaps(s.SMS, before.SMS), diffMaps(s.Throttle, before.Throttle), diffMaps(s.Gateways, before.Gateways)
}

func diffMaps(after, before map[string]Tally) map[string]Tally {
	out := map[string]Tally{}
	for k, v := range after {
		if d := v.Sub(before[k]); !d.Zero() {
			out[k] = d
		}
	}
	for k, v := range before {
		if _, ok := after[k]; !ok && !v.Zero() {
			out[k] = Tally{}.Sub(v)
		}
	}
	return out
}

// NoneOperations returns the operations of one OpenAPI document that need no
// session, sorted by operationId. The oracle test walks this list, so a route
// added to the document without a scenario fails the test.
func NoneOperations(t *testing.T, service ratelimit.Service) []apispec.Operation {
	t.Helper()
	doc := api.Tenant()
	if service == ratelimit.Admin {
		doc = api.Admin()
	}
	ops, err := apispec.Parse(doc, service)
	if err != nil {
		t.Fatal(err)
	}
	var out []apispec.Operation
	for _, o := range ops {
		if o.Auth == apispec.None {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
