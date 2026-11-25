// Package apispec reads the two extensions every operation of the Panel's
// OpenAPI documents carries (spec 2.2):
//
//	x-ctrlz-auth: what the request must hold before the handler runs
//	x-ctrlz-rate: the rate class it is charged to
//
// The routers read them at start-up to build their middleware, and a test reads
// the same documents and fails when an operation lacks one, so a new route
// cannot go live unauthenticated or unmetered by omission. One reader serves
// both, which is why it is a package and not a test helper.
package apispec

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Auth is the value of x-ctrlz-auth.
type Auth string

// The values. The tenant API uses the first four and the admin API the last four,
// with None shared (spec 14.2, 15.2).
const (
	None         Auth = "none"          // no session; a ticket or refresh cookie may still be checked by the handler
	Session      Auth = "session"       // a live, unrestricted session
	SessionSetup Auth = "session-setup" // a live session, also while restricted (one-time password)
	Reauth       Auth = "reauth"        // a session with a reauth window newer than 10 minutes

	AdminSetup Auth = "admin-setup" // an admin session, also while the account is in setup
	Admin      Auth = "admin"       // an admin session of a ready account
	AdminFresh Auth = "admin-fresh" // a ready admin session with a TOTP check in the last 5 minutes
)

// valid says which values each service accepts.
func valid(s ratelimit.Service, a Auth) bool {
	switch s {
	case ratelimit.Tenant:
		return a == None || a == Session || a == SessionSetup || a == Reauth
	case ratelimit.Admin:
		return a == None || a == AdminSetup || a == Admin || a == AdminFresh
	}
	return false
}

// NeedsSession is true for every value that resolves a session.
func (a Auth) NeedsSession() bool { return a != None }

// Operation is one route with the metadata the pipeline needs.
type Operation struct {
	ID     string
	Method string // upper case
	Path   string // as written in the document, with {name} parameters; relative to the server URL
	Auth   Auth
	Rate   string
	// Also is a second rate class the pipeline charges for the operation, on the tenant of the live session (x-ctrlz-rate-also): the
	// claim routes spend the tenant's hourly claim budget besides their own class (P3 spec 4.5). Empty for most.
	Also string
	// MaxBody is the body limit in bytes. Zero means the default of 16 KiB
	// (spec 2.3). Only the passkey finish routes raise it.
	MaxBody int64
	// Token, Lock and Outbox are the three extensions of the P2 routes (spec 8.1): what an API token may do (enforced from
	// P3), how the operation meets the lock of a profile, and which outbox rows it writes. Only the tenant document
	// carries them.
	Token  string
	Lock   string
	Outbox string
	// Tags are the OpenAPI tags of the operation. The operations an API token may call carry exactly one of PublicGroups.
	Tags []string
}

// Key is what the router looks an operation up by: the method and the path
// pattern relative to the server URL.
func (o Operation) Key() string { return o.Method + " " + o.Path }

type rawOp struct {
	ID      string   `yaml:"operationId"`
	Tags    []string `yaml:"tags"`
	Auth    string   `yaml:"x-ctrlz-auth"`
	Rate    string   `yaml:"x-ctrlz-rate"`
	Also    string   `yaml:"x-ctrlz-rate-also"`
	MaxBody int64    `yaml:"x-ctrlz-max-body"`
	Token   string   `yaml:"x-ctrlz-token"`
	Lock    string   `yaml:"x-ctrlz-lock"`
	Outbox  string   `yaml:"x-ctrlz-outbox"`
}

type document struct {
	Paths map[string]map[string]yaml.Node `yaml:"paths"`
}

// methods of an OpenAPI path item that are operations. The other keys
// (parameters, summary, servers) are skipped.
func isMethod(k string) bool {
	switch k {
	case "get", "put", "post", "delete", "patch":
		return true
	}
	return false
}

// Parse reads the operations of an OpenAPI document that run behind the /api
// pipeline. Operations tagged "health" live at the server root (/healthz,
// /readyz) outside the pipeline and are not returned. Every other operation must
// carry both extensions with values this service knows; the first problem is
// returned with the operation named, never with request data.
//
// The result is sorted by key so the order is stable.
func Parse(doc []byte, service ratelimit.Service) ([]Operation, error) {
	var d document
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("apispec: %w", err)
	}
	var out []Operation
	seen := map[string]bool{}
	for path, item := range d.Paths {
		for method, node := range item {
			if !isMethod(method) {
				continue
			}
			var raw rawOp
			if err := node.Decode(&raw); err != nil {
				return nil, fmt.Errorf("apispec: %s %s: %w", method, path, err)
			}
			if isHealth(raw.Tags) {
				continue
			}
			op := Operation{ID: raw.ID, Method: upper(method), Path: path, Auth: Auth(raw.Auth), Rate: raw.Rate, Also: raw.Also, MaxBody: raw.MaxBody, Token: raw.Token, Lock: raw.Lock, Outbox: raw.Outbox, Tags: raw.Tags}
			if op.ID == "" {
				return nil, fmt.Errorf("apispec: %s has no operationId", op.Key())
			}
			if seen[op.ID] {
				return nil, fmt.Errorf("apispec: operationId %s is used twice", op.ID)
			}
			seen[op.ID] = true
			if op.Auth == "" {
				return nil, fmt.Errorf("apispec: %s (%s) has no x-ctrlz-auth", op.ID, op.Key())
			}
			if !valid(service, op.Auth) {
				return nil, fmt.Errorf("apispec: %s has x-ctrlz-auth %q, which %s does not accept", op.ID, op.Auth, service)
			}
			if op.Rate == "" {
				return nil, fmt.Errorf("apispec: %s (%s) has no x-ctrlz-rate", op.ID, op.Key())
			}
			if _, ok := ratelimit.Lookup(service, op.Rate); !ok {
				return nil, fmt.Errorf("apispec: %s has x-ctrlz-rate %q, which %s does not have", op.ID, op.Rate, service)
			}
			if op.Also != "" {
				if c, ok := ratelimit.Lookup(service, op.Also); !ok || c.Key != ratelimit.BySession || !op.Auth.NeedsSession() {
					return nil, fmt.Errorf("apispec: %s has x-ctrlz-rate-also %q, which is not a session-keyed class of %s on a route with a session", op.ID, op.Also, service)
				}
			}
			if op.MaxBody < 0 {
				return nil, fmt.Errorf("apispec: %s has a negative x-ctrlz-max-body", op.ID)
			}
			out = append(out, op)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

func isHealth(tags []string) bool {
	for _, t := range tags {
		if t == "health" {
			return true
		}
	}
	return false
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// Index maps Key to the operation.
func Index(ops []Operation) map[string]Operation {
	m := make(map[string]Operation, len(ops))
	for _, o := range ops {
		m[o.Key()] = o
	}
	return m
}

// CheckP2 fails an operation of the tenant document without the three extensions of spec 8.1, or with a value that is not
// one of theirs, so a new route cannot go live without declaring what a token may do, how it meets the lock and what it
// writes to the outbox.
func CheckP2(op Operation) error {
	in := func(v string, ok ...string) bool {
		for _, o := range ok {
			if v == o {
				return true
			}
		}
		return false
	}
	switch {
	case !in(op.Token, "none", "read", "write"):
		return fmt.Errorf("apispec: %s has no valid x-ctrlz-token", op.ID)
	case !in(op.Lock, "none", "guard", "lock", "unlock"):
		return fmt.Errorf("apispec: %s has no valid x-ctrlz-lock", op.ID)
	case !in(op.Outbox, "none", "profile", "profile+endpoint_set", "endpoint_set"):
		return fmt.Errorf("apispec: %s has no valid x-ctrlz-outbox", op.ID)
	}
	return nil
}

// PublicGroups are the groups of the public API (P3 6.5, Plan "API و اسکلت"): the tag that names the group of each operation an
// API token may call. Analytics has no operation before P5. The Default Rule is an option of a profile and has no route of its own,
// so its operations are Options.
func PublicGroups() []string {
	return []string{"profiles", "options", "filters", "services", "rule-folders", "custom-rules", "locations", "endpoints",
		"authorized-ips", "service-categories", "analytics", "account"}
}

// CheckToken fails an operation whose x-ctrlz-token is missing or not one of none, read and write, and one that takes a token
// without being able to: the token path resolves a principal that has a tenant and a user and no session, so only a plain
// session operation (not a reauth one, which asks for a window a token cannot have) may take one, and a read token is for a GET.
// An operation an API token may call carries exactly one tag of PublicGroups (the group it is documented under). The admin service
// takes no token at all: every operation of its document says none.
func CheckToken(service ratelimit.Service, op Operation) error {
	switch op.Token {
	case "none":
		return nil
	case "read", "write":
	default:
		return fmt.Errorf("apispec: %s has no valid x-ctrlz-token", op.ID)
	}
	if service != ratelimit.Tenant {
		return fmt.Errorf("apispec: %s takes an API token, which the %s service does not accept", op.ID, service)
	}
	if op.Auth != Session {
		return fmt.Errorf("apispec: %s takes an API token and has x-ctrlz-auth %q: a token has no session and no reauth window", op.ID, op.Auth)
	}
	if op.Token == "read" && op.Method != "GET" {
		return fmt.Errorf("apispec: %s is %s and declares a read token: a read token is for a GET", op.ID, op.Method)
	}
	groups := map[string]bool{}
	for _, g := range PublicGroups() {
		groups[g] = true
	}
	n := 0
	for _, t := range op.Tags {
		if groups[t] {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("apispec: %s takes an API token and has %d of the public group tags, want exactly one", op.ID, n)
	}
	return nil
}
