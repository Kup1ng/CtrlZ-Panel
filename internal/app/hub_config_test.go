package app_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
)

// hubEnv writes the files the node port reads and returns the environment that names them.
func hubEnv(t *testing.T, extra map[string]string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	m := map[string]string{
		"CTRLZ_DB_HOST": "db", "CTRLZ_DB_PASSWORD_FILE": write("pw", "pw"),
		"CTRLZ_HUB_HOST":         "hub.example.net,203.0.113.9",
		"CTRLZ_NODE_CA_KEY_FILE": write("ca.key", "NODE-CA-KEY-CANARY"), "CTRLZ_NODE_CA_PEM_FILE": write("ca.pem", "pem"),
		"CTRLZ_HUB_TLS_KEY_FILE": write("tls.key", "HUB-TLS-KEY-CANARY"), "CTRLZ_ZONE_CA_KEY_FILE": write("zone.key", "ZONE-KEY-CANARY"),
		"CTRLZ_HUB_PUBLIC_DIR": dir, "CTRLZ_BUNDLES_DIR": dir,
		"CTRLZ_POLICY_KEY_FILE": write("policy.key", "POLICY-KEY-CANARY"), "CTRLZ_HUB_ARTIFACTS_DIR": dir, "CTRLZ_PROOF_KEY_FILE": write("proof.key", "PROOF-KEY-CANARY"),
		"CTRLZ_WILDCARD_INTAKE_KEY_FILE": write("wildcard.key", "WILDCARD-KEY-CANARY"),
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestHubNodePortConfig(t *testing.T) {
	c, err := app.LoadConfig(app.RoleHub, env(hubEnv(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Hub.Enabled() || c.Hub.Listen != "0.0.0.0:9443" || c.Hub.Host != "hub.example.net,203.0.113.9" {
		t.Fatalf("hub config: %+v", c.Hub)
	}
	// The keys are secrets: no format of the config prints one.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(verb, c); strings.Contains(s, "KEY-CANARY") {
			t.Fatalf("%s of the config prints a key", verb)
		}
	}
	// The sum of the pools is the one size the hub's pool setting may take.
	if _, err := app.LoadConfig(app.RoleHub, env(hubEnv(t, map[string]string{"CTRLZ_DB_MAX_CONNS": "13"}))); err != nil {
		t.Fatalf("13 connections: %v", err)
	}
	if _, err := app.LoadConfig(app.RoleHub, env(hubEnv(t, map[string]string{"CTRLZ_DB_MAX_CONNS": "4"}))); err == nil || !strings.Contains(err.Error(), "13") {
		t.Fatalf("4 connections: %v", err)
	}
}

func TestHubNodePortConfigRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		role  app.Role
		extra map[string]string
		drop  string
		want  string
	}{
		"a missing key variable":        {app.RoleHub, nil, "CTRLZ_ZONE_CA_KEY_FILE", "CTRLZ_ZONE_CA_KEY_FILE"},
		"a missing directory variable":  {app.RoleHub, nil, "CTRLZ_BUNDLES_DIR", "CTRLZ_BUNDLES_DIR"},
		"a missing policy key":          {app.RoleHub, nil, "CTRLZ_POLICY_KEY_FILE", "CTRLZ_POLICY_KEY_FILE"},
		"a missing artifacts directory": {app.RoleHub, nil, "CTRLZ_HUB_ARTIFACTS_DIR", "CTRLZ_HUB_ARTIFACTS_DIR"},
		"no proof key":                  {app.RoleHub, nil, "CTRLZ_PROOF_KEY_FILE", "CTRLZ_PROOF_KEY_FILE"},
		"no wildcard intake key":        {app.RoleHub, nil, "CTRLZ_WILDCARD_INTAKE_KEY_FILE", "CTRLZ_WILDCARD_INTAKE_KEY_FILE"},
		"a key file that is not there":  {app.RoleHub, map[string]string{"CTRLZ_HUB_TLS_KEY_FILE": "/no/such/key"}, "", "/no/such/key"},
		"no database":                   {app.RoleHub, nil, "CTRLZ_DB_HOST", "CTRLZ_DB_HOST"},
		"the port on the api":           {app.RoleAPI, map[string]string{"CTRLZ_HUB_HOST": "x"}, "", "hub only"},
		"a file variable on the admin":  {app.RoleAdmin, map[string]string{"CTRLZ_NODE_CA_KEY_FILE": "/x"}, "", "hub only"},
	} {
		m := hubEnv(t, tc.extra)
		if tc.role != app.RoleHub {
			m = map[string]string{"CTRLZ_DB_HOST": "db", "CTRLZ_DB_PASSWORD_FILE": m["CTRLZ_DB_PASSWORD_FILE"]}
			for k, v := range tc.extra {
				m[k] = v
			}
		}
		if tc.drop != "" {
			delete(m, tc.drop)
		}
		if _, err := app.LoadConfig(tc.role, env(m)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
	// The admin takes the host and the two read-only volumes of the install command of an enrolment, and none of the hub's keys
	// (W3-r5-2, W10): a host alone would print a command that cannot work, so it is refused.
	am := map[string]string{"CTRLZ_DB_HOST": "db", "CTRLZ_DB_PASSWORD_FILE": hubEnv(t, nil)["CTRLZ_DB_PASSWORD_FILE"], "CTRLZ_HUB_HOST": "hub.example.net"}
	if _, err := app.LoadConfig(app.RoleAdmin, env(am)); err == nil || !strings.Contains(err.Error(), "CTRLZ_HUB_PUBLIC_DIR") {
		t.Errorf("the admin with the host alone: %v", err)
	}
	am["CTRLZ_HUB_PUBLIC_DIR"], am["CTRLZ_BUNDLES_DIR"] = hubEnv(t, nil)["CTRLZ_HUB_PUBLIC_DIR"], hubEnv(t, nil)["CTRLZ_BUNDLES_DIR"]
	if ac, err := app.LoadConfig(app.RoleAdmin, env(am)); err != nil || ac.Install.Host != "hub.example.net" {
		t.Errorf("the admin with the install variables: %v, host %q", err, ac.Install.Host)
	}
	// A hub with no CTRLZ_HUB_HOST serves the health mux alone, and a leftover file variable is a mistake.
	m := hubEnv(t, nil)
	delete(m, "CTRLZ_HUB_HOST")
	if _, err := app.LoadConfig(app.RoleHub, env(m)); err == nil || !strings.Contains(err.Error(), "CTRLZ_HUB_HOST") {
		t.Errorf("file variables without a host: %v", err)
	}
	for _, k := range []string{"CTRLZ_HUB_LISTEN", "CTRLZ_NODE_CA_KEY_FILE", "CTRLZ_NODE_CA_PEM_FILE", "CTRLZ_HUB_TLS_KEY_FILE", "CTRLZ_ZONE_CA_KEY_FILE", "CTRLZ_HUB_PUBLIC_DIR", "CTRLZ_BUNDLES_DIR", "CTRLZ_POLICY_KEY_FILE", "CTRLZ_HUB_ARTIFACTS_DIR", "CTRLZ_WILDCARD_INTAKE_KEY_FILE"} {
		delete(m, k)
	}
	c, err := app.LoadConfig(app.RoleHub, env(m))
	if err != nil || c.Hub.Enabled() {
		t.Errorf("a hub with no node port: %v enabled %v", err, c.Hub.Enabled())
	}
}
