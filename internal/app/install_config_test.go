package app_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
)

// TestAdminInstallConfig: the admin prints the install command of an enrolment from the hub host and the two
// read-only volumes, all three or none (p4-nodes 4.2 step 1).
func TestAdminInstallConfig(t *testing.T) {
	base := map[string]string{"CTRLZ_DB_HOST": "db", "CTRLZ_DB_PASSWORD_FILE": hubEnv(t, nil)["CTRLZ_DB_PASSWORD_FILE"]}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	c, err := app.LoadConfig(app.RoleAdmin, env(with(nil)))
	if err != nil || c.Install.Enabled() {
		t.Fatalf("an admin with no hub host: %v enabled %v", err, c.Install.Enabled())
	}
	all := map[string]string{"CTRLZ_HUB_HOST": "hub.example.net", "CTRLZ_HUB_PUBLIC_DIR": "/var/lib/ctrlz/hub_public", "CTRLZ_BUNDLES_DIR": "/var/lib/ctrlz/bundles"}
	c, err = app.LoadConfig(app.RoleAdmin, env(with(all)))
	if err != nil || !c.Install.Enabled() || c.Install.Host != "hub.example.net" || c.Install.PublicDir != "/var/lib/ctrlz/hub_public" {
		t.Fatalf("an admin with the install variables: %v %+v", err, c.Install)
	}
	for _, drop := range []string{"CTRLZ_HUB_HOST", "CTRLZ_HUB_PUBLIC_DIR", "CTRLZ_BUNDLES_DIR"} {
		m := with(all)
		delete(m, drop)
		if _, err := app.LoadConfig(app.RoleAdmin, env(m)); err == nil || !strings.Contains(err.Error(), drop) {
			t.Errorf("without %s: %v", drop, err)
		}
	}
	// The hub's keys never reach the admin, and no other role takes the install variables.
	if _, err := app.LoadConfig(app.RoleAdmin, env(with(map[string]string{"CTRLZ_HUB_TLS_KEY_FILE": "/x"}))); err == nil || !strings.Contains(err.Error(), "hub only") {
		t.Errorf("a hub key on the admin: %v", err)
	}
	if _, err := app.LoadConfig(app.RoleAPI, env(with(all))); err == nil || !strings.Contains(err.Error(), "hub only") {
		t.Errorf("the install variables on the api: %v", err)
	}
}
