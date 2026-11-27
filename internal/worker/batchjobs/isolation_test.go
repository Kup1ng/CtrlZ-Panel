package batchjobs_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// queueFolder makes a folder in the profile of a tenant and returns its id.
func (f *fx) queueFolder(t *testing.T, tenant, profile uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.tenant.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		row, err := f.env.CreateFolder(tx, profile, profiles.FolderIn{Name: name, Kind: "standard"})
		id = row.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestEachJobKindHasItsTwoTenantCase: the job variant of every bulk operation runs end to end for tenant B with B's own ids
// (B's rows change, A's do not), and again with the ids of A named inside B's job, where the job fails not_found and A's rows
// are as they were (spec 10.1). A job's tenant is the one of its outbox row, never a member of its input, so an id of A in the
// input finds no row.
func TestEachJobKindHasItsTwoTenantCase(t *testing.T) {
	f := newFx(t)
	aSrc := f.seedProfile(t, f.A.Tenant, "A src", "a1.example", "a2.example")
	aFolder := f.queueFolder(t, f.A.Tenant, aSrc, "A folder")
	aIDs := f.ruleIDs(t, f.A.Tenant, aSrc)
	bSrc := f.seedProfile(t, f.B.Tenant, "B src", "b1.example", "b2.example")
	bFolder := f.queueFolder(t, f.B.Tenant, bSrc, "B folder")
	bIDs := f.ruleIDs(t, f.B.Tenant, bSrc)
	bDst := f.seedProfile(t, f.B.Tenant, "B dst")
	digest := func(tenant uuid.UUID) string {
		var s string
		f.scan(t, `SELECT (SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rules x WHERE tenant_id = $1) || '/' ||
			(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.profiles x WHERE tenant_id = $1) || '/' ||
			(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rule_folders x WHERE tenant_id = $1)`, []any{tenant}, &s)
		return s
	}
	f.start(t)

	type kase struct {
		name, kind string
		profile    uuid.UUID
		total      int
		own, other any
	}
	cases := []kase{
		{"rules batch", profiles.JobRulesBatch, bSrc, 2,
			profiles.BatchIn{Op: "copy", IDs: bIDs, DestProfile: bDst, DestRoot: true},
			profiles.BatchIn{Op: "disable", IDs: aIDs}},
		{"upload", profiles.JobUpload, bSrc, 1,
			profiles.UploadInput{FolderID: bFolder, Mode: "new_only", Doc: rulesDoc("up1.example")},
			profiles.UploadInput{FolderID: aFolder, Mode: "new_only", Doc: rulesDoc("up2.example")}},
		{"duplicate", profiles.JobDuplicate, bSrc, 2,
			profiles.DuplicateInput{Source: bSrc, Name: "B copy"},
			profiles.DuplicateInput{Source: aSrc, Name: "A copy by B"}},
	}
	for _, c := range cases {
		beforeA := digest(f.A.Tenant)
		beforeB := digest(f.B.Tenant)
		f.runToDone(t, f.queue(t, f.B.Tenant, c.kind, c.profile, c.total, c.own))
		if digest(f.B.Tenant) == beforeB {
			t.Errorf("%s: B's own job changed nothing of B", c.name)
		}
		if digest(f.A.Tenant) != beforeA {
			t.Errorf("%s: B's own job changed A's rows", c.name)
		}
		bad := f.queue(t, f.B.Tenant, c.kind, c.profile, c.total, c.other)
		testwait.Until(t, 90*time.Second, "the job to end", func() bool { st, _ := f.state(t, bad); return st == "done" || st == "failed" })
		s, e := f.state(t, bad)
		var got struct {
			Code string `json:"code"`
		}
		if s != "failed" || json.Unmarshal([]byte(e), &got) != nil || got.Code != "not_found" {
			t.Errorf("%s: B's job naming A's ids is %s with %s, want failed with not_found", c.name, s, e)
		}
		if digest(f.A.Tenant) != beforeA {
			t.Errorf("%s: B's job naming A's ids changed A's rows", c.name)
		}
	}
}

func rulesDoc(patterns ...string) profiles.RulesDocument {
	d := profiles.RulesDocument{Format: profiles.RulesFormat, Version: profiles.DocVersion}
	for _, p := range patterns {
		d.Rules = append(d.Rules, profiles.DocRule{Pattern: p, Action: "block"})
	}
	return d
}
