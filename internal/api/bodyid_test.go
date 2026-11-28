package api

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
)

// TestBodyIDReadsASentNilIdAsNotFound: uid answers the nil id for an absent member, so a sent all-zero id was read as
// "not sent" and took a rule out of its folder or moved it to the root of its own profile (p2-B3-r15-2).
func TestBodyIDReadsASentNilIdAsNotFound(t *testing.T) {
	zero := openapi_types.UUID(uuid.Nil)
	if _, err := bodyID(&zero); err == nil {
		t.Fatal("a sent all-zero id was accepted")
	} else if he := (*httpx.Error)(nil); !errors.As(err, &he) || he.Status != 404 {
		t.Fatalf("err = %v, want httpx 404", err)
	}
	if id, err := bodyID(nil); err != nil || id != uuid.Nil {
		t.Fatalf("an absent id gave %v, %v", id, err)
	}
	real := openapi_types.UUID(uuid.New())
	if id, err := bodyID(&real); err != nil || id != uuid.UUID(real) {
		t.Fatalf("a real id gave %v, %v", id, err)
	}
}

// TestBatchInRefusesANilIdAndCarriesATargetWithoutAction covers the two body shapes of rules:batch that used to be read
// as something else: a nil dest or folder id (404), and a target with no action, which CheckBatch must see (r15-1, r15-2).
func TestBatchInRefusesANilIdAndCarriesATargetWithoutAction(t *testing.T) {
	zero := openapi_types.UUID(uuid.Nil)
	for name, b := range map[string]gen.RulesBatch{
		"dest_profile_id": {Op: "move", DestProfileId: &zero},
		"dest_folder_id":  {Op: "move", DestFolderId: &zero},
		"set.folder_id":   {Op: "edit", Set: &gen.RuleEditSet{FolderId: &zero}},
	} {
		if _, err := batchIn(&b); err == nil {
			t.Errorf("%s: a sent all-zero id was accepted", name)
		}
	}
	in, err := batchIn(&gen.RulesBatch{Op: "edit", Set: &gen.RuleEditSet{Target: &gen.Target{Kind: "auto"}}})
	if err != nil {
		t.Fatal(err)
	}
	if in.Set == nil || in.Set.Act == nil || in.Set.Act.Action != "" {
		t.Fatalf("a target with no action was dropped: %+v", in.Set)
	}
}
