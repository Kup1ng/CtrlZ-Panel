package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Folders, rules, options and jobs (spec 8.2).

func folderOut(f store.FolderRow, keys locationKeys) gen.Folder {
	out := gen.Folder{Id: openapi_types.UUID(f.ID), Name: f.Name, Kind: gen.FolderKind(f.Kind), Target: targetOut(f.Target, keys),
		LocationUnavailable: f.LocationUnavailable, RuleCount: f.RuleCount}
	if f.Action != "" {
		a := gen.FolderAction(f.Action)
		out.Action = &a
	}
	return out
}

// ListFolders is GET /profiles/{id}/folders.
func (s *Server) ListFolders(ctx context.Context, req gen.ListFoldersRequestObject) (gen.ListFoldersResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListFolders200JSONResponse{Folders: []gen.Folder{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if err := s.requireProfile(tx, uuid.UUID(req.Id)); err != nil {
			return err
		}
		fs, err := tx.Folders(uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		keys, err := s.locKeys(tx)
		if err != nil {
			return err
		}
		for _, f := range fs {
			out.Folders = append(out.Folders, folderOut(f, keys))
		}
		return nil
	})
	return out, err
}

// CreateFolder is POST /profiles/{id}/folders.
func (s *Server) CreateFolder(ctx context.Context, req gen.CreateFolderRequestObject) (gen.CreateFolderResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	action := ""
	if b.Action != nil {
		action = string(*b.Action)
	}
	var out gen.Folder
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		f, err := s.prof.CreateFolder(tx, uuid.UUID(req.Id), profiles.FolderIn{Name: b.Name, Kind: string(b.Kind), Act: actIn(action, b.Target)})
		if err != nil {
			return err
		}
		keys, err := s.locKeys(tx)
		out = folderOut(f, keys)
		return err
	})
	return gen.CreateFolder201JSONResponse(out), err
}

// UpdateFolder is PATCH /profiles/{id}/folders/{folder_id}.
func (s *Server) UpdateFolder(ctx context.Context, req gen.UpdateFolderRequestObject) (gen.UpdateFolderResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	patch := profiles.FolderPatch{Name: b.Name}
	if b.Action != nil {
		a := actIn(string(*b.Action), b.Target)
		patch.Act = &a
	} else if b.Target != nil {
		return nil, errValidation("/action", profiles.CodeRequired)
	}
	if b.Clear != nil {
		for _, c := range *b.Clear {
			patch.Clear = append(patch.Clear, string(c))
		}
	}
	var out gen.Folder
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		f, err := s.prof.UpdateFolder(tx, uuid.UUID(req.Id), uuid.UUID(req.FolderId), patch)
		if err != nil {
			return err
		}
		keys, err := s.locKeys(tx)
		out = folderOut(f, keys)
		return err
	})
	return gen.UpdateFolder200JSONResponse(out), err
}

// DeleteFolder is DELETE /profiles/{id}/folders/{folder_id}.
func (s *Server) DeleteFolder(ctx context.Context, req gen.DeleteFolderRequestObject) (gen.DeleteFolderResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		return s.prof.DeleteFolder(tx, uuid.UUID(req.Id), uuid.UUID(req.FolderId))
	}); err != nil {
		return nil, err
	}
	return gen.DeleteFolder204Response{}, nil
}

// ---------------------------------------------------------------------------
// Rules.

// ruleOut builds the rules of a response. iranian_bypass is true when the predicate of D42 holds for the key and the
// effective action is Redirect (the rule's own, or its folder's for inherit): such a row stays in place and acts as Bypass
// at the node (spec 3.6).
func (s *Server) ruleOut(tx store.Tx, profile uuid.UUID, rows []store.RuleRow) ([]gen.Rule, error) {
	keys, err := s.locKeys(tx)
	if err != nil {
		return nil, err
	}
	fs, err := tx.FoldersBare(profile)
	if err != nil {
		return nil, err
	}
	folders := map[uuid.UUID]*store.FolderRow{}
	for i := range fs {
		folders[fs[i].ID] = &fs[i]
	}
	var redirecting []string
	for _, r := range rows {
		if profiles.EffectiveRedirect(r.Action, folders[r.FolderID]) {
			redirecting = append(redirecting, r.Key)
		}
	}
	ir, err := s.prof.IranianKeys(tx, redirecting)
	if err != nil {
		return nil, err
	}
	out := make([]gen.Rule, 0, len(rows))
	for _, r := range rows {
		x := gen.Rule{Id: openapi_types.UUID(r.ID), FolderId: uidp(r.FolderID), Pattern: r.Key, Key: r.Key, MatchKind: gen.RuleMatchKind(r.MatchKind),
			Negated: r.Negated, Action: gen.RuleAction(r.Action), Target: targetOut(r.Target, keys), Enabled: r.Enabled, ExpiresAt: r.ExpiresAt,
			Comment: strp(r.Comment), LocationUnavailable: r.LocationUnavailable, IranianBypass: ir[r.Key] && profiles.EffectiveRedirect(r.Action, folders[r.FolderID]),
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		out = append(out, x)
	}
	return out, nil
}

// The cursor of the rules list names a position in one tenant's list under one sort: base64url of
// "sort|key-or-microseconds|id|tenant". It is a position and not a proof, so it carries no MAC; the tenant is part of it so
// that a cursor of another tenant is refused before any row is resolved (as encodeCursor does).
func encodeRuleCursor(tenant uuid.UUID, sort string, r store.RuleRow) string {
	var pos string
	switch sort {
	case "created":
		pos = strconv.FormatInt(r.CreatedAt.UnixMicro(), 10)
	case "updated":
		pos = strconv.FormatInt(r.UpdatedAt.UnixMicro(), 10)
	default:
		pos = base64.RawURLEncoding.EncodeToString([]byte(r.Key))
	}
	return base64.RawURLEncoding.EncodeToString([]byte(sort + "|" + pos + "|" + r.ID.String() + "|" + tenant.String()))
}

func decodeRuleCursor(c *string, tenant uuid.UUID, sort string) (*store.RuleCursor, error) {
	if c == nil || *c == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(*c)
	if err != nil {
		return nil, httpx.BadRequest()
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != sort {
		return nil, httpx.BadRequest()
	}
	if owner, err := uuid.Parse(parts[3]); err != nil || owner != tenant {
		return nil, httpx.BadRequest()
	}
	id, err := uuid.Parse(parts[2])
	if err != nil {
		return nil, httpx.BadRequest()
	}
	cur := &store.RuleCursor{ID: id}
	switch sort {
	case "created", "updated":
		n, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || n < cursorMinMicro || n > cursorMaxMicro {
			return nil, httpx.BadRequest()
		}
		cur.At = time.UnixMicro(n).UTC()
	default:
		b, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil || len(b) > 260 {
			return nil, httpx.BadRequest()
		}
		// Postgres refuses invalid UTF-8 and NUL in a text parameter with 22021, which would answer 500 for a crafted cursor.
		if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
			return nil, httpx.BadRequest()
		}
		cur.Text = string(b)
	}
	return cur, nil
}

// ListRules is GET /profiles/{id}/rules.
func (s *Server) ListRules(ctx context.Context, req gen.ListRulesRequestObject) (gen.ListRulesResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	profile := uuid.UUID(req.Id)
	sort := "pattern"
	if req.Params.Sort != nil {
		sort = string(*req.Params.Sort)
	}
	after, err := decodeRuleCursor((*string)(req.Params.Cursor), pr.TenantID, sort)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	sel := store.RuleSelector{Q: profiles.SearchText(str(req.Params.Q)), Now: s.now()}
	if req.Params.Status != nil {
		sel.Status = string(*req.Params.Status)
	}
	if req.Params.Action != nil {
		sel.Action = string(*req.Params.Action)
	}
	folderParam := str(req.Params.Folder)
	switch {
	case folderParam == "root":
		sel.Folder = "root"
	case folderParam != "":
		id, err := uuid.Parse(folderParam)
		if err != nil {
			return nil, httpx.BadRequest()
		}
		sel.Folder, sel.FolderID = "folder", id
	}
	out := gen.ListRules200JSONResponse{Items: []gen.Rule{}}
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if err := s.requireProfile(tx, profile); err != nil {
			return err
		}
		if sel.FolderID != uuid.Nil {
			if _, ok, err := tx.Folder(profile, sel.FolderID); err != nil {
				return err
			} else if !ok {
				return httpx.NotFound()
			}
		}
		rows, err := tx.RulePage(profile, store.RulePageIn{Selector: sel, Sort: sort, After: after, Limit: limit})
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			c := encodeRuleCursor(pr.TenantID, sort, rows[limit-1])
			out.NextCursor = &c
		}
		out.Items, err = s.ruleOut(tx, profile, rows)
		return err
	})
	return out, err
}

// CreateRules is POST /profiles/{id}/rules.
func (s *Server) CreateRules(ctx context.Context, req gen.CreateRulesRequestObject) (gen.CreateRulesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	folder, err := bodyID(b.FolderId)
	if err != nil {
		return nil, err
	}
	in := profiles.RuleIn{Patterns: b.Patterns, Act: actIn(string(b.Action), b.Target), FolderID: folder, Comment: str(b.Comment),
		Disabled: b.Enabled != nil && !*b.Enabled}
	if b.ExpiresIn != nil {
		in.Expiry.In = string(*b.ExpiresIn)
	}
	if b.ExpiresAt != nil {
		in.Expiry.At, in.Expiry.HasAt = *b.ExpiresAt, true
	}
	// The answer is one object for each pattern, at most about 1.2 KiB each, and it is spilled to disk when it is above 64 KiB.
	// The rules are committed before it is written, where no refusal can be given, so the room is reserved here, before
	// the write, at 2 KiB for each pattern (p2-B3-r10-3).
	if len(b.Patterns) > heldRulesFloor {
		if e := httpx.HoldAnswer(ctx, int64(len(b.Patterns))*ruleAnswerBytes); e != nil {
			return nil, e
		}
	}
	out := gen.CreateRules201JSONResponse{Rules: []gen.Rule{}}
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		rows, err := s.prof.CreateRules(tx, uuid.UUID(req.Id), in)
		if err != nil {
			return err
		}
		out.Rules, err = s.ruleOut(tx, uuid.UUID(req.Id), rows)
		return err
	})
	return out, err
}

// heldRulesFloor is the number of patterns of a rule create whose answer may be above 64 KiB, the size from which it is
// spilled and counted; ruleAnswerBytes is what each pattern reserves, above the largest rule object there can be.
const (
	heldRulesFloor  = 32
	ruleAnswerBytes = 2 << 10
)

// UpdateRule is PATCH /profiles/{id}/rules/{rule_id}.
func (s *Server) UpdateRule(ctx context.Context, req gen.UpdateRuleRequestObject) (gen.UpdateRuleResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	patch := profiles.RulePatch{Pattern: b.Pattern, Enabled: b.Enabled, Comment: b.Comment}
	switch {
	case b.Action != nil:
		a := actIn(string(*b.Action), b.Target)
		patch.Act = &a
	case b.Target != nil:
		return nil, errValidation("/action", profiles.CodeRequired)
	}
	if b.FolderId != nil {
		f, err := bodyID(b.FolderId)
		if err != nil {
			return nil, err
		}
		patch.FolderID = &f
	}
	if b.ExpiresIn != nil || b.ExpiresAt != nil {
		x := profiles.Expiry{}
		if b.ExpiresIn != nil {
			x.In = string(*b.ExpiresIn)
		}
		if b.ExpiresAt != nil {
			x.At, x.HasAt = *b.ExpiresAt, true
		}
		patch.Expiry = &x
	}
	if b.Clear != nil {
		for _, c := range *b.Clear {
			patch.Clear = append(patch.Clear, string(c))
		}
	}
	var out gen.Rule
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		row, err := s.prof.UpdateRule(tx, uuid.UUID(req.Id), uuid.UUID(req.RuleId), patch)
		if err != nil {
			return err
		}
		rs, err := s.ruleOut(tx, uuid.UUID(req.Id), []store.RuleRow{row})
		if err != nil {
			return err
		}
		out = rs[0]
		return nil
	})
	return gen.UpdateRule200JSONResponse(out), err
}

// DeleteRule is DELETE /profiles/{id}/rules/{rule_id}.
func (s *Server) DeleteRule(ctx context.Context, req gen.DeleteRuleRequestObject) (gen.DeleteRuleResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		return s.prof.DeleteRule(tx, uuid.UUID(req.Id), uuid.UUID(req.RuleId))
	}); err != nil {
		return nil, err
	}
	return gen.DeleteRule204Response{}, nil
}

func newFolderIn(n *gen.NewFolder) *profiles.FolderIn {
	if n == nil {
		return nil
	}
	action := ""
	if n.Action != nil {
		action = string(*n.Action)
	}
	return &profiles.FolderIn{Name: n.Name, Kind: string(n.Kind), Act: actIn(action, n.Target)}
}

// TransferRule is POST /profiles/{id}/rules/{rule_id}:transfer: the batch semantics for one id.
func (s *Server) TransferRule(ctx context.Context, req gen.TransferRuleRequestObject) (gen.TransferRuleResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	destProfile, err := bodyID(b.DestProfileId)
	if err != nil {
		return nil, err
	}
	destFolder, err := bodyID(b.DestFolderId)
	if err != nil {
		return nil, err
	}
	in := profiles.BatchIn{Op: string(b.Op), IDs: []uuid.UUID{uuid.UUID(req.RuleId)}, DestProfile: destProfile, DestFolder: destFolder,
		DestRoot: b.DestRoot != nil && *b.DestRoot, NewFolder: newFolderIn(b.NewFolder)}
	var res profiles.BatchResult
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) (e error) {
		res, e = s.prof.RulesBatch(tx, uuid.UUID(req.Id), in)
		return e
	})
	return gen.TransferRule200JSONResponse(batchOut(res)), err
}

// batchIn converts the body of rules:batch.
func batchIn(b *gen.RulesBatch) (profiles.BatchIn, error) {
	destProfile, err := bodyID(b.DestProfileId)
	if err != nil {
		return profiles.BatchIn{}, err
	}
	destFolder, err := bodyID(b.DestFolderId)
	if err != nil {
		return profiles.BatchIn{}, err
	}
	in := profiles.BatchIn{Op: string(b.Op), DestProfile: destProfile, DestFolder: destFolder,
		DestRoot: b.DestRoot != nil && *b.DestRoot, NewFolder: newFolderIn(b.NewFolder)}
	if b.Ids != nil {
		for _, id := range *b.Ids {
			in.IDs = append(in.IDs, uuid.UUID(id))
		}
	}
	if b.Selector != nil {
		sel := &profiles.Selector{Q: profiles.SearchText(str(b.Selector.Q))}
		switch f := str(b.Selector.Folder); {
		case f == "root":
			sel.Folder = "root"
		case f != "":
			if id, err := uuid.Parse(f); err == nil {
				sel.Folder, sel.FolderID = "folder", id
			}
		}
		if b.Selector.Status != nil {
			sel.Status = string(*b.Selector.Status)
		}
		if b.Selector.Action != nil {
			sel.Action = string(*b.Selector.Action)
		}
		in.Selector = sel
	}
	if b.Set != nil {
		set := &profiles.EditSet{Comment: b.Set.Comment}
		switch {
		case b.Set.Action != nil:
			a := actIn(string(*b.Set.Action), b.Set.Target)
			set.Act = &a
		case b.Set.Target != nil:
			// Carried with an empty action so CheckBatch refuses it, inline and as a job alike (p2-B3-r15-1).
			a := actIn("", b.Set.Target)
			set.Act = &a
		}
		if b.Set.ExpiresIn != nil || b.Set.ExpiresAt != nil {
			x := profiles.Expiry{}
			if b.Set.ExpiresIn != nil {
				x.In = string(*b.Set.ExpiresIn)
			}
			if b.Set.ExpiresAt != nil {
				x.At, x.HasAt = *b.Set.ExpiresAt, true
			}
			set.Expiry = &x
		}
		if b.Set.FolderId != nil {
			f, err := bodyID(b.Set.FolderId)
			if err != nil {
				return profiles.BatchIn{}, err
			}
			set.FolderID = &f
		}
		in.Set = set
	}
	if b.Clear != nil {
		for _, c := range *b.Clear {
			in.Clear = append(in.Clear, string(c))
		}
	}
	return in, nil
}

// ---------------------------------------------------------------------------
// Options.

func optionsOut(o store.OptionsRow, keys locationKeys) gen.Options {
	out := gen.Options{DefaultLocationUnavailable: o.DefaultLocationUnavailable, BlockExfiltration: o.BlockExfiltration, RebindProtection: o.RebindProtection,
		DisableDnssec: o.DisableDNSSEC, Dns64: o.DNS64, CnameFlattening: o.CNAMEFlattening, SafeSearch: o.SafeSearch, RestrictedYoutube: o.RestrictedYouTube}
	i := func(v *int32) *int {
		if v == nil {
			return nil
		}
		x := int(*v)
		return &x
	}
	out.BlockTtl, out.RedirectTtl, out.BypassTtl = i(o.BlockTTL), i(o.RedirectTTL), i(o.BypassTTL)
	if o.DefaultAction != "" {
		out.DefaultRule = &gen.DefaultRuleOption{Action: gen.DefaultRuleOptionAction(o.DefaultAction), Target: targetOut(o.DefaultTarget, keys)}
	}
	if o.BlockResponse != "" {
		out.BlockResponse = &gen.BlockResponseOption{Mode: gen.BlockResponseOptionMode(o.BlockResponse), V4: strp(o.BlockV4), V6: strp(o.BlockV6)}
	}
	if o.ECSMode != "" {
		out.Ecs = &gen.ECSOption{Mode: gen.ECSOptionMode(o.ECSMode), V4: strp(o.ECSV4), V6: strp(o.ECSV6)}
	}
	return out
}

// GetOptions is GET /profiles/{id}/options.
func (s *Server) GetOptions(ctx context.Context, req gen.GetOptionsRequestObject) (gen.GetOptionsResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Options
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		if err := s.requireProfile(tx, uuid.UUID(req.Id)); err != nil {
			return err
		}
		o, _, err := tx.Options(uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		keys, err := s.locKeys(tx)
		out = optionsOut(o, keys)
		return err
	})
	return gen.GetOptions200JSONResponse(out), err
}

// PatchOptions is PATCH /profiles/{id}/options.
func (s *Server) PatchOptions(ctx context.Context, req gen.PatchOptionsRequestObject) (gen.PatchOptionsResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	in := profiles.OptionsPatch{BlockExfiltration: b.BlockExfiltration, RebindProtection: b.RebindProtection, DisableDNSSEC: b.DisableDnssec,
		BlockTTL: b.BlockTtl, RedirectTTL: b.RedirectTtl, BypassTTL: b.BypassTtl, DNS64: b.Dns64, CNAMEFlattening: b.CnameFlattening,
		SafeSearch: b.SafeSearch, RestrictedYouTube: b.RestrictedYoutube}
	if b.DefaultRule != nil {
		in.DefaultRule = &profiles.DefaultRule{Act: actIn(string(b.DefaultRule.Action), b.DefaultRule.Target)}
	}
	if b.BlockResponse != nil {
		in.BlockResponse = &profiles.BlockResponse{Mode: string(b.BlockResponse.Mode), V4: str(b.BlockResponse.V4), V6: str(b.BlockResponse.V6)}
	}
	if b.Ecs != nil {
		in.ECS = &profiles.ECS{Mode: string(b.Ecs.Mode), V4: str(b.Ecs.V4), V6: str(b.Ecs.V6)}
	}
	if b.Clear != nil {
		for _, c := range *b.Clear {
			in.Clear = append(in.Clear, string(c))
		}
	}
	var out gen.Options
	err = s.writeTx(ctx, pr.TenantID, func(tx store.Tx) error {
		row, err := s.prof.PatchOptions(tx, uuid.UUID(req.Id), in)
		if err != nil {
			return err
		}
		keys, err := s.locKeys(tx)
		out = optionsOut(row, keys)
		return err
	})
	return gen.PatchOptions200JSONResponse(out), err
}
