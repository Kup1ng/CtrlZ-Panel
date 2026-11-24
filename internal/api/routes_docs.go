package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/Kup1ng/CtrlZ-Panel/internal/api/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Documents, the bulk routes and the jobs (spec 6, 3.5, 8.2).

// jsonResponse is an answer whose status and bytes are decided at run time: the canonical bytes of an export, which are
// written as they are, and the stored answer of an idempotent request, which a replay gives back with its first status
// (201, 202 or 200). The generated response types fix one status per type and would marshal the export again.
type jsonResponse struct {
	status int
	body   []byte
	// stream, when set, writes the body instead of body: an export is encoded straight into the answer through a small
	// buffer, so no encoded copy of the document is in memory (spec 6.5 property 8). The writer is the spool file of the
	// request, not the client.
	stream func(io.Writer) error
}

func (r jsonResponse) write(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.status)
	if r.stream != nil {
		return r.stream(w)
	}
	_, err := w.Write(r.body)
	return err
}

func (r jsonResponse) VisitExportProfileResponse(w http.ResponseWriter) error     { return r.write(w) }
func (r jsonResponse) VisitExportFolderRulesResponse(w http.ResponseWriter) error { return r.write(w) }
func (r jsonResponse) VisitImportProfileResponse(w http.ResponseWriter) error     { return r.write(w) }
func (r jsonResponse) VisitDuplicateProfileResponse(w http.ResponseWriter) error  { return r.write(w) }
func (r jsonResponse) VisitUploadFolderRulesResponse(w http.ResponseWriter) error { return r.write(w) }
func (r jsonResponse) VisitBatchRulesResponse(w http.ResponseWriter) error        { return r.write(w) }

var (
	_ gen.ExportProfileResponseObject     = jsonResponse{}
	_ gen.ExportFolderRulesResponseObject = jsonResponse{}
	_ gen.ImportProfileResponseObject     = jsonResponse{}
	_ gen.DuplicateProfileResponseObject  = jsonResponse{}
	_ gen.UploadFolderRulesResponseObject = jsonResponse{}
	_ gen.BatchRulesResponseObject        = jsonResponse{}
)

// snapshotTx runs a read of one consistent snapshot: Export, Duplicate's read and the profile list read in one read-only
// RepeatableRead transaction, so a concurrent move cannot give a rule whose folder is missing (spec 6.1).
func (s *Server) snapshotTx(ctx context.Context, tenant uuid.UUID, fn func(store.Tx) error) error {
	return profileError(s.d.Store.WithTenant(ctx, tenant, store.TxOpts{Isolation: store.RepeatableRead, ReadOnly: true}, fn))
}

// ExportProfile is GET /profiles/{id}/export.
func (s *Server) ExportProfile(ctx context.Context, req gen.ExportProfileRequestObject) (gen.ExportProfileResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var doc profiles.Document
	if err := s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) (e error) {
		doc, e = s.prof.ReadDocument(tx, uuid.UUID(req.Id))
		return
	}); err != nil {
		return nil, err
	}
	return jsonResponse{status: http.StatusOK, stream: doc.EncodeTo}, nil
}

// ExportFolderRules is GET /profiles/{id}/folders/{folder_id}/export.
func (s *Server) ExportFolderRules(ctx context.Context, req gen.ExportFolderRulesRequestObject) (gen.ExportFolderRulesResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var doc profiles.RulesDocument
	if err := s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) (e error) {
		doc, e = s.prof.ReadRulesDocument(tx, uuid.UUID(req.Id), uuid.UUID(req.FolderId))
		return
	}); err != nil {
		return nil, err
	}
	return jsonResponse{status: http.StatusOK, stream: doc.EncodeTo}, nil
}

// docCheck is the schema check of a document: CheckComponent of the one validator, with its problems as fields.
func (s *Server) docCheck(ctx context.Context) profiles.Schema {
	return func(component string, raw []byte) ([]profiles.Field, error) {
		probs, err := s.docs.CheckDocument(ctx, component, raw)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err // the deadline of the work: 503 service_unavailable, not a finding about the file
			}
			return []profiles.Field{{Name: "", Code: profiles.CodeInvalid}}, nil
		}
		out := make([]profiles.Field, 0, len(probs))
		for _, p := range probs {
			out = append(out, profiles.Field{Name: p.Pointer, Code: p.Code})
		}
		return out, nil
	}
}

// decodeFile reads the base64 of a document body. A string that is not base64 is a validation failure with the pointer
// of the member, never the 400 of the pipeline: the schema bounds its alphabet, and the handler explains the rest.
func decodeFile(document string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(document)
	if err != nil {
		return nil, errValidation("/document", profiles.CodeInvalid)
	}
	return raw, nil
}

// idempotent runs a write that carries an Idempotency-Key. The key is the first statement of the transaction, so a
// concurrent twin waits on its row (within the lock wait) and then replays the stored answer; the answer is stored in the
// same transaction as the effect, so a replay sees both or neither (spec 3.5).
func (s *Server) idempotent(ctx context.Context, tenant uuid.UUID, req profiles.Request, run func(tx store.Tx) (int, []byte, error)) (jsonResponse, error) {
	if !profiles.ValidKey(req.Key) {
		return jsonResponse{}, httpx.BadRequest()
	}
	var out jsonResponse
	err := s.writeTx(ctx, tenant, func(tx store.Tx) error {
		proceed, replay, err := s.prof.BeginKey(tx, req)
		if err != nil {
			return err
		}
		if !proceed {
			out = jsonResponse{status: replay.Status, body: replay.Body}
			return nil
		}
		status, body, err := run(tx)
		if err != nil {
			return err
		}
		out = jsonResponse{status: status, body: body}
		return s.prof.FinishKey(tx, req, status, body)
	})
	return out, err
}

// queued records a job and its outbox row and renders the 202.
func (s *Server) queued(tx store.Tx, r profiles.JobRequest) (int, []byte, error) {
	id, err := s.prof.QueueJob(tx, r)
	if err != nil {
		return 0, nil, err
	}
	row, ok, err := tx.Job(id)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, nil, httpx.Internal()
	}
	j, err := jobOut(row)
	if err != nil {
		return 0, nil, err
	}
	b, err := json.Marshal(j)
	return statusAccepted, b, err
}

// createdBody renders a ProfileCreated for the stored answer of an Import or a Duplicate.
func (s *Server) createdBody(tx store.Tx, res profiles.ImportResult) (int, []byte, error) {
	v, err := s.profileView(tx, res.Profile.ID)
	if err != nil {
		return 0, nil, err
	}
	b, err := json.Marshal(gen.ProfileCreated{Profile: v, Flagged: res.Flagged})
	return statusCreated, b, err
}

// ImportProfile is POST /profiles:import.
func (s *Server) ImportProfile(ctx context.Context, req gen.ImportProfileRequestObject) (gen.ImportProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := decodeFile(req.Body.Document)
	if err != nil {
		return nil, err
	}
	doc, err := profiles.DecodeDocument(raw, s.docCheck(ctx))
	if err != nil {
		return nil, profileError(err)
	}
	r := profiles.Request{Key: req.Params.IdempotencyKey, Method: http.MethodPost, Path: "/profiles:import", Body: raw}
	return s.idempotent(ctx, pr.TenantID, r, func(tx store.Tx) (int, []byte, error) {
		if len(doc.Rules) > profiles.JobThreshold {
			if err := s.prof.CheckImport(tx, doc, doc.Name); err != nil {
				return 0, nil, err
			}
			in, err := profiles.JobInputJSON(profiles.ImportInput{Name: doc.Name, Doc: doc})
			if err != nil {
				return 0, nil, err
			}
			return s.queued(tx, profiles.JobRequest{Kind: profiles.JobImport, Total: len(doc.Rules), Input: in})
		}
		res, err := s.prof.ImportDocument(tx, doc, doc.Name)
		if err != nil {
			return 0, nil, err
		}
		return s.createdBody(tx, res)
	})
}

// DuplicateProfile is POST /profiles/{id}:duplicate: the read of the source in one snapshot, then the write in a
// transaction of its own, never nested (RULES rule 14), so the decision of 3.4 sees what the lock holder committed.
func (s *Server) DuplicateProfile(ctx context.Context, req gen.DuplicateProfileRequestObject) (gen.DuplicateProfileResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	src := uuid.UUID(req.Id)
	name := req.Body.Name
	body, _ := json.Marshal(req.Body)
	r := profiles.Request{Key: req.Params.IdempotencyKey, Method: http.MethodPost, Path: "/profiles/" + src.String() + ":duplicate", Body: body}
	var doc profiles.Document
	// The source is read whole inside the slot of the request, whose weight covers it (spec 6.5 property 8).
	if err := s.snapshotTx(ctx, pr.TenantID, func(tx store.Tx) (e error) { doc, e = s.prof.ReadDocument(tx, src); return }); err != nil {
		var he *httpx.Error
		if !errors.As(err, &he) || he.Status != http.StatusNotFound {
			return nil, err
		}
		// The source is gone. A retry of a Duplicate that succeeded before its source was deleted must get the stored
		// answer, not a 404: the key is looked up, and a first-time request rolls the claim back and answers 404.
		return s.idempotent(ctx, pr.TenantID, r, func(store.Tx) (int, []byte, error) { return 0, nil, err })
	}
	return s.idempotent(ctx, pr.TenantID, r, func(tx store.Tx) (int, []byte, error) {
		if len(doc.Rules) > profiles.JobThreshold {
			if err := s.prof.CheckImport(tx, doc, name); err != nil {
				return 0, nil, err
			}
			in, err := profiles.JobInputJSON(profiles.DuplicateInput{Source: src, Name: name})
			if err != nil {
				return 0, nil, err
			}
			return s.queued(tx, profiles.JobRequest{Kind: profiles.JobDuplicate, Total: len(doc.Rules), Input: in})
		}
		res, err := s.prof.ImportDocument(tx, doc, name)
		if err != nil {
			return 0, nil, err
		}
		return s.createdBody(tx, res)
	})
}

// UploadFolderRules is POST /profiles/{id}/folders/{folder_id}:upload.
func (s *Server) UploadFolderRules(ctx context.Context, req gen.UploadFolderRulesRequestObject) (gen.UploadFolderRulesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	mode := "new_only"
	if req.Body.Mode != nil {
		mode = string(*req.Body.Mode)
	}
	raw, err := decodeFile(req.Body.Document)
	if err != nil {
		return nil, err
	}
	doc, err := profiles.DecodeRulesDocument(raw, s.docCheck(ctx))
	if err != nil {
		return nil, profileError(err)
	}
	profile, folder := uuid.UUID(req.Id), uuid.UUID(req.FolderId)
	q := url.Values{"mode": {mode}}
	r := profiles.Request{Key: req.Params.IdempotencyKey, Method: http.MethodPost,
		Path: "/profiles/" + profile.String() + "/folders/" + folder.String() + ":upload", Params: q.Encode(), Body: raw}
	return s.idempotent(ctx, pr.TenantID, r, func(tx store.Tx) (int, []byte, error) {
		if len(doc.Rules) > profiles.JobThreshold {
			if _, ok, err := tx.Folder(profile, folder); err != nil {
				return 0, nil, err
			} else if !ok {
				return 0, nil, httpx.NotFound()
			}
			if err := s.prof.CheckUploadShape(tx, doc, mode); err != nil {
				return 0, nil, err
			}
			in, err := profiles.JobInputJSON(profiles.UploadInput{FolderID: folder, Mode: mode, Doc: doc})
			if err != nil {
				return 0, nil, err
			}
			return s.queued(tx, profiles.JobRequest{Kind: profiles.JobUpload, Profile: profile, Total: len(doc.Rules), Input: in})
		}
		res, err := s.prof.UploadRules(tx, profile, folder, doc, mode)
		if err != nil {
			return 0, nil, err
		}
		b, err := json.Marshal(batchOut(res))
		return http.StatusOK, b, err
	})
}

// BatchRules is POST /profiles/{id}/rules:batch. A selection of more than 1,000 rules is a job.
func (s *Server) BatchRules(ctx context.Context, req gen.BatchRulesRequestObject) (gen.BatchRulesResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.BadRequest()
	}
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	profile := uuid.UUID(req.Id)
	in := batchIn(req.Body)
	body, _ := json.Marshal(req.Body)
	r := profiles.Request{Key: req.Params.IdempotencyKey, Method: http.MethodPost, Path: "/profiles/" + profile.String() + "/rules:batch", Body: body}
	return s.idempotent(ctx, pr.TenantID, r, func(tx store.Tx) (int, []byte, error) {
		// The checks that need no row work come first, so a malformed request is the same 422 as inline and a request
		// above the tenant's own max_rules_per_request is never queued (spec 3.4, 3.5).
		lim, err := s.prof.CheckBatch(tx, profile, in)
		if err != nil {
			return 0, nil, err
		}
		n := len(in.IDs)
		if in.Selector != nil && len(in.IDs) == 0 {
			sel := store.RuleSelector{Folder: in.Selector.Folder, FolderID: in.Selector.FolderID, Q: in.Selector.Q, Status: in.Selector.Status,
				Action: in.Selector.Action, Now: s.now(), MaxResult: max(profiles.JobThreshold, lim.MaxRulesPerRequest)}
			ids, err := tx.RuleIDsMatching(profile, sel)
			if err != nil {
				return 0, nil, err
			}
			// The count must reach the tenant's own limit, or a limit above the job threshold could never be seen
			// exceeded here and the request would hold the job slot only to fail (spec 3.4, 3.5).
			n = len(ids)
		}
		if n > profiles.JobThreshold {
			if n > lim.MaxRulesPerRequest {
				return 0, nil, &profiles.Error{Kind: profiles.KindValidation, Fields: []profiles.Field{{Name: "max_rules_per_request", Code: profiles.CodeExceeded}}}
			}
			input, err := profiles.JobInputJSON(in)
			if err != nil {
				return 0, nil, err
			}
			jr := profiles.JobRequest{Kind: profiles.JobRulesBatch, Profile: profile, Total: n, Input: input}
			if in.Op == "copy" {
				jr.Dest = in.DestProfile
			}
			return s.queued(tx, jr)
		}
		res, err := s.prof.RulesBatch(tx, profile, in)
		if err != nil {
			return 0, nil, err
		}
		b, err := json.Marshal(batchOut(res))
		return http.StatusOK, b, err
	})
}

// ---------------------------------------------------------------------------
// Jobs.

// jobOut renders a job row: its result and its error come from the stored JSON, which holds closed codes only.
func jobOut(j store.JobRow) (gen.Job, error) {
	out := gen.Job{Id: openapi_types.UUID(j.ID), Kind: gen.JobKind(j.Kind), State: gen.JobState(j.State), Progress: j.Progress, Total: j.Total}
	// profile_id is the new profile of a finished Import or Duplicate (spec 8.3). The row also holds the path profile
	// of a rules_batch or upload job, and the source of a Duplicate that is not done yet; neither is what the field names.
	if j.State == "done" && (gen.JobKind(j.Kind) == gen.JobKindImport || gen.JobKind(j.Kind) == gen.JobKindDuplicate) {
		out.ProfileId = uidp(j.ProfileID)
	}
	if len(j.Result) > 0 {
		var r gen.BatchResult
		if err := json.Unmarshal(j.Result, &r); err != nil {
			return gen.Job{}, err
		}
		if r.Items == nil {
			r.Items = []gen.BatchItem{}
		}
		out.Result = &r
	}
	if len(j.Error) > 0 {
		var e struct {
			Code   string `json:"code"`
			Fields []struct {
				Name string `json:"name"`
				Code string `json:"code"`
			} `json:"fields"`
		}
		if err := json.Unmarshal(j.Error, &e); err != nil {
			return gen.Job{}, err
		}
		ge := &gen.Error{Code: e.Code}
		if len(e.Fields) > 0 {
			fs := make([]struct {
				Code string `json:"code"`
				Name string `json:"name"`
			}, 0, len(e.Fields))
			for _, f := range e.Fields {
				fs = append(fs, struct {
					Code string `json:"code"`
					Name string `json:"name"`
				}{Code: f.Code, Name: f.Name})
			}
			ge.Fields = &fs
		}
		out.Error = ge
	}
	return out, nil
}

// GetActiveJob is GET /jobs/active: the queued or running job, so a client that lost the 202 resumes polling.
func (s *Server) GetActiveJob(ctx context.Context, _ gen.GetActiveJobRequestObject) (gen.GetActiveJobResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.ActiveJob
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		row, ok, err := tx.JobActive()
		if err != nil || !ok {
			return err
		}
		j, err := jobOut(row)
		out.Job = &j
		return err
	})
	return gen.GetActiveJob200JSONResponse(out), err
}

// GetJob is GET /jobs/{id}.
func (s *Server) GetJob(ctx context.Context, req gen.GetJobRequestObject) (gen.GetJobResponseObject, error) {
	pr, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	var out gen.Job
	err = s.readTenant(ctx, pr.TenantID, func(tx store.Tx) error {
		row, ok, err := tx.Job(uuid.UUID(req.Id))
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		out, err = jobOut(row)
		return err
	})
	return gen.GetJob200JSONResponse(out), err
}
