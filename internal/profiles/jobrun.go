package profiles

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The work of a batch job (spec 3.5). The handler of the River job calls Run, which enters WithTenant for each of
// three transactions in turn, never nested (RULES rule 14): claim, work, and, on a refusal, mark-failed. The work is the
// code of the routes, so the guard, the quotas, the location and D42 checks run again against the state at run time.

// The kinds of a job, closed.
const (
	JobRulesBatch = "rules_batch"
	JobUpload     = "upload"
	JobImport     = "import"
	JobDuplicate  = "duplicate"
)

// JobKinds lists the kinds.
func JobKinds() []string { return []string{JobRulesBatch, JobUpload, JobImport, JobDuplicate} }

// UploadInput is the input of an upload job.
type UploadInput struct {
	FolderID uuid.UUID
	Mode     string
	Doc      RulesDocument
}

// ImportInput is the input of an import job: the decoded and validated document. Name is the name of the new profile.
type ImportInput struct {
	Name string
	Doc  Document
}

// DuplicateInput is the input of a duplicate job; the source is read again when the job runs.
type DuplicateInput struct {
	Source uuid.UUID
	Name   string
}

// JobInputJSON encodes the input of a job of the kind from the typed value.
func JobInputJSON(v any) ([]byte, error) { return json.Marshal(v) }

// ResultJSON is the stored and returned form of a BatchResult.
type ResultJSON struct {
	Created  int          `json:"created"`
	Updated  int          `json:"updated"`
	Skipped  int          `json:"skipped"`
	Conflict int          `json:"conflict"`
	Flagged  int          `json:"flagged"`
	Items    []ResultItem `json:"items"`
}

// ResultItem is one item of a result.
type ResultItem struct {
	Index   int        `json:"index"`
	Outcome string     `json:"outcome"`
	ID      *uuid.UUID `json:"id,omitempty"`
}

// ToJSON turns a result into its wire form.
func (r BatchResult) ToJSON() ResultJSON {
	out := ResultJSON{Created: r.Created, Updated: r.Updated, Skipped: r.Skipped, Conflict: r.Conflict, Flagged: r.Flagged, Items: []ResultItem{}}
	for _, it := range r.Items {
		x := ResultItem{Index: it.Index, Outcome: it.Outcome}
		if it.ID != uuid.Nil {
			id := it.ID
			x.ID = &id
		}
		out.Items = append(out.Items, x)
	}
	return out
}

// ErrJobGone says the job ended before its work did (a mark-failed came between): the work rolled back and the
// delivery is done, it is not an error to retry.
var ErrJobGone = errors.New("profiles: the job is no longer running")

// JobRunner runs the jobs of one tenant at a time through the store of the worker.
type JobRunner struct {
	Env   *Env
	Store *store.Store
}

// jobAttempts is how many runs a job gets before it only fails (D31); River counts them and the handler passes the
// number in.
const JobAttempts = 3

// Run runs one job of the tenant. It returns nil when the job was done, failed with a refusal, or was no longer there
// to run; it returns an error only for what a later attempt may mend (a lost connection, a lock wait that timed out),
// which River retries. The error text holds no request data.
func (r *JobRunner) Run(ctx context.Context, tenant, id uuid.UUID) error {
	var work store.JobWork
	claimed := false
	err := r.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		w, won, err := tx.JobClaim(id)
		if err != nil {
			return err
		}
		if won.Yes() {
			work, claimed = w, true
		}
		return nil
	})
	if err != nil || !claimed {
		return err
	}

	// A duplicate reads its source in a transaction of its own, then writes in another: the decision of 3.4 then sees
	// what the lock holder committed (spec 6.1).
	var src Document
	var dup DuplicateInput
	if work.Kind == JobDuplicate {
		if err := json.Unmarshal(work.Input, &dup); err != nil {
			return r.fail(ctx, tenant, id, invalid(Field{"", CodeType}))
		}
		err := r.Store.WithTenant(ctx, tenant, store.TxOpts{Isolation: store.RepeatableRead, ReadOnly: true}, func(tx store.Tx) error {
			d, err := r.Env.ReadDocument(tx, dup.Source)
			src = d
			return err
		})
		if err != nil {
			return r.settle(ctx, tenant, id, err)
		}
	}

	err = r.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		e := *r.Env
		e.gate = func(tx store.Tx) error {
			running, err := tx.JobRunning(id)
			if err != nil {
				return err
			}
			if !running {
				return ErrJobGone
			}
			return nil
		}
		res, profile, err := e.runWork(tx, work, src, dup)
		if err != nil {
			return err
		}
		body, err := json.Marshal(res.ToJSON())
		if err != nil {
			return err
		}
		won, err := tx.JobFinish(id, body, profile)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return ErrJobGone
		}
		return nil
	})
	return r.settle(ctx, tenant, id, err)
}

// settle maps the end of the work: done, gone, a refusal that fails the job once, or an error to retry.
func (r *JobRunner) settle(ctx context.Context, tenant, id uuid.UUID, err error) error {
	switch {
	case err == nil, errors.Is(err, ErrJobGone):
		return nil
	}
	if _, refused := RefusalJSON(err); refused {
		return r.fail(ctx, tenant, id, err)
	}
	return err
}

// fail is mark-failed, touching only batch_jobs, in a transaction of its own after the work rolled back.
func (r *JobRunner) fail(ctx context.Context, tenant, id uuid.UUID, cause error) error {
	body, _ := RefusalJSON(cause)
	return r.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		won, err := tx.JobFail(id, body)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return nil // already ended by another delivery: one winner
		}
		return nil
	})
}

// Exhausted ends a job whose attempts ran out (spec 3.5): the fourth delivery only marks it failed.
func (r *JobRunner) Exhausted(ctx context.Context, tenant, id uuid.UUID) error {
	body, _ := json.Marshal(jobError{Code: "job_attempts_exhausted"})
	return r.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		won, err := tx.JobFail(id, body)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return nil
		}
		return nil
	})
}

// runWork runs the code of the route of the job kind. It returns the result and the profile an Import or a Duplicate
// made.
func (e *Env) runWork(tx store.Tx, work store.JobWork, src Document, dup DuplicateInput) (BatchResult, uuid.UUID, error) {
	switch work.Kind {
	case JobRulesBatch:
		var in BatchIn
		if err := json.Unmarshal(work.Input, &in); err != nil {
			return BatchResult{}, uuid.Nil, invalid(Field{"", CodeType})
		}
		res, err := e.RulesBatch(tx, work.ProfileID, in)
		return res, uuid.Nil, err
	case JobUpload:
		var in UploadInput
		if err := json.Unmarshal(work.Input, &in); err != nil {
			return BatchResult{}, uuid.Nil, invalid(Field{"", CodeType})
		}
		res, err := e.UploadRules(tx, work.ProfileID, in.FolderID, in.Doc, in.Mode)
		return res, uuid.Nil, err
	case JobImport:
		var in ImportInput
		if err := json.Unmarshal(work.Input, &in); err != nil {
			return BatchResult{}, uuid.Nil, invalid(Field{"", CodeType})
		}
		out, err := e.ImportDocument(tx, in.Doc, in.Name)
		if err != nil {
			return BatchResult{}, uuid.Nil, err
		}
		return BatchResult{Flagged: out.Flagged}, out.Profile.ID, nil
	case JobDuplicate:
		out, err := e.ImportDocument(tx, src, dup.Name)
		if err != nil {
			return BatchResult{}, uuid.Nil, err
		}
		return BatchResult{Flagged: out.Flagged}, out.Profile.ID, nil
	}
	return BatchResult{}, uuid.Nil, invalid(Field{"/kind", CodeInvalid})
}
