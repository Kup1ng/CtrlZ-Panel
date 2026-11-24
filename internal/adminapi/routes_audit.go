package adminapi

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/audit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// params turns a stored jsonb object into the map the API returns. A value that
// is not an object becomes an empty one.
func params(raw []byte) map[string]interface{} {
	out := map[string]interface{}{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out
}

// ListAudit is GET /audit (spec 13): the chained log, newest first, by id. The
// row shows neither hash: the chain is checked by `ctrlz-admin audit verify`.
func (s *Server) ListAudit(ctx context.Context, req gen.ListAuditRequestObject) (gen.ListAuditResponseObject, error) {
	before, err := intCursor(req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	limit := pageLimit(req.Params.Limit)
	action := deref(req.Params.Action)
	out := gen.AuditPage{Items: []gen.AuditRow{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.AuditPage(before, action, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			out.NextCursor = ptr(encodeKey(strconv.FormatInt(rows[len(rows)-1].ID, 10)))
		}
		for _, r := range rows {
			item := gen.AuditRow{Id: r.ID, At: r.At.UTC(), Action: r.Action, Params: params(r.Params)}
			if r.AdminID != nil {
				id := *r.AdminID
				item.AdminId = &id
			}
			if r.Target != "" {
				item.Target = ptr(r.Target)
			}
			if r.IP != nil {
				item.Ip = ptr(r.IP.Unmap().String())
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListAudit200JSONResponse(out), nil
}

// ListAlerts is GET /alerts: the operator's signal that a gateway has a
// credential or credit problem (9.1). Open alerts come first, then resolved ones.
func (s *Server) ListAlerts(ctx context.Context, req gen.ListAlertsRequestObject) (gen.ListAlertsResponseObject, error) {
	cur, err := decodeKey(req.Params.Cursor, 2)
	if err != nil {
		return nil, err
	}
	var resolved bool
	var after uuid.UUID
	if cur != nil {
		if cur[0] != "0" && cur[0] != "1" {
			return nil, httpx.BadRequest()
		}
		resolved = cur[0] == "1"
		if after, err = uuid.Parse(cur[1]); err != nil {
			return nil, httpx.BadRequest()
		}
	}
	limit := pageLimit(req.Params.Limit)
	out := gen.AlertPage{Items: []gen.AlertRow{}}
	err = s.readGlobal(ctx, func(g store.GlobalTx) error {
		rows, err := g.AlertsPageAfter(cur != nil, resolved, after, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			last := rows[len(rows)-1]
			flag := "0"
			if last.ResolvedAt != nil {
				flag = "1"
			}
			out.NextCursor = ptr(encodeKey(flag, last.ID.String()))
		}
		for _, r := range rows {
			out.Items = append(out.Items, gen.AlertRow{
				Id: r.ID, Severity: gen.AlertRowSeverity(r.Severity), Kind: r.Kind, Params: params(r.Params),
				CreatedAt: r.CreatedAt.UTC(), ResolvedAt: timePtr(r.ResolvedAt),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.ListAlerts200JSONResponse(out), nil
}

// AckAlert is POST /alerts/{id}/ack: it sets resolved_at and writes alert.ack.
func (s *Server) AckAlert(ctx context.Context, req gen.AckAlertRequestObject) (gen.AckAlertResponseObject, error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	err = s.global(ctx, func(g store.GlobalTx) error {
		kind, ok, err := g.AlertAck(req.Id)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.NotFound()
		}
		_, err = audit.Admin(g, s.now(), p.AdminID, httpx.ClientIPFrom(g.Context()), audit.AlertAck{Alert: req.Id, Kind: audit.AlertKindOf(kind)})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.AckAlert204Response{}, nil
}
