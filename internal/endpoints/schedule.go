package endpoints

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// ScheduleIn replaces the whole schedule of an Endpoint: its zone and its windows (T-254). No windows means no schedule.
type ScheduleIn struct {
	Timezone            string
	Windows             []WindowIn
	ConfirmDestinations bool
}

// Schedule is an Endpoint's zone and windows as stored.
type Schedule struct {
	Timezone string
	Windows  []store.WindowRow
}

// SetSchedule replaces the windows of an Endpoint in one transaction, under its row. A window that names an id the Endpoint
// has keeps it (the compiler's window_id), any other is new. It needs the lock passwords of the profiles the new schedule
// takes out of the stack at some instant of the next year, a change of the zone included (spec 3.3).
func (e *Env) SetSchedule(ctx context.Context, st *store.Store, tenant uuid.UUID, opts store.TxOpts, a Auth, id uuid.UUID, in ScheduleIn) (Schedule, error) {
	var fs []Field
	if !ValidZone(in.Timezone) {
		fs = append(fs, Field{"/timezone", CodeUnknown})
	}
	fs = append(fs, checkWindows(in.Windows)...)
	if fs != nil {
		return Schedule{}, invalid(fs...)
	}
	var named []uuid.UUID
	members := map[uuid.UUID]string{}
	for i, w := range in.Windows {
		named = append(named, w.ProfileID, w.Profile2ID)
		members[w.ProfileID] = fmt.Sprintf("/windows/%d/profile_id", i)
		if w.Profile2ID != uuid.Nil {
			members[w.Profile2ID] = fmt.Sprintf("/windows/%d/profile2_id", i)
		}
	}
	named = uniqueIDs(named)
	var out Schedule
	err := e.Run(ctx, st, tenant, opts, a, func(tx store.Tx, g *Guard) error {
		if err := g.Begin(tx, []uuid.UUID{id}, named...); err != nil {
			return err
		}
		found, err := tx.EndpointsLock([]uuid.UUID{id})
		if err != nil {
			return err
		}
		if len(found) != 1 {
			return notFound()
		}
		before, err := g.Inputs(tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		row, _, err := tx.EndpointGet(id)
		if err != nil {
			return err
		}
		old, err := tx.WindowsOf([]uuid.UUID{id})
		if err != nil {
			return err
		}
		var bad []Field
		for i, w := range in.Windows {
			if w.ID != uuid.Nil && !slices.ContainsFunc(old, func(o store.WindowRow) bool { return o.ID == w.ID }) {
				bad = append(bad, Field{fmt.Sprintf("/windows/%d/id", i), CodeUnknown})
			}
		}
		if bad != nil {
			// A window id that is not one of this Endpoint's names a row that is not the caller's.
			return notFound()
		}
		d, err := e.watchProfiles(tx, append(slices.Clone(named), before[id].Profiles()...), members)
		if err != nil {
			return err
		}
		rows := make([]store.WindowRow, len(in.Windows))
		for i, w := range in.Windows {
			wid := w.ID
			if wid == uuid.Nil {
				if wid, err = uuid.NewV7(); err != nil {
					return fmt.Errorf("endpoints: window id: %w", err)
				}
			}
			rows[i] = store.WindowRow{ID: wid, EndpointID: id, Start: w.Start, End: w.End, ProfileID: w.ProfileID, Profile2ID: w.Profile2ID}
		}
		slices.SortFunc(rows, func(x, y store.WindowRow) int { return x.Start - y.Start })
		zoneChanged := row.ScheduleTimezone != in.Timezone
		if zoneChanged {
			row.ScheduleTimezone = in.Timezone
			if err := tx.EndpointUpdate(row); err != nil {
				return err
			}
		}
		if err := tx.WindowsDelete(id); err != nil {
			return err
		}
		for _, w := range rows {
			if err := tx.WindowInsert(w); err != nil {
				return refuseWindow(err)
			}
		}
		after, err := g.Inputs(tx, []uuid.UUID{id})
		if err != nil {
			return err
		}
		if err := d.check(in.ConfirmDestinations); err != nil {
			return err
		}
		if err := g.Check(tx, before, after); err != nil {
			return err
		}
		if zoneChanged || !sameWindows(old, rows) {
			if err := store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID()); err != nil {
				return err
			}
		}
		out = Schedule{Timezone: in.Timezone, Windows: rows}
		return nil
	})
	return out, err
}

// refuseWindow maps the database's own refusal of a window, which the validation of the request should have caught: the
// exclusion constraint is an overlap and a check is the grid.
func refuseWindow(err error) error {
	switch {
	case isConflict(err):
		return invalid(Field{"/windows", CodeOverlap})
	case isConstraint(err):
		return invalid(Field{"/windows", CodeGrid})
	}
	return err
}

func sameWindows(a, b []store.WindowRow) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Start != b[i].Start || a[i].End != b[i].End || a[i].ProfileID != b[i].ProfileID || a[i].Profile2ID != b[i].Profile2ID {
			return false
		}
	}
	return true
}

// ReadSchedule reads an Endpoint's schedule.
func ReadSchedule(tx store.Tx, id uuid.UUID) (Schedule, bool, error) {
	row, ok, err := tx.EndpointGet(id)
	if err != nil || !ok {
		return Schedule{}, ok, err
	}
	ws, err := tx.WindowsOf([]uuid.UUID{id})
	return Schedule{Timezone: row.ScheduleTimezone, Windows: ws}, true, err
}
