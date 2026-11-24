package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// timeLayout is RFC 3339 in UTC to microseconds, the precision of timestamptz.
const timeLayout = "2006-01-02T15:04:05.000000Z"

// Canonical is the byte string the chain hashes (spec 13.1): the JSON of
// {at, admin_id, action, target, params, ip} with sorted keys and no spaces.
// There is one definition, here, and the store hashes whatever it is given, so
// the writer and `audit verify` cannot drift apart.
//
// params is re-encoded from its parsed form, so the form Postgres stores (jsonb
// reorders keys and drops whitespace) hashes the same as the form the writer
// had. Absent values are JSON null.
func Canonical(at time.Time, admin uuid.UUID, action, target string, params []byte, ip netip.Addr) ([]byte, error) {
	var p any = map[string]any{}
	if len(bytes.TrimSpace(params)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(params))
		dec.UseNumber() // keep 5 as 5, not 5.0 or 5e0
		if err := dec.Decode(&p); err != nil {
			return nil, errors.New("audit: params are not JSON")
		}
	}
	m := map[string]any{
		"at":       at.UTC().Truncate(time.Microsecond).Format(timeLayout),
		"admin_id": nil,
		"action":   action,
		"target":   nil,
		"params":   p,
		"ip":       nil,
	}
	if admin != uuid.Nil {
		m["admin_id"] = admin.String()
	}
	if target != "" {
		m["target"] = target
	}
	if ip.IsValid() {
		m["ip"] = ip.WithZone("").Unmap().String() // inet has no zone
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // encoding/json sorts map keys
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// ChainError says where the chain is broken. Row is the id of the first bad row.
type ChainError struct {
	Row    int64
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit chain broken at row %d: %s", e.Row, e.Reason)
}

// VerifyChain recomputes the hashes of rows, which must be in chain order. prev
// is the entry hash of the row before the first one (nil from the start of the
// table). It returns the last entry hash, so a long chain can be checked in
// pages, and a *ChainError for the first row whose link or hash is wrong.
func VerifyChain(prev []byte, rows []store.AuditRow) ([]byte, error) {
	for _, r := range rows {
		if !bytes.Equal(r.PrevHash, prev) {
			return prev, &ChainError{Row: r.ID, Reason: "prev_hash does not match the row before"}
		}
		admin := uuid.Nil
		if r.AdminID != nil {
			admin = *r.AdminID
		}
		var ip netip.Addr
		if r.IP != nil {
			ip = *r.IP
		}
		canon, err := Canonical(r.At, admin, r.Action, r.Target, r.Params, ip)
		if err != nil {
			return prev, &ChainError{Row: r.ID, Reason: "params cannot be read"}
		}
		h := sha256.New()
		h.Write(prev)
		h.Write(canon)
		if !bytes.Equal(h.Sum(nil), r.EntryHash) {
			return prev, &ChainError{Row: r.ID, Reason: "entry_hash does not match the row"}
		}
		prev = r.EntryHash
	}
	return prev, nil
}
