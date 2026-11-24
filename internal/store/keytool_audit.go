package store

import "errors"

// The audit rows of the key tool (admin-r18-6 and admin-r18-7, D64 user-totp-rekey-audit and
// keys-declare-lost-proof). The tool's login has no grant on audit_log, so the row is one call of
// ctrlz_fn.keytool_audit_key_event, which can write key.rekeyed and key.declared_lost for the user_totp
// domain and nothing else, and which takes the audit lock itself (the last lock of the transaction, after
// the users rows the same transaction holds). The callers run inside the tenant transaction of the change,
// so a change of sealed seeds cannot commit without its row.
const qKeytoolAuditKeyEvent = `SELECT ctrlz_fn.keytool_audit_key_event($1, $2, $3, $4, $5)`

var errKeytoolAuditRefused = errors.New("store: the key tool's audit row was refused")

func (t Tx) keytoolAuditKeyEvent(action string, keyNumber, rewritten, changed, failed int) error {
	var id *int64
	if err := t.tx.QueryRow(t.ctx, qKeytoolAuditKeyEvent, action,
		int32(keyNumber), int32(rewritten), int32(changed), int32(failed)).Scan(&id); err != nil {
		return sanitize(err)
	}
	if id == nil {
		return errKeytoolAuditRefused
	}
	return nil
}

// KeytoolAuditRekeyed records that this transaction re-sealed seeds under the user_totp key number
// keyNumber: how many it rewrote, found changed meanwhile, or could not open. Counts only.
func (t Tx) KeytoolAuditRekeyed(keyNumber, rewritten, changed, failed int) error {
	return t.keytoolAuditKeyEvent("key.rekeyed", keyNumber, rewritten, changed, failed)
}

// KeytoolAuditDeclaredLost records that this transaction cleared the seeds sealed under the lost
// user_totp key number keyNumber.
func (t Tx) KeytoolAuditDeclaredLost(keyNumber int) error {
	return t.keytoolAuditKeyEvent("key.declared_lost", keyNumber, 0, 0, 0)
}
