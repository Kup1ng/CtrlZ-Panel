package profiles

import (
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// IranianKeys says, for each rule key, whether it is an Iranian name by the shared predicate (spec 3.6). Reads come back
// with iranian_bypass when the predicate holds and the effective action is Redirect, so the UI marks a rule that a later
// list version covers: it acts as Bypass at the node (SC 10.5). Only the booleans leave the lookup (S8).
func (e *Env) IranianKeys(tx store.Tx, keys []string) (map[string]bool, error) {
	out := make(map[string]bool, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	var ps []rules.Pattern
	var ok []string
	for _, k := range keys {
		p, err := parse(k)
		if err != nil {
			continue // a stored key always parses; skip rather than fail a read
		}
		ps, ok = append(ps, p.p), append(ok, k)
	}
	w := &wtx{e: e, tx: tx}
	ir, err := w.iranian(ps)
	if err != nil {
		return nil, err
	}
	for i, k := range ok {
		out[k] = ir[i]
	}
	return out, nil
}

// EffectiveRedirect is whether the rule's effective action is Redirect: its own, or its folder's for inherit.
func EffectiveRedirect(action string, folder *store.FolderRow) bool {
	return effRedirect(action, folder)
}
