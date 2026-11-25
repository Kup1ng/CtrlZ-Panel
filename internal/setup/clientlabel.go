package setup

import (
	"errors"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
)

// The three refusals of the client label rule (P3 3.8). The route turns each
// into the field code of the same name; "exists" is the store's, because
// uniqueness per Endpoint needs the table.
var (
	ErrLabelRequired = errors.New("setup: client label required")
	ErrLabelInvalid  = errors.New("setup: client label invalid")
	ErrLabelReserved = errors.New("setup: client label reserved")
)

// defaultLabel is the label the hub gives Plain DNS and overflow traffic (SC 12).
// A person cannot create it: a manual client with that label would take that
// traffic's row and its settings.
const defaultLabel = "default"

// ClientLabel decides the label of a new manual client: the label as given when
// there is one, which must already be in the grammar of SC 3.1 (it is not
// normalized, so what a person types is what the hostname will say), otherwise
// identity.SlugClient of the alias, the one normalizer behind DoH, DoT, DoQ and
// the wizard. An alias that leaves nothing after the slug (Persian text lives
// only in the alias) is ErrLabelRequired, so the wizard asks for a label.
func ClientLabel(label, alias string) (string, error) {
	if label == "" {
		slug, ok := identity.SlugClient(alias)
		if !ok {
			return "", ErrLabelRequired
		}
		label = slug
	} else if !identity.ValidClient(label) {
		return "", ErrLabelInvalid
	}
	if label == defaultLabel {
		return "", ErrLabelReserved
	}
	return label, nil
}
