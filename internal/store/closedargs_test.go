package store_test

import "github.com/Kup1ng/CtrlZ-Panel/internal/closed"

// word is a closed.Text for the tests that exercise the status columns with
// arbitrary text. Production code passes sms.Code or sms.Status; the store only needs
// the interface (rule closed-values-in-logs).
type word string

func (w word) String() string { return string(w) }
func (word) Valid() bool      { return true }

// badWord is a Text that is off its list.
type badWord string

func (w badWord) String() string { return string(w) }
func (badWord) Valid() bool      { return false }

// key makes an alert key from fixed test words.
func key(parts ...string) closed.Key {
	ts := make([]closed.Text, len(parts))
	for i, p := range parts {
		ts[i] = word(p)
	}
	return closed.NewKey(ts...)
}

func mustParams(v any) closed.Params {
	p, err := closed.NewParams(v)
	if err != nil {
		panic(err)
	}
	return p
}
