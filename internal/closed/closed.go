// Package closed is the one definition of "a value that cannot carry a secret".
//
// An audit row, an alert, a provider status column and a log line may hold only
// three kinds of value: a number or a bool, an opaque id, and a member of a closed
// set. The old guard was a deny list (a scan for runs of digits) applied to the
// field kinds somebody remembered, and each review round found one it missed: a
// slice, a script, a new driver. This package turns the question around. A string
// can be stored only if its type names its own finite set and says whether the value
// belongs to it; every other string is refused by the compiler (a function that takes
// Closed or Text does not accept a plain string) or by Check (a struct that holds
// one). A value outside its set is refused, never cleaned up: a cleaned value would
// look real.
//
// Review round 5, rule closed-values-in-logs (spec 8.6, 13.3).
package closed

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Closed is a string type with a registered, finite value list. Valid says whether
// a value is on the list. The list is code, not data: a type whose Valid reads a
// database or a request would not be closed.
type Closed interface {
	~string
	Valid() bool
}

// Text is a closed value as a column or a key part sees it: the stored text, and
// whether it belongs to its set. A function that takes Text (store.GatewayFailed)
// cannot be handed a plain string, because string has no Valid method, and refuses
// a value that is off its list.
type Text interface {
	String() string
	Valid() bool
}

// Opaque marks a struct type that cannot hold free text by construction, such as a
// masked phone number whose only field is unexported and set by its constructor.
type Opaque interface{ ClosedOpaque() }

// CheckType judges the shape of a struct type: every exported field is a bool, an
// integer, an id, an Opaque struct, a string type with a Valid method, or a slice
// of those. It is what the reflection tests of the audit events and the alert
// params call for each registered type, so a field added later (a Note string, a
// map, an interface) fails there. unexported fields are refused too: they cannot be
// marshalled, so their presence means the struct is not the whole record.
func CheckType(t reflect.Type) error { return checkStruct(t, false) }

// CheckFields judges the same kinds as CheckType and also the UNEXPORTED fields: every field of the struct,
// exported or not, is a closed kind. It is for a type that is never marshalled and keeps a field private on
// purpose (an error value whose class no encoder may print, sms-r17-23), where CheckType would refuse the
// field and a hand-written test of one level would not prove what the field holds.
func CheckFields(t reflect.Type) error { return checkStruct(t, true) }

func checkStruct(t reflect.Type, allowUnexported bool) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return errors.New("closed: " + t.String() + " is not a struct")
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() && !allowUnexported {
			return errors.New("closed: " + t.Name() + "." + f.Name + " is unexported")
		}
		if err := checkKind(f.Type); err != nil {
			return errors.New("closed: " + t.Name() + "." + f.Name + ": " + err.Error())
		}
	}
	return nil
}

func checkKind(t reflect.Type) error {
	// No package-level variables (the workspace rule): the types are cheap to ask for.
	uuidType := reflect.TypeOf(uuid.UUID{})
	opaqueType := reflect.TypeOf((*Opaque)(nil)).Elem()
	boolType := reflect.TypeOf(true)
	switch {
	case t == uuidType:
		return nil
	case t.Implements(opaqueType):
		return checkOpaque(t)
	case t.Kind() == reflect.Bool, isInt(t.Kind()):
		return nil
	case t.Kind() == reflect.String:
		if t.PkgPath() == "" {
			return errors.New("a plain string; use a named type with a closed value list")
		}
		m, ok := t.MethodByName("Valid")
		if !ok || m.Type.NumIn() != 1 || m.Type.NumOut() != 1 || m.Type.Out(0) != boolType {
			return errors.New(t.String() + " has no Valid() bool method")
		}
		return nil
	case t.Kind() == reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return errors.New("a byte slice")
		}
		return checkKind(t.Elem())
	}
	return errors.New(t.String() + " is not a closed kind")
}

// checkOpaque holds the escape hatch to its own definition: an Opaque type is a struct whose
// fields are all unexported, so nothing outside its package can put text in it and its
// constructor is the only writer. Before this, any type with a ClosedOpaque method was
// accepted unseen, so `type Note struct{ Text string }` with the method opened free text
// to the audit log and the alerts with every test green (primitives-r5-3). A named string
// or a struct with an exported field is not opaque, whatever it declares.
func checkOpaque(t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return errors.New(t.String() + " declares itself opaque and is not a struct")
	}
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).IsExported() {
			return errors.New(t.String() + " declares itself opaque and has the exported field " + t.Field(i).Name)
		}
	}
	return nil
}

func isInt(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

// Check judges a value: CheckType for its type, and for each string field (or
// element of a slice of them) that the value is on its type's list.
func Check(v any) error {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return errors.New("closed: nil")
		}
		rv = rv.Elem()
	}
	if err := CheckType(rv.Type()); err != nil {
		return err
	}
	for i := 0; i < rv.NumField(); i++ {
		if !member(rv.Field(i)) {
			return errors.New("closed: field " + rv.Type().Field(i).Name + " of " + rv.Type().Name() + " is outside its closed set")
		}
	}
	return nil
}

func member(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		ok := v.MethodByName("Valid").Call(nil)[0].Bool()
		return ok
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if !member(v.Index(i)) {
				return false
			}
		}
	}
	return true
}

// Params is a JSON object that passed Check. The only way to make a non-empty one
// is Marshal, so a function that takes Params (store.GlobalTx.AlertOnce) cannot be
// given bytes that were built by hand. The zero Params is "{}".
type Params struct{ b []byte }

// Marshal checks v and encodes it as a JSON object. HTML escaping is off so the
// stored text is the plain value.
func Marshal(v any) ([]byte, error) {
	if err := Check(v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// NewParams is Marshal as a Params.
func NewParams(v any) (Params, error) {
	b, err := Marshal(v)
	return Params{b}, err
}

// JSON is the encoded object.
func (p Params) JSON() []byte {
	if p.b == nil {
		return []byte("{}")
	}
	return append([]byte(nil), p.b...)
}

// Key is the dedupe key of an alert, joined from closed parts. It is stored inside
// the alert's params, so it is held to the same rule as the rest of them.
type Key struct{ s string }

// NewKey joins parts with ":". A part that is off its list makes the key invalid
// and it reads as the empty string, which the store refuses.
func NewKey(parts ...Text) Key {
	ss := make([]string, len(parts))
	for i, p := range parts {
		if !p.Valid() {
			return Key{}
		}
		ss[i] = p.String()
	}
	return Key{strings.Join(ss, ":")}
}

// String is the key text; empty for an invalid key.
func (k Key) String() string { return k.s }

// ID is a uuid as a Text, for a key part. An id is opaque: it names a row.
type ID uuid.UUID

// String is the canonical text.
func (i ID) String() string { return uuid.UUID(i).String() }

// Valid is always true: every uuid is a legal opaque id.
func (ID) Valid() bool { return true }

// UTCHour is an instant truncated to its hour, as "2006-01-02T15", for a key that
// changes every hour. It is digits and two separators; it cannot be anything else.
type UTCHour struct{ t time.Time }

// HourOf truncates t.
func HourOf(t time.Time) UTCHour { return UTCHour{t.UTC().Truncate(time.Hour)} }

// String is the hour.
func (h UTCHour) String() string { return h.t.Format("2006-01-02T15") }

// Valid is always true.
func (UTCHour) Valid() bool { return true }
