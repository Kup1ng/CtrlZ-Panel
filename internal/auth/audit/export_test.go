package audit

// MarshalParams exposes the params encoder to the external tests.
func MarshalParams(ev any) ([]byte, error) { return marshalParams(ev) }
