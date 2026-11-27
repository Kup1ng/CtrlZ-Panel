package failovergen

import (
	"bytes"
	"encoding/json"
)

// Generate returns the bytes of vectors/zone-failover.json: the generated
// cases, then the fixed sequences.
func Generate() ([]byte, error) {
	cases := generated()
	cases = append(cases, sequences()...)
	file := struct {
		Format  int    `json:"format"`
		Group   string `json:"group"`
		Fixture string `json:"fixture"`
		Cases   []Case `json:"cases"`
	}{1, "zone-failover", "", cases}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(file); err != nil {
		return nil, err
	}
	// One case per line would be unreadable for a long case and a diff of
	// the whole file for a short one; compact JSON with a newline between
	// cases keeps both diffs and review workable.
	return splitCases(b.Bytes()), nil
}

// splitCases puts each case on its own line.
func splitCases(b []byte) []byte {
	b = bytes.Replace(b, []byte(`"cases":[`), []byte("\"cases\":[\n"), 1)
	b = bytes.ReplaceAll(b, []byte(`},{"id":`), []byte("},\n{\"id\":"))
	return b
}
