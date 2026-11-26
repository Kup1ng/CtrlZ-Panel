// Package vectors holds the golden vectors and the single runner (contract 15).
//
// The panel runs the reference harness in this package. The node runs the same
// files through its own glue harness, so a node that drifts from the shared
// evaluator fails here first (R45). Vector files are embedded, so the runner
// does no file I/O.
package vectors

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/policy"
)

//go:embed *.json fixtures/*.json
var files embed.FS

// Format is the only vector file format version.
const Format = 1

// decodeStrict rejects unknown keys, so a typo in a vector file fails the run
// instead of silently turning an assertion off.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after the JSON value")
	}
	return nil
}

// GroupFile is the envelope every group file shares.
type GroupFile struct {
	Format  int             `json:"format"`
	Group   string          `json:"group"`
	Fixture string          `json:"fixture"`
	Cases   json.RawMessage `json:"cases"`
}

// Groups lists the group file names (without .json), sorted.
func Groups() []string {
	ents, _ := fs.ReadDir(files, ".")
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ReadGroup returns the decoded envelope of one group.
func ReadGroup(name string) (*GroupFile, error) {
	data, err := files.ReadFile(name + ".json")
	if err != nil {
		return nil, err
	}
	var g GroupFile
	if err := decodeStrict(data, &g); err != nil {
		return nil, fmt.Errorf("%s.json: %w", name, err)
	}
	if g.Format != Format {
		return nil, fmt.Errorf("%s.json: format %d, want %d", name, g.Format, Format)
	}
	if g.Group != name {
		return nil, fmt.Errorf("%s.json: group field is %q", name, g.Group)
	}
	return &g, nil
}

// LoadFixture compiles fixtures/<name>.json.
func LoadFixture(name string) (*Fixture, error) {
	data, err := files.ReadFile("fixtures/" + name + ".json")
	if err != nil {
		return nil, err
	}
	var f FixtureFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, fmt.Errorf("fixtures/%s.json: %w", name, err)
	}
	if f.Format != Format {
		return nil, fmt.Errorf("fixtures/%s.json: format %d", name, f.Format)
	}
	return Compile(name, &f)
}

// Request is one query handed to a harness.
type Request struct {
	Input      policy.Input
	Endpoint   string
	ClientHash [16]byte
	Isolated   bool
	Resolver   policy.Resolver
	// NoPolicy asks for policy.PostDefault: the answer of a path with no profile.
	NoPolicy bool
}

// Outcome is what a harness returns for a Request.
type Outcome struct {
	PreDone  bool
	Deferred bool
	Walk     bool
	Final    policy.Final
	// Wildcard is sysnames.Entry.Wildcard of the row that answered.
	Wildcard bool
}

// Evaluator runs requests against one compiled fixture.
type Evaluator interface {
	Evaluate(ctx context.Context, r *Request) (*Outcome, error)
}

// Harness is what an implementation provides. Prepare gets the compiled
// fixture, including the raw blob and table bytes, so a node can load them
// through the same code paths it uses in production.
type Harness interface {
	Prepare(fx *Fixture) (Evaluator, error)
}

// Run executes every vector group against h. Evaluator groups go through the
// harness; grammar, binary and other groups run shared code directly, because
// the node imports that code unchanged.
func Run(t *testing.T, h Harness) {
	t.Helper()
	for _, name := range Groups() {
		g, err := ReadGroup(name)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		t.Run(name, func(t *testing.T) { runGroup(t, g, h) })
	}
}

// RunGroup executes one group, for a harness that wants to run them separately.
func RunGroup(t *testing.T, name string, h Harness) {
	t.Helper()
	g, err := ReadGroup(name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	runGroup(t, g, h)
}

func runGroup(t *testing.T, g *GroupFile, h Harness) {
	switch {
	case g.Fixture != "":
		runEvaluatorGroup(t, g, h)
	case g.Group == "blob" || g.Group == "gtable":
		runBinaryGroup(t, g)
	case g.Group == "zone-failover":
		runZoneFailoverGroup(t, g)
	case g.Group == "pair-table-validate":
		runPairTableValidateGroup(t, g)
	case g.Group == "telemetry-validate":
		runTelemetryValidateGroup(t, g)
	case g.Group == "pair-table-apply":
		runPairTableApplyGroup(t, g, h)
	case g.Group == "zone-answer":
		runZoneAnswerGroup(t, g)
	case g.Group == "quarantine":
		runQuarantineGroup(t, g)
	default:
		runTextGroup(t, g)
	}
}
