package redact

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_chunking.yaml
var chunkFixtureData []byte

type chunkFixtures struct {
	Catalog              chunkCase         `yaml:"catalog"`
	RequiredNames        []chunkCaseName   `yaml:"required_names"`
	Cases                []chunkCase       `yaml:"cases"`
	PolicyRequiredNames  []policyCaseName  `yaml:"policy_required_names"`
	PolicyCases          []policyCase      `yaml:"policy_cases"`
	RefusalRequiredNames []refusalCaseName `yaml:"refusal_required_names"`
	RefusalCases         []refusalCase     `yaml:"refusal_cases"`
	RefusalInput         string            `yaml:"refusal_input"`
	RefusalChunk         int               `yaml:"refusal_chunk"`
	RefusalCeiling       int               `yaml:"refusal_ceiling"`
}
type chunkCase struct {
	Name      chunkCaseName `yaml:"name"`
	Input     string        `yaml:"input"`
	SizeBytes int           `yaml:"size_bytes"`
	Fill      string        `yaml:"fill"`
	Plants    []struct {
		Offset int    `yaml:"offset"`
		Value  string `yaml:"value"`
	} `yaml:"plants"`
	ChunkBytes      int    `yaml:"chunk_bytes"`
	Pattern         string `yaml:"pattern"`
	Filter          bool   `yaml:"filter"`
	Refusal         bool   `yaml:"refusal"`
	ExpectedOffsets []int  `yaml:"expected_offsets"`
}
type policyCase struct {
	Name       policyCaseName `yaml:"name"`
	Chunk      int            `yaml:"chunk"`
	Ceiling    int            `yaml:"ceiling"`
	Invalid    bool           `yaml:"invalid"`
	Production bool           `yaml:"production"`
	InputBytes int            `yaml:"input_bytes"`
	Refused    bool           `yaml:"refused"`
}
type refusalCase struct {
	Name      refusalCaseName  `yaml:"name"`
	Operation refusalOperation `yaml:"operation"`
	Error     bool             `yaml:"error"`
	Output    string           `yaml:"output"`
}

func loadChunkFixtures(t *testing.T) chunkFixtures {
	t.Helper()
	var f chunkFixtures
	if err := yaml.Unmarshal(chunkFixtureData, &f); err != nil {
		t.Fatal(err)
	}
	chunkNames := make([]chunkCaseName, len(f.Cases))
	for i, row := range f.Cases {
		chunkNames[i] = row.Name
	}
	if err := validateTypedChunkManifest("required_names", requiredChunkCaseNames, f.RequiredNames, chunkNames); err != nil {
		t.Fatal(err)
	}
	policyNames := make([]policyCaseName, len(f.PolicyCases))
	for i, row := range f.PolicyCases {
		policyNames[i] = row.Name
	}
	if err := validateTypedChunkManifest("policy_required_names", AllPolicyCaseNames, f.PolicyRequiredNames, policyNames); err != nil {
		t.Fatal(err)
	}
	refusalNames := make([]refusalCaseName, len(f.RefusalCases))
	for i, row := range f.RefusalCases {
		refusalNames[i] = row.Name
	}
	if err := validateTypedChunkManifest("refusal_required_names", AllRefusalCaseNames, f.RefusalRequiredNames, refusalNames); err != nil {
		t.Fatal(err)
	}
	return f
}

// The spy delegates to the actual build-selected engine. It observes raw calls,
// including prefix/context patterns, so a bypass of the window bound fails.
type inputSpyEngine struct {
	engine
	calls, maximum int
}
type inputSpyPattern struct {
	compiled
	owner *inputSpyEngine
}

func (e *inputSpyEngine) Compile(expression string) (compiled, error) {
	p, err := e.engine.Compile(expression)
	if err != nil {
		return nil, err
	}
	return &inputSpyPattern{compiled: p, owner: e}, nil
}
func (p *inputSpyPattern) FindAllStringIndex(s string, n int) [][]int {
	p.owner.calls++
	p.owner.maximum = max(p.owner.maximum, len(s))
	return p.compiled.FindAllStringIndex(s, n)
}
func (p *inputSpyPattern) ReplaceAllString(s, repl string) string {
	p.owner.calls++
	p.owner.maximum = max(p.owner.maximum, len(s))
	return p.compiled.ReplaceAllString(s, repl)
}

// These tests isolate a configured rule through the mounted production
// constructor/Detect/RedactText path. Existing catalog fixtures protect the full
// rule table; copying that table into a 200 MiB test adds cost, not coverage.
func isolateChunkRules(t *testing.T) {
	t.Helper()
	original, residue := Rules, ResidueRules
	Rules, ResidueRules = nil, nil
	t.Cleanup(func() { Rules, ResidueRules = original, residue })
}

func TestEngineChunkFixtures(t *testing.T) {
	f := loadChunkFixtures(t)
	isolateChunkRules(t)
	for _, row := range f.Cases {
		t.Run(string(row.Name), func(t *testing.T) {
			input := row.Input
			if row.SizeBytes > 0 {
				if row.Fill == "" {
					t.Fatal("synthetic input requires fill")
				}
				var b strings.Builder
				b.Grow(row.SizeBytes)
				for b.Len() < row.SizeBytes {
					b.WriteString(row.Fill[:min(len(row.Fill), row.SizeBytes-b.Len())])
				}
				data := []byte(b.String())
				for _, plant := range row.Plants {
					copy(data[plant.Offset:], plant.Value)
				}
				input = string(data)
			}
			e := &inputSpyEngine{engine: selectEngine()}
			patterns := []UserPattern{{ID: "planted_value", Category: CategorySecrets, Pattern: row.Pattern, Replacement: "<VALUE>"}}
			policy := MaxInputBytesPolicy{ChunkBytes: row.ChunkBytes, CeilingBytes: DefaultMaxInputBytesPolicy.CeilingBytes}
			raw, err := newRedactorWithEngine(e, Standard, patterns, XDGPaths{}, WithMaxInputBytes(policy))
			if err != nil {
				t.Fatal(err)
			}
			r := raw.(*DefaultRedactor)
			if r.MaxInputBytes() != policy {
				t.Fatalf("accessor=%+v want %+v", r.MaxInputBytes(), policy)
			}
			filterCalls := 0
			if row.Filter {
				r.userRules[0].FilterFn = func(matched, whole string, offset int) bool {
					filterCalls++
					if whole != input || offset < 0 || whole[offset:offset+len(matched)] != matched || !slices.Contains(row.ExpectedOffsets, offset) {
						t.Errorf("filter did not receive whole input and absolute offset: %d", offset)
					}
					return true
				}
			}
			started := time.Now()
			matches, err := r.DetectChecked(input)
			detectElapsed := time.Since(started)
			if row.Refusal {
				if !errors.Is(err, ErrInputCannotChunkSafely) || matches != nil {
					t.Fatalf("got %v, %v; want explicit ambiguous-split refusal", matches, err)
				}
				if output, textErr := r.RedactTextChecked(input); output != "" || !errors.Is(textErr, ErrInputCannotChunkSafely) {
					t.Fatalf("checked output=%q err=%v", output, textErr)
				}
				if output := r.RedactText(input); output != "<REDACTED>" {
					t.Fatal("legacy text did not mask refused input")
				}
				// A configured rule cannot turn the synthetic refusal match
				// into an identity replacement and expose the original input.
				r.userRules[0].ID = inputRefusalRule
				r.userRules[0].Replacement = "${0}"
				if output := r.Redact(input, r.Detect(input)); output != "<REDACTED>" {
					t.Fatal("configured replacement overrode refusal masking")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			offsets := make([]int, len(matches))
			for i, m := range matches {
				offsets[i] = m.Offset
				if m.MatchedText != input[m.Offset:m.Offset+m.Length] {
					t.Fatal("matched text lost original offsets")
				}
			}
			if !slices.Equal(offsets, row.ExpectedOffsets) {
				t.Fatalf("offsets=%v want %v", offsets, row.ExpectedOffsets)
			}
			if row.Filter && filterCalls != len(matches) {
				t.Fatalf("filter calls=%d matches=%d; overlapping windows duplicated a callback", filterCalls, len(matches))
			}
			redactStarted := time.Now()
			chunked, err := r.RedactTextChecked(input)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d bytes, %d-byte chunks: detect %s, redact-text %s; maximum engine buffer %d", len(input), row.ChunkBytes, detectElapsed, time.Since(redactStarted), e.maximum)
			if e.maximum > row.ChunkBytes+engineOverlapBytes+4 {
				t.Fatalf("engine saw %d bytes, above window bound", e.maximum)
			}
			if len(input) == row.ChunkBytes && e.calls != 2 {
				t.Fatalf("exact boundary made %d calls; want one per scan", e.calls)
			}
			if len(input) > row.ChunkBytes && e.calls <= 2 {
				t.Fatal("large input bypassed chunking")
			}
			baseline, err := NewRedactor(Standard, patterns, XDGPaths{}, WithMaxInputBytes(MaxInputBytesPolicy{ChunkBytes: len(input) + 1, CeilingBytes: policy.CeilingBytes}))
			if err != nil {
				t.Fatal(err)
			}
			plain := baseline.(*DefaultRedactor)
			plain.userRules[0].FilterFn = r.userRules[0].FilterFn
			unchunked, err := plain.RedactTextChecked(input)
			if err != nil {
				t.Fatal(err)
			}
			if chunked != unchunked {
				t.Fatalf("chunked output differs from unchunked: pattern=%q offsets=%v sizes=%d/%d", row.Pattern, offsets, len(chunked), len(unchunked))
			}
			if !reflect.DeepEqual(r.Report(), plain.Report()) {
				t.Fatalf("reports differ: chunked=%+v unchunked=%+v", r.Report(), plain.Report())
			}
			if count := r.Report().Counts["planted_value"]; count != len(row.ExpectedOffsets) {
				t.Fatalf("report count=%d want %d", count, len(row.ExpectedOffsets))
			}
		})
	}
}

func TestEngineInputPolicyFixtures(t *testing.T) {
	for _, row := range loadChunkFixtures(t).PolicyCases {
		t.Run(string(row.Name), func(t *testing.T) {
			policy := MaxInputBytesPolicy{ChunkBytes: row.Chunk, CeilingBytes: row.Ceiling}
			if err := policy.Validate(); (err != nil) != row.Invalid {
				t.Fatalf("Validate=%v invalid=%v", err, row.Invalid)
			}
			r, err := NewRedactor(Standard, nil, XDGPaths{}, WithMaxInputBytes(policy))
			if (err != nil) != row.Invalid || row.Invalid && r != nil {
				t.Fatalf("constructor=%v,%v invalid=%v", r, err, row.Invalid)
			}
			if row.Production && DefaultMaxInputBytesPolicy != policy {
				t.Fatalf("production policy=%+v want %+v", DefaultMaxInputBytesPolicy, policy)
			}
			if row.InputBytes > 0 {
				// Exercise the exact production 2 GiB integer without allocating
				// that input or entering the engine; small-ceiling tests below
				// prove that the real public paths apply this same guard.
				err := policy.check(row.InputBytes)
				if errors.Is(err, ErrInputAboveEngineCeiling) != row.Refused {
					t.Fatalf("check(%d)=%v refused=%v", row.InputBytes, err, row.Refused)
				}
			}
		})
	}
}

func TestEngineInputRefusalPublicPaths(t *testing.T) {
	f := loadChunkFixtures(t)
	for _, row := range f.RefusalCases {
		t.Run(string(row.Name), func(t *testing.T) {
			e := &inputSpyEngine{engine: selectEngine()}
			policy := MaxInputBytesPolicy{ChunkBytes: f.RefusalChunk, CeilingBytes: f.RefusalCeiling}
			raw, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{}, WithMaxInputBytes(policy))
			if err != nil {
				t.Fatal(err)
			}
			r := raw.(*DefaultRedactor)
			input := f.RefusalInput
			var output string
			switch row.Operation {
			case refusalOperationCheckedDetect:
				var m []Match
				m, err = r.DetectChecked(input)
				if m != nil {
					t.Fatal("refusal returned matches")
				}
			case refusalOperationCheckedText:
				output, err = r.RedactTextChecked(input)
			case refusalOperationCheckedJSON:
				var v any
				v, err = r.RedactJSONChecked(map[string]any{"nested": []any{input}})
				if v != nil {
					t.Fatal("refusal returned partial JSON")
				}
			case refusalOperationJSONL:
				data, _ := json.Marshal(map[string]any{"value": input})
				data = append(data, '\n')
				var out []byte
				out, err = RedactJSONLBytes(r, data)
				if !bytes.Equal(out, data) {
					t.Fatal("JSONL refusal changed original bytes")
				}
			case refusalOperationCheckedDocument:
				data, _ := json.Marshal(input)
				var out []byte
				out, err = RedactJSONDocBytesChecked(r, data)
				if out != nil {
					t.Fatal("document refusal returned output")
				}
			case refusalOperationDetect:
				output = r.Redact(input, r.Detect(input))
			case refusalOperationText:
				output = r.RedactText(input)
			case refusalOperationJSON:
				output = r.RedactJSON(input).(string)
			case refusalOperationDocument:
				data, _ := json.Marshal(input)
				output = string(RedactJSONDocBytes(r, data))
			case refusalOperationRedact:
				output = r.Redact(input, []Match{{Length: len(input)}})
			case refusalOperationTitleGenerate, refusalOperationTitleSanitize:
				p, pErr := newTitlePipelineWithEngine(e)
				if pErr != nil {
					t.Fatal(pErr)
				}
				p.scans.policy = policy
				var result TitleResult
				if row.Operation == refusalOperationTitleGenerate {
					result, err = p.Generate(input, TitleContext{})
				} else {
					result, err = p.Sanitize(input, TitleContext{})
				}
				output = result.Text
			default:
				t.Fatalf("unknown operation %q", row.Operation)
			}
			if errors.Is(err, ErrInputAboveEngineCeiling) != row.Error || output != row.Output {
				t.Fatalf("output=%q err=%v; want %q error=%v", output, err, row.Output, row.Error)
			}
			if e.calls != 0 {
				t.Fatalf("refused input made %d engine calls", e.calls)
			}
			if row.Error {
				for _, field := range []string{"what:", "why:", "where:", "when:", "means:", "fix:"} {
					if !strings.Contains(err.Error(), field) {
						t.Fatalf("refusal missing %s: %v", field, err)
					}
				}
			}
		})
	}
}

func TestEngineCatalogChunkedParity(t *testing.T) {
	row := loadChunkFixtures(t).Catalog
	if row.Name != chunkFullCatalogParity {
		t.Fatal("restore the full catalog parity fixture")
	}
	data := bytes.Repeat([]byte(row.Fill), row.SizeBytes/len(row.Fill)+1)[:row.SizeBytes]
	for _, plant := range row.Plants {
		copy(data[plant.Offset:], plant.Value)
	}
	input := string(data)
	chunked, err := NewRedactor(Standard, nil, XDGPaths{}, WithMaxInputBytes(MaxInputBytesPolicy{ChunkBytes: row.ChunkBytes, CeilingBytes: DefaultMaxInputBytesPolicy.CeilingBytes}))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := NewRedactor(Standard, nil, XDGPaths{}, WithMaxInputBytes(MaxInputBytesPolicy{ChunkBytes: len(input) + 1, CeilingBytes: DefaultMaxInputBytesPolicy.CeilingBytes}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := chunked.(*DefaultRedactor).RedactTextChecked(input)
	if err != nil {
		t.Fatal(err)
	}
	want, err := plain.(*DefaultRedactor).RedactTextChecked(input)
	if err != nil {
		t.Fatal(err)
	}
	chunkedReport := chunked.Report()
	plainReport := plain.Report()
	// Legacy category insertion follows a counts map's unspecified iteration
	// order. Compare category membership, just as the engine parity corpus does.
	slices.Sort(chunkedReport.Categories)
	slices.Sort(plainReport.Categories)
	if got != want || !reflect.DeepEqual(chunkedReport, plainReport) {
		t.Fatalf("full catalog output or report differs across chunk policy: chunked=%+v unchunked=%+v", chunkedReport, plainReport)
	}
	if got == input || len(chunked.Report().Counts) == 0 {
		t.Fatal("catalog fixture did not exercise production replacements")
	}
}
