package redact

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/peasant-labs/schema"
	"gopkg.in/yaml.v3"
)

//go:embed testdata/title.yaml
var titleFixtureData []byte

type titleFixtureOperation string

const (
	titleGenerate titleFixtureOperation = "generate"
	titleSanitize titleFixtureOperation = "sanitize"
)

type titleFixture struct {
	Name             string                `yaml:"name"`
	Operation        titleFixtureOperation `yaml:"operation"`
	Harness          schema.Harness        `yaml:"harness"`
	ProjectPath      string                `yaml:"projectPath"`
	Input            string                `yaml:"input"`
	Output           string                `yaml:"output"`
	Categories       []CategoryString      `yaml:"categories"`
	ErrorContains    string                `yaml:"errorContains"`
	NoEchoContains   []string              `yaml:"noEchoContains"`
	Idempotent       bool                  `yaml:"idempotent"`
	RuntimeIsolation bool                  `yaml:"runtimeIsolation"`
	Concurrent       bool                  `yaml:"concurrent"`
	ConcurrentGroup  string                `yaml:"concurrentGroup"`
	EngineParity     bool                  `yaml:"engineParity"`
	NilReceiver      bool                  `yaml:"nilReceiver"`
}
type titleFixtures struct {
	Cases            []titleFixture         `yaml:"cases"`
	DecoderMutations []titleDecoderMutation `yaml:"decoderMutations"`
}

type titleDecoderMutation struct {
	Name  string `yaml:"name"`
	Input string `yaml:"input"`
}

func loadTitleFixtures() (titleFixtures, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(titleFixtureData))
	decoder.KnownFields(true)
	var fixtures titleFixtures
	if err := decoder.Decode(&fixtures); err != nil {
		return titleFixtures{}, fmt.Errorf("redact: could not strictly decode testdata/title.yaml: %w; title behavior cannot be verified; fix the YAML fields and syntax", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return titleFixtures{}, fmt.Errorf("redact: testdata/title.yaml has trailing YAML content; exact fixture ownership is ambiguous; keep exactly one YAML document")
	}
	if len(fixtures.Cases) != 40 {
		return titleFixtures{}, fmt.Errorf("redact: testdata/title.yaml defines %d rows, want exactly 40 title behavior rows; restore the reviewed behavior matrix", len(fixtures.Cases))
	}
	knownHarnesses := make(map[schema.Harness]struct{})
	for _, harness := range schema.Harnesses() {
		knownHarnesses[harness] = struct{}{}
	}
	seen := make(map[string]struct{}, len(fixtures.Cases))
	arms := make(map[titleFixtureOperation]int)
	canonical := []CategoryString{CategoryStringCredential, CategoryStringPII, CategoryStringPath, CategoryStringInternal}
	for i, fixture := range fixtures.Cases {
		if fixture.Name == "" || (fixture.Operation != titleGenerate && fixture.Operation != titleSanitize) {
			return titleFixtures{}, fmt.Errorf("redact: title fixture row %d requires a unique name and closed generate/sanitize operation; fill in the missing contract fields", i)
		}
		if _, ok := knownHarnesses[fixture.Harness]; !ok {
			return titleFixtures{}, fmt.Errorf("redact: title fixture %q uses unknown harness %q; use a schema Harnesses value", fixture.Name, fixture.Harness)
		}
		if _, duplicate := seen[fixture.Name]; duplicate {
			return titleFixtures{}, fmt.Errorf("redact: title fixture name %q is duplicated; give every behavior row a unique name", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
		arms[fixture.Operation]++
		for _, category := range fixture.Categories {
			if !slices.Contains(canonical, category) {
				return titleFixtures{}, fmt.Errorf("redact: title fixture %q uses unknown category %q; use a canonical CategoryString", fixture.Name, category)
			}
		}
		if fixture.ErrorContains == "" && fixture.Input != "" && fixture.Output == "" {
			return titleFixtures{}, fmt.Errorf("redact: title fixture %q has no observable output or error; make the row non-vacuous", fixture.Name)
		}
		wrapperError := fixture.Operation == titleGenerate && fixture.ErrorContains != "" &&
			(strings.Contains(fixture.Input, "<system-reminder>") || strings.Contains(fixture.Input, "<user_query>"))
		if wrapperError && len(fixture.NoEchoContains) == 0 {
			return titleFixtures{}, fmt.Errorf("redact: wrapper error fixture %q has no noEchoContains fragments; payload no-echo coverage would be vacuous; declare every sensitive payload fragment", fixture.Name)
		}
		seenForbidden := make(map[string]struct{}, len(fixture.NoEchoContains))
		for _, forbidden := range fixture.NoEchoContains {
			if forbidden == "" || forbidden == fixture.Input || !strings.Contains(fixture.Input, forbidden) || strings.ContainsAny(forbidden, "<>") {
				return titleFixtures{}, fmt.Errorf("redact: title fixture %q has vacuous noEchoContains fragment %q; each fragment must be non-empty, occur inside the input, differ from the full input, and identify payload rather than wrapper markup", fixture.Name, forbidden)
			}
			if _, duplicate := seenForbidden[forbidden]; duplicate {
				return titleFixtures{}, fmt.Errorf("redact: title fixture %q duplicates noEchoContains fragment %q; duplicate assertions do not strengthen no-echo coverage", fixture.Name, forbidden)
			}
			seenForbidden[forbidden] = struct{}{}
		}
	}
	if arms[titleGenerate] != 14 || arms[titleSanitize] != 26 {
		return titleFixtures{}, fmt.Errorf("redact: title fixture operation arms are generate=%d sanitize=%d, want 14 and 26; restore exact production-path coverage", arms[titleGenerate], arms[titleSanitize])
	}
	if len(fixtures.DecoderMutations) != 2 || fixtures.DecoderMutations[0].Name == "" || fixtures.DecoderMutations[1].Name == "" || fixtures.DecoderMutations[0].Input == "" || fixtures.DecoderMutations[1].Input == "" {
		return titleFixtures{}, fmt.Errorf("redact: testdata/title.yaml must define exactly two named non-empty strict-decoder mutations; restore unknown-field and trailing-document guards")
	}
	return fixtures, nil
}

func TestTitlePipelineFixtures(t *testing.T) {
	fixtures, err := loadTitleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := NewTitlePipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures.Cases {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			active := pipeline
			if fixture.NilReceiver {
				active = nil
			}
			result, callErr := runTitleFixture(active, fixture, fixture.Input)
			if fixture.ErrorContains != "" {
				if callErr == nil || !strings.Contains(callErr.Error(), fixture.ErrorContains) {
					t.Fatalf("error = %v, want safe diagnostic containing %q", callErr, fixture.ErrorContains)
				}
				if fixture.Input != "safe" && strings.Contains(callErr.Error(), fixture.Input) {
					t.Fatal("error disclosed fixture input")
				}
				for _, forbidden := range fixture.NoEchoContains {
					if strings.Contains(callErr.Error(), forbidden) {
						t.Fatalf("error disclosed forbidden payload fragment %q", forbidden)
					}
				}
				return
			}
			if callErr != nil {
				t.Fatal(callErr)
			}
			assertTitleFixtureResult(t, fixture, result)
			if fixture.Idempotent {
				second, secondErr := runTitleFixture(pipeline, fixture, result.Text)
				if secondErr != nil || second.Text != result.Text || len(second.Categories) != 0 {
					t.Fatalf("second pass = %#v, %v; want identical text and no fresh sensitive categories", second, secondErr)
				}
			}
			if fixture.RuntimeIsolation {
				configured, e := NewRedactor(Standard, []UserPattern{{ID: "runtime_only", Category: CategorySecrets, Pattern: "title-policy-marker", Replacement: "<RUNTIME>"}}, XDGPaths{ConfigHome: "/private/alice/config"})
				if e != nil {
					t.Fatal(e)
				}
				if configured.RedactText(fixture.Input) == fixture.Input {
					t.Fatal("runtime isolation guard is vacuous")
				}
				again, e := pipeline.Sanitize(fixture.Input, TitleContext{Harness: fixture.Harness})
				if e != nil || again.Text != fixture.Output || again.HasSensitiveContent() {
					t.Fatalf("runtime configuration affected title policy: %#v, %v", again, e)
				}
			}
			if fixture.Concurrent {
				assertConcurrentTitleCalls(t, pipeline, fixture)
			}
			if fixture.EngineParity {
				redactor, redactorErr := NewRedactor(Standard, nil, XDGPaths{})
				if redactorErr != nil {
					t.Fatal(redactorErr)
				}
				canonical := redactor.Redact(fixture.Input, redactor.Detect(fixture.Input))
				if result.Text != canonical {
					t.Fatalf("title output %q differs from canonical Standard Detect/Redact output %q", result.Text, canonical)
				}
			}
		})
	}
	assertMixedConcurrentTitleCalls(t, pipeline, fixtures.Cases)
}

func assertMixedConcurrentTitleCalls(t *testing.T, pipeline *TitlePipeline, fixtures []titleFixture) {
	t.Helper()
	var group []titleFixture
	for _, fixture := range fixtures {
		if fixture.ConcurrentGroup == "mixed_categories" {
			group = append(group, fixture)
		}
	}
	if len(group) != 3 {
		t.Fatalf("mixed concurrent fixture group has %d rows, want exactly 3 distinct category calls", len(group))
	}
	const repetitions = 32
	results := make(chan struct {
		fixture titleFixture
		result  TitleResult
		err     error
	}, len(group)*repetitions)
	var wait sync.WaitGroup
	for range repetitions {
		for _, fixture := range group {
			fixture := fixture
			wait.Add(1)
			go func() {
				defer wait.Done()
				result, err := runTitleFixture(pipeline, fixture, fixture.Input)
				results <- struct {
					fixture titleFixture
					result  TitleResult
					err     error
				}{fixture: fixture, result: result, err: err}
			}()
		}
	}
	wait.Wait()
	close(results)
	for call := range results {
		if call.err != nil {
			t.Fatal(call.err)
		}
		assertTitleFixtureResult(t, call.fixture, call.result)
	}
}

func runTitleFixture(p *TitlePipeline, f titleFixture, input string) (TitleResult, error) {
	c := TitleContext{Harness: f.Harness, ProjectPath: f.ProjectPath}
	if f.Operation == titleGenerate {
		return p.Generate(input, c)
	}
	return p.Sanitize(input, c)
}
func assertTitleFixtureResult(t *testing.T, f titleFixture, r TitleResult) {
	t.Helper()
	if r.Text != f.Output || !slices.Equal(r.Categories, f.Categories) {
		t.Fatalf("result = %#v, want text %q categories %v", r, f.Output, f.Categories)
	}
	if r.HasSensitiveContent() != (len(f.Categories) != 0) {
		t.Fatalf("HasSensitiveContent mismatch")
	}
	if !utf8.ValidString(r.Text) || len([]rune(r.Text)) > titleCodePointLimit {
		t.Fatalf("invalid or overlong title %q", r.Text)
	}
}
func assertConcurrentTitleCalls(t *testing.T, p *TitlePipeline, f titleFixture) {
	t.Helper()
	const calls = 64
	results := make(chan TitleResult, calls)
	errors := make(chan error, calls)
	var wait sync.WaitGroup
	for range calls {
		wait.Add(1)
		go func() { defer wait.Done(); r, e := runTitleFixture(p, f, f.Input); results <- r; errors <- e }()
	}
	wait.Wait()
	close(results)
	close(errors)
	for e := range errors {
		if e != nil {
			t.Fatal(e)
		}
	}
	for r := range results {
		assertTitleFixtureResult(t, f, r)
	}
}

func TestTitleFixtureStrictDecoderRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	fixtures, err := loadTitleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range fixtures.DecoderMutations {
		decoder := yaml.NewDecoder(strings.NewReader(mutation.Input))
		decoder.KnownFields(true)
		var fixtures titleFixtures
		firstErr := decoder.Decode(&fixtures)
		var trailing any
		secondErr := decoder.Decode(&trailing)
		if firstErr == nil && secondErr == io.EOF {
			t.Fatalf("strict-decoder mutation %q unexpectedly succeeded", mutation.Name)
		}
	}
}
