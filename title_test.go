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
	ExpectEmpty      bool                  `yaml:"expectEmpty"`
	Idempotent       bool                  `yaml:"idempotent"`
	RuntimeIsolation bool                  `yaml:"runtimeIsolation"`
	Concurrent       bool                  `yaml:"concurrent"`
	ConcurrentGroup  string                `yaml:"concurrentGroup"`
	EngineParity     bool                  `yaml:"engineParity"`
	NilReceiver      bool                  `yaml:"nilReceiver"`
}
type titleFixtures struct {
	Cases                  []titleFixture             `yaml:"cases"`
	SimpleTitleCases       []simpleTitleFixture       `yaml:"simpleTitleCases"`
	GenerateFromTurnsCases []generateFromTurnsFixture `yaml:"generateFromTurnsCases"`
	WrapperTables          []wrapperTableFixture      `yaml:"wrapperTables"`
	DecoderMutations       []titleDecoderMutation     `yaml:"decoderMutations"`
}

// generateFromTurnsFixture pins the turn-selection contract: which turn index
// supplies the title, and which turns are skipped as injected or unusable.
type generateFromTurnsFixture struct {
	Name                 string           `yaml:"name"`
	Harness              schema.Harness   `yaml:"harness"`
	ProjectPath          string           `yaml:"projectPath"`
	Turns                []string         `yaml:"turns"`
	WantIndex            int              `yaml:"wantIndex"`
	WantText             string           `yaml:"wantText"`
	WantCategories       []CategoryString `yaml:"wantCategories"`
	SkippedErrorContains []string         `yaml:"skippedErrorContains"`
	NoEchoContains       []string         `yaml:"noEchoContains"`
	NilReceiver          bool             `yaml:"nilReceiver"`
}

// wrapperTableFixture pins the closed per-harness wrapper table itself, so
// adding, removing, or re-actioning a wrapper is a reviewed fixture change.
type wrapperTableFixture struct {
	Harness           schema.Harness             `yaml:"harness"`
	Wrappers          []wrapperTableEntryFixture `yaml:"wrappers"`
	WholeTurnPrefixes []string                   `yaml:"wholeTurnPrefixes"`
}

type wrapperTableEntryFixture struct {
	Name   string `yaml:"name"`
	Action string `yaml:"action"`
}

type simpleTitleFixture struct {
	Name            string         `yaml:"name"`
	Harness         schema.Harness `yaml:"harness"`
	Input           string         `yaml:"input"`
	Output          string         `yaml:"output"`
	ExpectEmpty     bool           `yaml:"expectEmpty"`
	ErrorContains   string         `yaml:"errorContains"`
	LiteralContains []string       `yaml:"literalContains"`
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
	if len(fixtures.Cases) != 84 {
		return titleFixtures{}, fmt.Errorf("redact: testdata/title.yaml defines %d rows, want exactly 84 title behavior rows; restore the reviewed behavior matrix", len(fixtures.Cases))
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
		if fixture.ExpectEmpty && (fixture.Output != "" || fixture.ErrorContains != "") {
			return titleFixtures{}, fmt.Errorf("redact: title fixture %q declares expectEmpty together with an output or an expected error; declare exactly one observable outcome", fixture.Name)
		}
		if fixture.ErrorContains == "" && fixture.Input != "" && fixture.Output == "" && !fixture.ExpectEmpty {
			return titleFixtures{}, fmt.Errorf("redact: title fixture %q has no observable output or error; make the row non-vacuous, or set expectEmpty when the row proves injected markup cleans to nothing", fixture.Name)
		}
		wrapperError := fixture.Operation == titleGenerate && fixture.ErrorContains != "" &&
			inputContainsRecognizedWrapper(fixture.Input, fixture.Harness)
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
	if arms[titleGenerate] != 57 || arms[titleSanitize] != 27 {
		return titleFixtures{}, fmt.Errorf("redact: title fixture operation arms are generate=%d sanitize=%d, want 57 and 27; restore exact production-path coverage", arms[titleGenerate], arms[titleSanitize])
	}
	if err := validateGenerateFromTurnsFixtures(fixtures.GenerateFromTurnsCases); err != nil {
		return titleFixtures{}, err
	}
	if err := validateWrapperTableFixtures(fixtures.WrapperTables); err != nil {
		return titleFixtures{}, err
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

func TestTitlePipelineSimpleTitleFixtures(t *testing.T) {
	fixtures, err := loadTitleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures.SimpleTitleCases) != 11 {
		t.Fatalf("simpleTitleCases has %d rows, want exactly 11; restore the reviewed SimpleTitle behavior matrix", len(fixtures.SimpleTitleCases))
	}
	knownHarnesses := make(map[schema.Harness]struct{})
	for _, harness := range schema.Harnesses() {
		knownHarnesses[harness] = struct{}{}
	}
	seen := make(map[string]struct{}, len(fixtures.SimpleTitleCases))
	for i, fixture := range fixtures.SimpleTitleCases {
		if fixture.Name == "" {
			t.Fatalf("simple title fixture row %d needs a unique name", i)
		}
		if _, ok := knownHarnesses[fixture.Harness]; !ok {
			t.Fatalf("simple title fixture %q uses unknown harness %q", fixture.Name, fixture.Harness)
		}
		if _, dup := seen[fixture.Name]; dup {
			t.Fatalf("simple title fixture name %q is duplicated", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
		if fixture.ExpectEmpty && (fixture.Output != "" || fixture.ErrorContains != "") {
			t.Fatalf("simple title fixture %q declares expectEmpty together with an output or an expected error; declare exactly one observable outcome", fixture.Name)
		}
		if fixture.ErrorContains == "" && fixture.Output == "" && !fixture.ExpectEmpty {
			t.Fatalf("simple title fixture %q has no observable output or error; make the row non-vacuous, or set expectEmpty when the row proves injected markup cleans to nothing", fixture.Name)
		}
		for _, literal := range fixture.LiteralContains {
			if literal == "" || !strings.Contains(fixture.Input, literal) {
				t.Fatalf("simple title fixture %q has a vacuous literalContains fragment %q; each fragment must be non-empty and occur in the input", fixture.Name, literal)
			}
		}
	}

	pipeline, err := NewTitlePipeline()
	if err != nil {
		t.Fatal(err)
	}

	// A nil receiver fails closed with the shared actionable diagnostic.
	if _, nilErr := (*TitlePipeline)(nil).SimpleTitle("safe", schema.HarnessClaudeCode); nilErr == nil || !strings.Contains(nilErr.Error(), "title pipeline receiver is nil") {
		t.Fatalf("nil receiver SimpleTitle error = %v, want nil-receiver diagnostic", nilErr)
	}
	// An empty first turn yields an empty title without error.
	if empty, emptyErr := pipeline.SimpleTitle("", schema.HarnessClaudeCode); empty != "" || emptyErr != nil {
		t.Fatalf("empty SimpleTitle = %q, %v; want empty string and no error", empty, emptyErr)
	}

	for _, fixture := range fixtures.SimpleTitleCases {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			got, callErr := pipeline.SimpleTitle(fixture.Input, fixture.Harness)
			if fixture.ErrorContains != "" {
				if callErr == nil || !strings.Contains(callErr.Error(), fixture.ErrorContains) {
					t.Fatalf("error = %v, want diagnostic containing %q", callErr, fixture.ErrorContains)
				}
				if got != "" {
					t.Fatalf("errored SimpleTitle returned %q, want empty string", got)
				}
				return
			}
			if callErr != nil {
				t.Fatal(callErr)
			}
			if got != fixture.Output {
				t.Fatalf("SimpleTitle = %q, want %q", got, fixture.Output)
			}
			if !utf8.ValidString(got) || len([]rune(got)) > titleCodePointLimit {
				t.Fatalf("invalid or overlong SimpleTitle %q", got)
			}
			// SimpleTitle must NOT redact: declared literal fragments survive verbatim,
			// whereas the redacting Generate path would rewrite them.
			for _, literal := range fixture.LiteralContains {
				if !strings.Contains(got, literal) {
					t.Fatalf("SimpleTitle dropped literal fragment %q from %q; it must not redact", literal, got)
				}
				generated, genErr := pipeline.Generate(fixture.Input, TitleContext{Harness: fixture.Harness})
				if genErr != nil {
					t.Fatal(genErr)
				}
				if strings.Contains(generated.Text, literal) {
					t.Fatalf("literalContains fragment %q is vacuous: Generate preserved it too", literal)
				}
			}
		})
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

// inputContainsRecognizedWrapper reports whether a fixture input opens a wrapper
// the harness's production table recognizes. The fixture loader derives the
// no-echo requirement from that table, so a newly added wrapper cannot ship an
// error row without declaring its payload fragments.
func inputContainsRecognizedWrapper(input string, harness schema.Harness) bool {
	for _, name := range titleWrapperNames(harness) {
		if strings.Contains(input, "<"+name) {
			return true
		}
	}
	return false
}

func validateGenerateFromTurnsFixtures(cases []generateFromTurnsFixture) error {
	if len(cases) != 6 {
		return fmt.Errorf("redact: testdata/title.yaml defines %d generateFromTurns rows, want exactly 6; restore the reviewed turn-selection matrix", len(cases))
	}
	knownHarnesses := make(map[schema.Harness]struct{})
	for _, harness := range schema.Harnesses() {
		knownHarnesses[harness] = struct{}{}
	}
	seen := make(map[string]struct{}, len(cases))
	for i, fixture := range cases {
		if fixture.Name == "" {
			return fmt.Errorf("redact: generateFromTurns fixture row %d needs a unique name; name every turn-selection row", i)
		}
		if _, duplicate := seen[fixture.Name]; duplicate {
			return fmt.Errorf("redact: generateFromTurns fixture name %q is duplicated; give every turn-selection row a unique name", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
		if _, ok := knownHarnesses[fixture.Harness]; !ok {
			return fmt.Errorf("redact: generateFromTurns fixture %q uses unknown harness %q; use a schema Harnesses value", fixture.Name, fixture.Harness)
		}
		if fixture.WantIndex < -1 || fixture.WantIndex >= len(fixture.Turns) {
			return fmt.Errorf("redact: generateFromTurns fixture %q wants index %d for %d turns; declare -1 for no usable turn or a real turn index", fixture.Name, fixture.WantIndex, len(fixture.Turns))
		}
		if fixture.WantIndex == -1 && fixture.WantText != "" {
			return fmt.Errorf("redact: generateFromTurns fixture %q wants index -1 with title text %q; no usable turn means no text", fixture.Name, fixture.WantText)
		}
		if fixture.WantIndex >= 0 && fixture.WantText == "" {
			return fmt.Errorf("redact: generateFromTurns fixture %q selects turn %d without expected text; a selected turn always yields non-empty text", fixture.Name, fixture.WantIndex)
		}
		for _, expected := range fixture.SkippedErrorContains {
			if expected == "" {
				return fmt.Errorf("redact: generateFromTurns fixture %q declares an empty skipped-error fragment; an empty fragment matches everything", fixture.Name)
			}
		}
		for _, forbidden := range fixture.NoEchoContains {
			if forbidden == "" || strings.ContainsAny(forbidden, "<>") || !slices.ContainsFunc(fixture.Turns, func(turn string) bool { return strings.Contains(turn, forbidden) }) {
				return fmt.Errorf("redact: generateFromTurns fixture %q has a vacuous noEchoContains fragment %q; each fragment must be non-empty, occur inside a turn, and identify payload rather than wrapper markup", fixture.Name, forbidden)
			}
		}
	}
	return nil
}

func validateWrapperTableFixtures(tables []wrapperTableFixture) error {
	harnesses := schema.Harnesses()
	if len(tables) != len(harnesses) {
		return fmt.Errorf("redact: testdata/title.yaml declares %d wrapperTables rows, want exactly %d (one per known harness); declare the recognized wrappers of every harness, including the empty ones", len(tables), len(harnesses))
	}
	seen := make(map[schema.Harness]struct{}, len(tables))
	for _, table := range tables {
		if _, duplicate := seen[table.Harness]; duplicate {
			return fmt.Errorf("redact: wrapperTables declares harness %q twice; keep exactly one reviewed row per harness", table.Harness)
		}
		seen[table.Harness] = struct{}{}
		for i, entry := range table.Wrappers {
			if entry.Name == "" {
				return fmt.Errorf("redact: wrapperTables row %q entry %d has no wrapper name; name every recognized wrapper", table.Harness, i)
			}
			if _, err := titleWrapperActionFromFixture(entry.Action); err != nil {
				return fmt.Errorf("redact: wrapperTables row %q entry %q: %w", table.Harness, entry.Name, err)
			}
		}
	}
	return nil
}

func titleWrapperActionFromFixture(action string) (titleWrapperAction, error) {
	switch action {
	case "drop":
		return titleWrapperDrop, nil
	case "unwrap":
		return titleWrapperUnwrap, nil
	}
	return 0, fmt.Errorf("unknown wrapper action %q; use drop or unwrap", action)
}

// TestTitleWrapperTableMatchesFixture pins the compiled per-harness cleanup
// policy to the reviewed fixture table. Adding, removing, renaming, or
// re-actioning a wrapper fails here until the fixture records the change.
func TestTitleWrapperTableMatchesFixture(t *testing.T) {
	fixtures, err := loadTitleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	declared := make(map[schema.Harness]wrapperTableFixture, len(fixtures.WrapperTables))
	for _, table := range fixtures.WrapperTables {
		declared[table.Harness] = table
	}
	for _, harness := range schema.Harnesses() {
		table, ok := declared[harness]
		if !ok {
			t.Fatalf("wrapperTables declares no row for harness %q; every known harness needs a reviewed row", harness)
		}
		names := titleWrapperNames(harness)
		if len(names) != len(table.Wrappers) {
			t.Fatalf("harness %q recognizes %d wrappers %v, fixture declares %d; reconcile the reviewed table", harness, len(names), names, len(table.Wrappers))
		}
		policy := titleCleanPolicies[harness]
		for i, entry := range table.Wrappers {
			if names[i] != entry.Name {
				t.Fatalf("harness %q wrapper %d is %q, fixture declares %q; reconcile the reviewed table", harness, i, names[i], entry.Name)
			}
			wantAction, actionErr := titleWrapperActionFromFixture(entry.Action)
			if actionErr != nil {
				t.Fatal(actionErr)
			}
			if policy.wrappers[i].action != wantAction {
				t.Fatalf("harness %q wrapper %q has action %d, fixture declares %q; reconcile the reviewed table", harness, entry.Name, policy.wrappers[i].action, entry.Action)
			}
		}
		if !slices.Equal(titleWholeTurnPrefixes(harness), table.WholeTurnPrefixes) {
			t.Fatalf("harness %q whole-turn prefixes %v differ from the fixture %v; reconcile the reviewed table", harness, titleWholeTurnPrefixes(harness), table.WholeTurnPrefixes)
		}
		if len(names) == 0 {
			if _, compiled := titleCleanPolicies[harness]; compiled {
				t.Fatalf("harness %q declares no wrappers but has a compiled cleanup policy; a harness without wrappers must keep its first turn verbatim", harness)
			}
		}
	}
}

// TestTitlePipelineGenerateFromTurnsFixtures pins the turn-selection contract:
// injected turns and unusable turns are skipped, the first turn with real user
// prose supplies the title, and no skipped error echoes raw turn text.
func TestTitlePipelineGenerateFromTurnsFixtures(t *testing.T) {
	fixtures, err := loadTitleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := NewTitlePipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures.GenerateFromTurnsCases {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			active := pipeline
			if fixture.NilReceiver {
				active = nil
			}
			result, index, skipped := active.GenerateFromTurns(fixture.Turns, TitleContext{Harness: fixture.Harness, ProjectPath: fixture.ProjectPath})
			if index != fixture.WantIndex {
				t.Fatalf("selected turn index = %d, want %d", index, fixture.WantIndex)
			}
			if result.Text != fixture.WantText || !slices.Equal(result.Categories, fixture.WantCategories) {
				t.Fatalf("result = %#v, want text %q categories %v", result, fixture.WantText, fixture.WantCategories)
			}
			if len(skipped) != len(fixture.SkippedErrorContains) {
				t.Fatalf("skipped = %v, want exactly %d skipped turn errors", skipped, len(fixture.SkippedErrorContains))
			}
			for i, expected := range fixture.SkippedErrorContains {
				if !strings.Contains(skipped[i].Error(), expected) {
					t.Fatalf("skipped error %d = %v, want safe diagnostic containing %q", i, skipped[i], expected)
				}
			}
			for _, callErr := range skipped {
				for _, forbidden := range fixture.NoEchoContains {
					if strings.Contains(callErr.Error(), forbidden) {
						t.Fatalf("skipped error disclosed forbidden payload fragment %q", forbidden)
					}
				}
				for _, turn := range fixture.Turns {
					if turn != "" && strings.Contains(callErr.Error(), turn) {
						t.Fatal("skipped error disclosed a raw turn")
					}
				}
			}
		})
	}
}
