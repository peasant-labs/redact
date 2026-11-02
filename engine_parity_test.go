//go:build !no_re2

package redact

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/peasant-labs/schema"
	re2 "github.com/wasilibs/go-re2"
	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_parity.yaml
var engineParityData []byte

type engineParityCase struct {
	Name                string                 `yaml:"name"`
	Level               RedactionLevel         `yaml:"level"`
	Input               string                 `yaml:"input"`
	Output              string                 `yaml:"output"`
	Rules               []string               `yaml:"rules"`
	Patterns            []UserPattern          `yaml:"patterns"`
	Reports             []engineExpectedReport `yaml:"reports"`
	RequiredReportNames []string               `yaml:"required_report_names"`
}

type engineExpectedReport struct {
	Name   string         `yaml:"name"`
	Total  int            `yaml:"total"`
	Counts map[string]int `yaml:"counts"`
}

type engineParityFixtures struct {
	RequiredNames      []string           `yaml:"required_names"`
	Cases              []engineParityCase `yaml:"cases"`
	LiteralReplacement string             `yaml:"literal_replacement"`
	InvalidPattern     string             `yaml:"invalid_pattern"`
	XDGDataHome        string             `yaml:"xdg_data_home"`
	RoutingInput       string             `yaml:"routing_input"`
	TitleRoutingInput  string             `yaml:"title_routing_input"`
	RequiredOperations []string           `yaml:"required_operations"`
	Operations         []string           `yaml:"operations"`
}

func loadEngineParityFixtures(t *testing.T) engineParityFixtures {
	t.Helper()
	var fixtures engineParityFixtures
	if err := yaml.Unmarshal(engineParityData, &fixtures); err != nil {
		t.Fatal(err)
	}
	names := fixtureNames(fixtures.Cases, func(row engineParityCase) string { return row.Name })
	if err := requireFixtureNames("testdata/engine_parity.yaml", "required_names", fixtures.RequiredNames, names); err != nil {
		t.Fatal(err)
	}
	if err := requireFixtureNames("testdata/engine_parity.yaml", "required_operations", fixtures.RequiredOperations, fixtures.Operations); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixtures.Cases {
		if err := requireFixtureNames("testdata/engine_parity.yaml", row.Name+"/required_report_names", row.RequiredReportNames, fixtureNames(row.Reports, func(report engineExpectedReport) string { return report.Name })); err != nil {
			t.Fatal(err)
		}
		for _, report := range row.Reports {
			total := 0
			for _, count := range report.Counts {
				if count <= 0 {
					t.Fatalf("%s: expected per-rule counts must be positive", row.Name)
				}
				total += count
			}
			if report.Counts == nil || report.Total != total {
				t.Fatalf("%s: expected report counts missing or do not sum to total", row.Name)
			}
		}
	}
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate engine fixture %q; give each case a unique name", name)
		}
		seen[name] = true
	}
	if fixtures.LiteralReplacement == "" || fixtures.InvalidPattern == "" || fixtures.XDGDataHome == "" || fixtures.RoutingInput == "" || fixtures.TitleRoutingInput == "" {
		t.Fatal("engine fixture settings missing; restore literal replacement, invalid pattern, and XDG data home")
	}
	return fixtures
}

// engineCorpus reuses reviewed synthetic inputs rather than copying the rule
// catalog into another fixture. Every production rule must match at least one
// input and miss at least one input; filter rules must both keep and suppress.
func engineCorpus(t *testing.T) []engineParityCase {
	t.Helper()
	corpus := loadEngineParityFixtures(t).Cases
	behavior := loadRedactorBehaviorFixtures(t)
	for _, family := range [][]textRedactionFixture{behavior.Secrets, behavior.PII, behavior.Paths} {
		for _, row := range family {
			corpus = append(corpus, engineParityCase{Name: "redactor/" + row.ID, Level: row.Level, Input: row.Input})
		}
	}
	for _, row := range behavior.Parity {
		corpus = append(corpus, engineParityCase{Name: "parity/" + row.ID, Level: row.Level, Input: row.Input})
	}
	for _, row := range behavior.CodeBlocks {
		corpus = append(corpus, engineParityCase{Name: "code_blocks/" + row.ID, Input: row.Input})
	}
	for _, row := range behavior.CodePipeline {
		corpus = append(corpus, engineParityCase{Name: "code_pipeline/" + row.ID, Level: row.Level, Input: row.Input})
	}
	conformance, err := schema.LoadRedactionExamples()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range conformance {
		corpus = append(corpus, engineParityCase{Name: "conformance/" + row.Name, Level: RedactionLevel(row.Level), Input: row.OriginalText})
	}
	rules := mustLoadRuleFixtures(t)
	for _, family := range rules.Rules {
		for _, row := range family.Cases {
			corpus = append(corpus, engineParityCase{Name: family.RuleID + "/" + row.Name, Input: row.Input})
		}
	}
	project, err := loadProjectRuleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range project.Rules {
		for _, row := range family.Cases {
			corpus = append(corpus, engineParityCase{Name: family.RuleID + "/" + row.Name, Input: row.Input})
		}
	}
	for _, row := range rules.Residues {
		corpus = append(corpus, engineParityCase{Name: "residue/" + row.Name, Input: row.Input})
	}
	for _, row := range project.Residues {
		corpus = append(corpus, engineParityCase{Name: "residue/" + row.Name, Input: row.Input})
	}
	for _, row := range loadResidueFixtures(t).PositiveTriggers {
		corpus = append(corpus, engineParityCase{Name: "residue/" + row.ID, Input: row.Input})
	}
	falsePositives, err := LoadFalsePositiveFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range falsePositives {
		corpus = append(corpus, engineParityCase{Name: row.Name, Level: row.Level, Input: row.Input})
	}
	return corpus
}

func TestEngineRuleParity(t *testing.T) {
	e := goRE2Engine{}
	if e.Identity() != engineGoRE2 {
		t.Fatal("go-re2 adapter reports the wrong engine identity")
	}
	fixtures := loadEngineParityFixtures(t)
	corpus := engineCorpus(t)
	for _, rule := range Rules {
		t.Run(rule.ID, func(t *testing.T) {
			pattern, err := (goRE2Engine{}).Compile(rule.Pattern.String())
			if err != nil {
				t.Fatal(err)
			}
			if pattern.String() != rule.Pattern.String() {
				t.Fatal("adapter changed the pattern source")
			}
			var matched, missed, kept, suppressed bool
			for _, row := range corpus {
				want := rule.Pattern.FindAllStringIndex(row.Input, -1)
				got := pattern.FindAllStringIndex(row.Input, -1)
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: spans = %v, stdlib = %v", row.Name, got, want)
				}
				matched = matched || len(want) > 0
				missed = missed || len(want) == 0
				if got, want := pattern.ReplaceAllString(row.Input, rule.Replacement), rule.Pattern.ReplaceAllString(row.Input, rule.Replacement); got != want {
					t.Fatalf("%s: replacement = %q, stdlib = %q", row.Name, got, want)
				}
				if got, want := pattern.ReplaceAllLiteralString(row.Input, fixtures.LiteralReplacement), rule.Pattern.ReplaceAllLiteralString(row.Input, fixtures.LiteralReplacement); got != want {
					t.Fatalf("%s: literal replacement = %q, stdlib = %q", row.Name, got, want)
				}
				for _, loc := range want {
					if rule.FilterFn != nil {
						accepted := rule.FilterFn(row.Input[loc[0]:loc[1]], row.Input, loc[0])
						kept = kept || accepted
						suppressed = suppressed || !accepted
					}
				}
			}
			if !matched || !missed || (rule.FilterFn != nil && (!kept || !suppressed)) {
				t.Fatalf("incomplete corpus: match=%v miss=%v filter_keep=%v filter_suppress=%v; add the missing synthetic boundary", matched, missed, kept, suppressed)
			}
		})
	}
	if pattern, err := (goRE2Engine{}).Compile(fixtures.InvalidPattern); err == nil || pattern != nil {
		t.Fatalf("invalid pattern: got %v, %v; compilation must refuse", pattern, err)
	}
}

func newEngineTestRedactor(t *testing.T, e engine, patterns []UserPattern) Redactor {
	t.Helper()
	fixtures := loadEngineParityFixtures(t)
	r, err := newRedactorWithEngine(e, Standard, patterns, XDGPaths{DataHome: fixtures.XDGDataHome})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assertEngineReports(t *testing.T, actual, baseline RedactionReport) {
	t.Helper()
	// Legacy category insertion iterates a count map, so its order is not a
	// contract. Preserve exact membership, counts, warnings, and last matches.
	slices.Sort(actual.Categories)
	slices.Sort(baseline.Categories)
	if !reflect.DeepEqual(actual, baseline) {
		t.Fatalf("report = %#v, stdlib = %#v", actual, baseline)
	}
}

func TestEnginePublicTextParity(t *testing.T) {
	baselines, actuals := make(map[RedactionLevel]Redactor), make(map[RedactionLevel]Redactor)
	for _, row := range engineCorpus(t) {
		t.Run(row.Name, func(t *testing.T) {
			level := row.Level
			if level == "" {
				level = Standard
			}
			if level == Maximum && !MaximumAvailable {
				t.Skip("Maximum mechanics require cgo; exercised by the cgo-enabled parity run")
			}
			if baselines[level] == nil {
				var err error
				baselines[level], err = newRedactorWithEngine(goRegexpEngine{}, level, nil, XDGPaths{})
				if err != nil {
					t.Fatal(err)
				}
				actuals[level], err = newRedactorWithEngine(goRE2Engine{}, level, nil, XDGPaths{})
				if err != nil {
					t.Fatal(err)
				}
			}
			baseline, actual := baselines[level], actuals[level]
			t.Logf("level=%s input=%q", level, row.Input)
			wantMatches, gotMatches := baseline.Detect(row.Input), actual.Detect(row.Input)
			if !reflect.DeepEqual(gotMatches, wantMatches) {
				t.Fatalf("Detect = %v, stdlib = %v", gotMatches, wantMatches)
			}
			if got, want := actual.Redact(row.Input, gotMatches), baseline.Redact(row.Input, wantMatches); got != want {
				t.Fatalf("Redact = %q, stdlib = %q", got, want)
			}
			if got, want := actual.RedactText(row.Input), baseline.RedactText(row.Input); got != want {
				t.Fatalf("RedactText = %q, stdlib = %q", got, want)
			}
			assertEngineReports(t, actual.Report(), baseline.Report())
		})
	}
}

func TestEngineMetadataPathParity(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).MetadataPaths {
		t.Run(row.ID, func(t *testing.T) {
			actual, err := newRedactorWithEngine(goRE2Engine{}, row.Level, nil, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := newRedactorWithEngine(goRegexpEngine{}, row.Level, nil, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			got, want := actual.RedactMetadata(metadataPathInput(row)), baseline.RedactMetadata(metadataPathInput(row))
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("level=%s RedactMetadata = %#v, stdlib = %#v", row.Level, got, want)
			}
			assertEngineReports(t, actual.Report(), baseline.Report())
		})
	}
}

func TestEnginePublicStructuredParity(t *testing.T) {
	for _, row := range loadEngineParityFixtures(t).Cases {
		t.Run(row.Name, func(t *testing.T) {
			actual := newEngineTestRedactor(t, goRE2Engine{}, row.Patterns)
			baseline := newEngineTestRedactor(t, goRegexpEngine{}, row.Patterns)
			matches := actual.Detect(row.Input)
			ids := make([]string, 0, len(matches))
			for _, match := range matches {
				ids = append(ids, match.Rule)
			}
			if !slices.Equal(ids, row.Rules) {
				t.Fatalf("rule order = %v, want %v", ids, row.Rules)
			}
			for call, expected := range row.Reports {
				if got := actual.RedactText(row.Input); got != row.Output {
					t.Fatalf("go-re2 call %d: RedactText = %q, want %q", call+1, got, row.Output)
				}
				assertExpectedEngineReport(t, engineGoRE2, call+1, actual.Report(), expected)
				if got := baseline.RedactText(row.Input); got != row.Output {
					t.Fatalf("stdlib call %d: RedactText = %q, want %q", call+1, got, row.Output)
				}
				assertExpectedEngineReport(t, engineGoRegexp, call+1, baseline.Report(), expected)
				assertEngineReports(t, actual.Report(), baseline.Report())
			}
			value := []any{row.Input, map[string]any{"text": row.Input}, json.Number("9007199254740993")}
			if got, want := actual.RedactJSON(value), baseline.RedactJSON(value); !reflect.DeepEqual(got, want) {
				t.Fatalf("RedactJSON = %#v, stdlib = %#v", got, want)
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := RedactJSONDocBytes(actual, data), RedactJSONDocBytes(baseline, data); string(got) != string(want) {
				t.Fatalf("RedactJSONDocBytes = %s, stdlib = %s", got, want)
			}
			got, gotErr := RedactJSONLBytes(actual, append(data, '\n'))
			want, wantErr := RedactJSONLBytes(baseline, append(data, '\n'))
			if gotErr != nil || wantErr != nil || string(got) != string(want) {
				t.Fatalf("RedactJSONLBytes = %s, %v; stdlib = %s, %v", got, gotErr, want, wantErr)
			}
			meta := schema.NewUnifiedMetadata()
			meta.CWD, meta.Project.FilePath, meta.Source.FilePath = row.Input, row.Input, row.Input
			meta.Git.Remote = &row.Input
			before := meta
			if got, want := actual.RedactMetadata(&meta), baseline.RedactMetadata(&meta); !reflect.DeepEqual(got, want) {
				t.Fatalf("RedactMetadata = %#v, stdlib = %#v", got, want)
			}
			if !reflect.DeepEqual(meta, before) {
				t.Fatal("RedactMetadata mutated its input")
			}
			if actual.Level() != baseline.Level() || actual.RuleSetVersion() != baseline.RuleSetVersion() {
				t.Fatal("engine changed level or rule-set version")
			}
		})
	}
}

func assertExpectedEngineReport(t *testing.T, name engineName, call int, got RedactionReport, want engineExpectedReport) {
	t.Helper()
	if got.TotalRedactions != want.Total || !reflect.DeepEqual(got.Counts, want.Counts) {
		t.Fatalf("%s call %d: report total=%d counts=%v, want total=%d counts=%v", name, call, got.TotalRedactions, got.Counts, want.Total, want.Counts)
	}
}

func TestEngineConfiguredAndXDGRulesCompiled(t *testing.T) {
	for _, row := range loadEngineParityFixtures(t).Cases {
		t.Run(row.Name, func(t *testing.T) {
			r := newEngineTestRedactor(t, goRE2Engine{}, row.Patterns).(*DefaultRedactor)
			if r.configuredRuleCount != len(row.Patterns) {
				t.Fatal("configured rules missing from the constructor")
			}
			var xdgFound bool
			for index, rule := range r.userRules {
				// Inspect the actual map, not lookup: its stdlib fallback could
				// otherwise conceal an uncompiled configured or generated rule.
				pattern, exists := r.patterns[rule.Pattern]
				if _, ok := pattern.(*re2.Regexp); !exists || !ok {
					t.Fatalf("%s: engine map entry = %T, present=%v; want *re2.Regexp", rule.ID, pattern, exists)
				}
				if index >= r.configuredRuleCount && rule.ID == "xdg_data_home" {
					xdgFound = true
				}
			}
			if !xdgFound {
				t.Fatal("generated XDG data-home rule missing; the routing assertion must not be vacuous")
			}
		})
	}
}

func TestEngineConcurrentTextParity(t *testing.T) {
	actual := newEngineTestRedactor(t, goRE2Engine{}, nil)
	baseline := newEngineTestRedactor(t, goRegexpEngine{}, nil)
	for _, row := range loadEngineParityFixtures(t).Cases {
		t.Run(row.Name, func(t *testing.T) {
			t.Parallel()
			if got, want := actual.RedactText(row.Input), baseline.RedactText(row.Input); got != want {
				t.Fatalf("concurrent RedactText = %q, stdlib = %q", got, want)
			}
			// Exercise report snapshots while other calls update the same
			// redactor. Last-call match ordering is intentionally unspecified
			// across concurrent calls, so only output parity is asserted.
			actual.Report()
		})
	}
}

func TestEngineResidueParity(t *testing.T) {
	patterns, err := compileRulePatterns(goRE2Engine{}, Rules, nil, ResidueRules)
	if err != nil {
		t.Fatal(err)
	}
	actual := &DefaultResidueDetector{patterns: patterns}
	baseline := NewResidueDetector()
	seen := make(map[string]bool)
	for _, row := range engineCorpus(t) {
		got, want := actual.Scan(row.Input), baseline.Scan(row.Input)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: residue = %v, stdlib = %v", row.Name, got, want)
		}
		for _, warning := range got {
			seen[warning.RuleID] = true
		}
	}
	for _, rule := range ResidueRules {
		if !seen[rule.ID] {
			t.Errorf("residue rule %s has no positive corpus input; add a synthetic case", rule.ID)
		}
	}
}

func TestEngineTitleParity(t *testing.T) {
	fixtures, err := loadTitleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := newTitlePipelineWithEngine(goRE2Engine{})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := newTitlePipelineWithEngine(goRegexpEngine{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range fixtures.Cases {
		t.Run(row.Name, func(t *testing.T) {
			context := TitleContext{Harness: row.Harness, ProjectPath: row.ProjectPath}
			got, gotErr := actual.Generate(row.Input, context)
			want, wantErr := baseline.Generate(row.Input, context)
			if !reflect.DeepEqual(got, want) || engineErrorText(gotErr) != engineErrorText(wantErr) {
				t.Fatalf("Generate = %#v, %v; stdlib = %#v, %v", got, gotErr, want, wantErr)
			}
			got, gotErr = actual.Sanitize(row.Input, context)
			want, wantErr = baseline.Sanitize(row.Input, context)
			if !reflect.DeepEqual(got, want) || engineErrorText(gotErr) != engineErrorText(wantErr) {
				t.Fatalf("Sanitize = %#v, %v; stdlib = %#v, %v", got, gotErr, want, wantErr)
			}
		})
	}
}

func engineErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// trackingEngine delegates to the actual adapter. It detects wiring regressions
// that differential output alone cannot catch when both engines agree.
type trackingEngine struct {
	engine
	scans, replacements int
}

func (e *trackingEngine) Compile(pattern string) (compiled, error) {
	p, err := e.engine.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return trackingPattern{compiled: p, engine: e}, nil
}

type trackingPattern struct {
	compiled
	engine *trackingEngine
}

func (p trackingPattern) FindAllStringIndex(s string, n int) [][]int {
	p.engine.scans++
	return p.compiled.FindAllStringIndex(s, n)
}

func (p trackingPattern) ReplaceAllString(s, repl string) string {
	p.engine.replacements++
	return p.compiled.ReplaceAllString(s, repl)
}

func TestEnginePublicPathUsesAdapter(t *testing.T) {
	fixtures := loadEngineParityFixtures(t)
	for _, operation := range fixtures.Operations {
		t.Run(operation, func(t *testing.T) {
			e := &trackingEngine{engine: goRE2Engine{}}
			r := newEngineTestRedactor(t, e, nil)
			input := fixtures.RoutingInput
			matches := r.Detect(input)
			e.scans, e.replacements = 0, 0
			switch operation {
			case "Detect":
				r.Detect(input)
			case "Redact":
				r.Redact(input, matches)
			case "RedactText":
				r.RedactText(input)
			case "RedactJSON":
				r.RedactJSON(input)
			case "RedactMetadata":
				meta := schema.NewUnifiedMetadata()
				meta.Git.Remote = &input
				r.RedactMetadata(&meta)
			case "RedactJSONLBytes", "RedactJSONDocBytes":
				data, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "RedactJSONLBytes" {
					if _, err := RedactJSONLBytes(r, data); err != nil {
						t.Fatal(err)
					}
				} else {
					RedactJSONDocBytes(r, data)
				}
			case "Generate", "Sanitize":
				p, err := newTitlePipelineWithEngine(e)
				if err != nil {
					t.Fatal(err)
				}
				// A non-path input survives title path normalization and reaches
				// the canonical rule scanner through the selected engine.
				if operation == "Generate" {
					_, err = p.Generate(fixtures.TitleRoutingInput, TitleContext{})
				} else {
					_, err = p.Sanitize(fixtures.TitleRoutingInput, TitleContext{})
				}
				if err != nil {
					t.Fatal(err)
				}
			case "Scan":
				r.(*DefaultRedactor).residueDetector.Scan(input)
			default:
				t.Fatalf("unknown engine operation %q; implement the production-path assertion", operation)
			}
			if operation == "Redact" {
				if e.scans != 0 || e.replacements == 0 {
					t.Fatalf("Redact scans=%d replacements=%d; must use the adapter without rescanning", e.scans, e.replacements)
				}
			} else if e.scans == 0 {
				t.Fatal("public operation bypassed the selected adapter")
			}
		})
	}
}
