package redact

import (
	_ "embed"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/peasant-labs/schema"
	"gopkg.in/yaml.v3"
)

//go:embed testdata/redactor_behavior.yaml
var redactorBehaviorFixtureData []byte

// Every family carries a reviewed name manifest. requireFixtureNames asserts
// exact membership in both directions, so a deleted row and an unreviewed new
// row both fail without a bare row count to bump.
type redactorBehaviorFixtures struct {
	RequiredSecretsIDs      []string               `yaml:"required_secrets_ids"`
	Secrets                 []textRedactionFixture `yaml:"secrets"`
	RequiredPIIIDs          []string               `yaml:"required_pii_ids"`
	PII                     []textRedactionFixture `yaml:"pii"`
	RequiredPathsIDs        []string               `yaml:"required_paths_ids"`
	Paths                   []textRedactionFixture `yaml:"paths"`
	RequiredCodeBlocksIDs   []string               `yaml:"required_code_blocks_ids"`
	CodeBlocks              []codeBlockFixture     `yaml:"code_blocks"`
	RequiredParityIDs       []string               `yaml:"required_parity_ids"`
	Parity                  []parityFixture        `yaml:"parity"`
	RequiredMetadataPathIDs []string               `yaml:"required_metadata_paths_ids"`
	MetadataPaths           []metadataPathFixture  `yaml:"metadata_paths"`
	RequiredCodePipelineIDs []string               `yaml:"required_code_pipeline_ids"`
	CodePipeline            []codePipelineFixture  `yaml:"code_pipeline"`
	RequiredJSONKeyIDs      []string               `yaml:"required_json_keys_ids"`
	JSONKeys                []jsonKeyFixture       `yaml:"json_keys"`
	RequiredUnchangedIDs    []string               `yaml:"required_unchanged_text_ids"`
	UnchangedText           []unchangedTextFixture `yaml:"unchanged_text"`
	RequiredObservedKeyIDs  []string               `yaml:"required_observed_json_keys_ids"`
	ObservedJSONKeys        []observedKeyFixture   `yaml:"observed_json_keys"`
	RequiredObservedTextIDs []string               `yaml:"required_observed_text_ids"`
	ObservedText            []observedTextFixture  `yaml:"observed_text"`
	RequiredInactiveRuleIDs []string               `yaml:"required_inactive_json_key_rules_ids"`
	InactiveJSONKeyRules    []inactiveRuleFixture  `yaml:"inactive_json_key_rules"`
	JSONKeySets             jsonKeySetsFixture     `yaml:"json_key_sets"`
	RequiredTextOutputIDs   []string               `yaml:"required_standard_text_outputs_ids"`
	TextOutputs             []textOutputFixture    `yaml:"standard_text_outputs"`
	RequiredValueRuleIDs    []string               `yaml:"required_value_rule_replacements_ids"`
	ValueRuleReplacements   []valueRuleFixture     `yaml:"value_rule_replacements"`
	RequiredLinearTimeIDs   []string               `yaml:"required_linear_time_ids"`
	LinearTime              []linearTimeFixture    `yaml:"linear_time"`
}

// textOutputFixture is a text and the exact output of RedactText at standard.
// A second pass over the output must return it unchanged.
type textOutputFixture struct {
	ID    string `yaml:"id"`
	Why   string `yaml:"why"`
	Input string `yaml:"input"`
	Want  string `yaml:"want"`
}

// valueRuleFixture is a rule that replaces a value and not its whole pattern
// match: the placeholder its Replacement must be, and the output of the
// recovery path, which applies the pattern alone, for one input.
type valueRuleFixture struct {
	ID             string `yaml:"id"`
	Why            string `yaml:"why"`
	Placeholder    string `yaml:"placeholder"`
	RecoveryInput  string `yaml:"recovery_input"`
	RecoveryOutput string `yaml:"recovery_output"`
}

// linearTimeFixture is a short text that RedactText must read in time that
// follows the length of the input when the text is repeated with no space
// between the copies.
type linearTimeFixture struct {
	ID   string `yaml:"id"`
	Why  string `yaml:"why"`
	Unit string `yaml:"unit"`
}

// observedKeyFixture is a JSON document in which RedactJSON replaces exactly
// one value because of its key, and the rule an observer must see for it.
type observedKeyFixture struct {
	ID       string   `yaml:"id"`
	Why      string   `yaml:"why"`
	JSON     string   `yaml:"json"`
	Rule     string   `yaml:"rule"`
	Category Category `yaml:"category"`
}

// observedTextFixture is a text and the detections an observer must be told of
// for it at standard: every rule with a count above zero, and no other.
type observedTextFixture struct {
	ID         string         `yaml:"id"`
	Why        string         `yaml:"why"`
	Input      string         `yaml:"input"`
	Detections map[string]int `yaml:"detections"`
}

// inactiveRuleFixture is a JSON document that RedactJSON must return as it is
// while the named rule is not active at the configured level.
type inactiveRuleFixture struct {
	ID   string `yaml:"id"`
	Why  string `yaml:"why"`
	Rule string `yaml:"rule"`
	JSON string `yaml:"json"`
}

// jsonKeySetsFixture holds the closed lists RedactJSON reads an object key by.
type jsonKeySetsFixture struct {
	JWKPrivateMembers []string `yaml:"jwk_private_members"`
	HeaderValueKeys   []string `yaml:"header_value_keys"`
}

// unchangedTextFixture is a text that RedactText must return as it is, at
// minimal and at standard. It states the outcome a skip case promises: not
// only that one rule stayed silent, but that nothing in the text changed.
type unchangedTextFixture struct {
	ID    string `yaml:"id"`
	Why   string `yaml:"why"`
	Input string `yaml:"input"`
}

// jsonKeyFixture drives RedactJSON on a whole document. JSON and Want are JSON
// text; the test compares decoded values, so key order and spacing do not matter.
type jsonKeyFixture struct {
	ID    string         `yaml:"id"`
	Why   string         `yaml:"why"`
	Level RedactionLevel `yaml:"level"`
	JSON  string         `yaml:"json"`
	Want  string         `yaml:"want"`
	// KeyRedactions is the number of redactions Report() counts for the
	// key-name rule and the JSON Web Key rule after the first pass.
	KeyRedactions int `yaml:"key_redactions"`
	// Counts, when set, is every count Report() holds after the first pass.
	Counts map[string]int `yaml:"counts"`
	// Categories, when set, is every category Report() names after the first
	// pass, in any order.
	Categories []string `yaml:"categories"`
}

// metadataPathFixture drives RedactMetadata, the context-aware stage that knows
// the owner of the session. Each want_* expectation is asserted only when its
// input field is set, so a row states exactly the fields it is about.
type metadataPathFixture struct {
	ID                  string         `yaml:"id"`
	Why                 string         `yaml:"why"`
	Level               RedactionLevel `yaml:"level"`
	SourceFilePath      string         `yaml:"source_file_path"`
	CWD                 string         `yaml:"cwd"`
	ProjectFilePath     string         `yaml:"project_file_path"`
	ProjectName         string         `yaml:"project_name"`
	HostSlug            string         `yaml:"host_slug"`
	WantSourceFilePath  string         `yaml:"want_source_file_path"`
	WantCWD             string         `yaml:"want_cwd"`
	WantProjectFilePath string         `yaml:"want_project_file_path"`
	WantProjectName     string         `yaml:"want_project_name"`
	WantHostSlug        string         `yaml:"want_host_slug"`
	Idempotent          bool           `yaml:"idempotent"`
}

type textRedactionFixture struct {
	ID       string         `yaml:"id"`
	Level    RedactionLevel `yaml:"level"`
	Input    string         `yaml:"input"`
	Contains string         `yaml:"contains"`
	Absent   string         `yaml:"absent"`
}

type codeBlockFixture struct {
	ID    string `yaml:"id"`
	Input string `yaml:"input"`
	Want  string `yaml:"want"`
}
type parityFixture struct {
	ID    string         `yaml:"id"`
	Level RedactionLevel `yaml:"level"`
	Input string         `yaml:"input"`
	Want  string         `yaml:"want"`
}
type codePipelineFixture struct {
	ID       string         `yaml:"id"`
	Level    RedactionLevel `yaml:"level"`
	Input    string         `yaml:"input"`
	Contains []string       `yaml:"contains"`
	Absent   []string       `yaml:"absent"`
}

func loadRedactorBehaviorFixtures(t *testing.T) redactorBehaviorFixtures {
	t.Helper()
	var fixtures redactorBehaviorFixtures
	if err := yaml.Unmarshal(redactorBehaviorFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/redactor_behavior.yaml while loading redactor behavior fixtures: %v", err)
	}
	checkFixtureFamily(t, "secrets", fixtures.RequiredSecretsIDs, textFixtureIDs(fixtures.Secrets))
	checkFixtureFamily(t, "pii", fixtures.RequiredPIIIDs, textFixtureIDs(fixtures.PII))
	checkFixtureFamily(t, "paths", fixtures.RequiredPathsIDs, textFixtureIDs(fixtures.Paths))
	checkFixtureFamily(t, "code_blocks", fixtures.RequiredCodeBlocksIDs, codeBlockFixtureIDs(fixtures.CodeBlocks))
	checkFixtureFamily(t, "parity", fixtures.RequiredParityIDs, parityFixtureIDs(fixtures.Parity))
	checkFixtureFamily(t, "metadata_paths", fixtures.RequiredMetadataPathIDs, metadataPathFixtureIDs(fixtures.MetadataPaths))
	checkFixtureFamily(t, "code_pipeline", fixtures.RequiredCodePipelineIDs, codePipelineFixtureIDs(fixtures.CodePipeline))
	checkFixtureFamily(t, "json_keys", fixtures.RequiredJSONKeyIDs, jsonKeyFixtureIDs(fixtures.JSONKeys))
	for _, row := range fixtures.JSONKeys {
		checkFixtureLevel(t, row.ID, row.Level)
		if row.Why == "" || row.JSON == "" || row.Want == "" {
			t.Fatalf("JSON key fixture %q is incomplete; why, json and want are required", row.ID)
		}
	}
	checkFixtureFamily(t, "unchanged_text", fixtures.RequiredUnchangedIDs, unchangedTextFixtureIDs(fixtures.UnchangedText))
	for _, row := range fixtures.UnchangedText {
		if row.Why == "" || row.Input == "" {
			t.Fatalf("unchanged text fixture %q is incomplete; why and input are required", row.ID)
		}
	}
	checkFixtureFamily(t, "observed_json_keys", fixtures.RequiredObservedKeyIDs, fixtureNames(fixtures.ObservedJSONKeys, func(row observedKeyFixture) string { return row.ID }))
	for _, row := range fixtures.ObservedJSONKeys {
		if row.Why == "" || row.JSON == "" || row.Rule == "" || !row.Category.IsValid() {
			t.Fatalf("observed JSON key fixture %q is incomplete; why, json, rule and a valid category are required", row.ID)
		}
	}
	checkFixtureFamily(t, "observed_text", fixtures.RequiredObservedTextIDs, fixtureNames(fixtures.ObservedText, func(row observedTextFixture) string { return row.ID }))
	for _, row := range fixtures.ObservedText {
		if row.Why == "" || row.Input == "" || len(row.Detections) == 0 {
			t.Fatalf("observed text fixture %q is incomplete; why, input and detections are required", row.ID)
		}
	}
	checkFixtureFamily(t, "inactive_json_key_rules", fixtures.RequiredInactiveRuleIDs, fixtureNames(fixtures.InactiveJSONKeyRules, func(row inactiveRuleFixture) string { return row.ID }))
	for _, row := range fixtures.InactiveJSONKeyRules {
		if row.Why == "" || row.JSON == "" || row.Rule == "" {
			t.Fatalf("inactive JSON key rule fixture %q is incomplete; why, rule and json are required", row.ID)
		}
	}
	checkFixtureFamily(t, "standard_text_outputs", fixtures.RequiredTextOutputIDs, fixtureNames(fixtures.TextOutputs, func(row textOutputFixture) string { return row.ID }))
	for _, row := range fixtures.TextOutputs {
		if row.Why == "" || row.Input == "" || row.Want == "" {
			t.Fatalf("standard text output fixture %q is incomplete; why, input and want are required", row.ID)
		}
	}
	checkFixtureFamily(t, "value_rule_replacements", fixtures.RequiredValueRuleIDs, fixtureNames(fixtures.ValueRuleReplacements, func(row valueRuleFixture) string { return row.ID }))
	for _, row := range fixtures.ValueRuleReplacements {
		if row.Why == "" || row.Placeholder == "" || row.RecoveryInput == "" || row.RecoveryOutput == "" {
			t.Fatalf("value rule fixture %q is incomplete; why, placeholder, recovery_input and recovery_output are required", row.ID)
		}
	}
	checkFixtureFamily(t, "linear_time", fixtures.RequiredLinearTimeIDs, fixtureNames(fixtures.LinearTime, func(row linearTimeFixture) string { return row.ID }))
	for _, row := range fixtures.LinearTime {
		if row.Why == "" || row.Unit == "" {
			t.Fatalf("linear time fixture %q is incomplete; why and unit are required", row.ID)
		}
	}
	if len(fixtures.JSONKeySets.JWKPrivateMembers) == 0 || len(fixtures.JSONKeySets.HeaderValueKeys) == 0 {
		t.Fatal("the redactor behavior fixture has no json_key_sets; restore both closed lists")
	}
	for _, row := range fixtures.MetadataPaths {
		checkFixtureLevel(t, row.ID, row.Level)
		if row.Why == "" {
			t.Fatalf("metadata path fixture %q has no why; state what the row protects so a later reader can judge a change to it", row.ID)
		}
		if row.WantSourceFilePath == "" && row.WantCWD == "" && row.WantProjectFilePath == "" && row.WantProjectName == "" && row.WantHostSlug == "" {
			t.Fatalf("metadata path fixture %q states no expectation; give it at least one want_ field", row.ID)
		}
	}
	for _, family := range [][]textRedactionFixture{fixtures.Secrets, fixtures.PII, fixtures.Paths} {
		for _, row := range family {
			checkFixtureLevel(t, row.ID, row.Level)
			if row.Contains == "" && row.Absent == "" {
				t.Fatalf("redactor behavior fixture %q has no expected outcome", row.ID)
			}
		}
	}
	for _, row := range fixtures.Parity {
		checkFixtureLevel(t, row.ID, row.Level)
	}
	for _, row := range fixtures.CodePipeline {
		checkFixtureLevel(t, row.ID, row.Level)
	}
	return fixtures
}

func checkFixtureLevel(t *testing.T, id string, level RedactionLevel) {
	t.Helper()
	if level != Minimal && level != Standard && level != Maximum {
		t.Fatalf("redactor behavior fixture %q has unsupported level %q", id, level)
	}
}

func checkFixtureFamily(t *testing.T, family string, manifest, ids []string) {
	t.Helper()
	seen := make(map[string]struct{}, len(ids))
	for row, id := range ids {
		if id == "" {
			t.Fatalf("redactor behavior fixture family %q row %d has an empty identity", family, row)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("redactor behavior fixture family %q has duplicate identity %q", family, id)
		}
		seen[id] = struct{}{}
	}
	if err := requireFixtureNames("testdata/redactor_behavior.yaml", "required_"+family+"_ids", manifest, ids); err != nil {
		t.Fatal(err)
	}
}

func textFixtureIDs(rows []textRedactionFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func codeBlockFixtureIDs(rows []codeBlockFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func metadataPathFixtureIDs(rows []metadataPathFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func codePipelineFixtureIDs(rows []codePipelineFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func jsonKeyFixtureIDs(rows []jsonKeyFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func unchangedTextFixtureIDs(rows []unchangedTextFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func parityFixtureIDs(rows []parityFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

// TestRedactMetadata_PathFixtures pins the canonical redacted form of every
// owner-owned path in session metadata: the project folder survives, everything
// above it becomes one placeholder, and the same rule applies to the slug forms
// of that path.
func TestRedactMetadata_PathFixtures(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).MetadataPaths {
		t.Run(row.ID, func(t *testing.T) {
			redactor := mustNewRedactor(t, row.Level, nil)
			result := redactor.RedactMetadata(metadataPathInput(row))
			assertMetadataPathRow(t, row, "first pass", result)
			if row.Idempotent {
				assertMetadataPathRow(t, row, "second pass", redactor.RedactMetadata(result))
			}
		})
	}
}

func metadataPathInput(row metadataPathFixture) *schema.UnifiedMetadata {
	meta := schema.NewUnifiedMetadata()
	meta.Source.FilePath = row.SourceFilePath
	meta.CWD = row.CWD
	meta.Project.FilePath = row.ProjectFilePath
	meta.Project.Name = row.ProjectName
	meta.HostSlug = schema.HostSlug(row.HostSlug)
	return &meta
}

func assertMetadataPathRow(t *testing.T, row metadataPathFixture, pass string, result *schema.UnifiedMetadata) {
	t.Helper()
	for _, field := range []struct {
		name string
		want string
		got  string
	}{
		{"source file path", row.WantSourceFilePath, result.Source.FilePath},
		{"working directory", row.WantCWD, result.CWD},
		{"project file path", row.WantProjectFilePath, result.Project.FilePath},
		{"project name", row.WantProjectName, result.Project.Name},
		{"host slug", row.WantHostSlug, string(result.HostSlug)},
	} {
		if field.want == "" {
			continue
		}
		if field.got != field.want {
			t.Errorf("%s redacted %s = %q, want %q", pass, field.name, field.got, field.want)
		}
	}
}

// TestRedactJSON_KeyNameFixtures pins how RedactJSON treats a string value
// under an object key that names a secret, and that every skip the text form
// makes holds for the JSON form too.
func TestRedactJSON_KeyNameFixtures(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).JSONKeys {
		t.Run(row.ID, func(t *testing.T) {
			redactor := mustNewRedactor(t, row.Level, nil)
			got := redactor.RedactJSON(decodeJSONFixture(t, row.ID, row.JSON))
			want := decodeJSONFixture(t, row.ID, row.Want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("RedactJSON(%s) = %#v, want %#v", row.JSON, got, want)
			}
			counts := redactor.Report().Counts
			if counted := counts[keyNameSecretRuleID] + counts[jwkPrivateMemberRuleID]; counted != row.KeyRedactions {
				t.Errorf("Report() counts %d key redactions, want %d (counts: %v)", counted, row.KeyRedactions, counts)
			}
			if row.Counts != nil && !reflect.DeepEqual(counts, row.Counts) {
				t.Errorf("Report() counts = %v, want exactly %v", counts, row.Counts)
			}
			if categories := slices.Sorted(slices.Values(redactor.Report().Categories)); row.Categories != nil && !slices.Equal(categories, slices.Sorted(slices.Values(row.Categories))) {
				t.Errorf("Report() categories = %v, want exactly %v", categories, row.Categories)
			}
			if again := redactor.RedactJSON(got); !reflect.DeepEqual(again, want) {
				t.Errorf("second RedactJSON pass = %#v, want %#v; redaction must be idempotent", again, want)
			}
		})
	}
}

func decodeJSONFixture(t *testing.T, id, text string) any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("JSON key fixture %q holds invalid JSON %q: %v", id, text, err)
	}
	return value
}

// TestRedactText_UnchangedFixtures pins the texts no rule may touch: every
// placeholder, reference, literal and count the key-name rules must skip comes
// back byte for byte at both offered levels.
func TestRedactText_UnchangedFixtures(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).UnchangedText {
		for _, level := range []RedactionLevel{Minimal, Standard} {
			t.Run(row.ID+"/"+level.String(), func(t *testing.T) {
				if got := mustNewRedactor(t, level, nil).RedactText(row.Input); got != row.Input {
					t.Errorf("RedactText(%q) = %q, want it unchanged: %s", row.Input, got, row.Why)
				}
			})
		}
	}
}

// isKeyNameRule reports whether id is one of the rules in key_name_rules.go.
// They come after every format rule in the rule table, so that a format rule
// wins when its match and a value match span the same text.
func isKeyNameRule(id string) bool {
	return id == keyNameSecretRuleID || id == urlQuerySecretRuleID || id == cookieHeaderRuleID
}

// TestRules_KeyNameRulesComeLast pins the table order the overlap rules rely
// on: two matches of equal offset and length resolve by table order, so every
// rule that knows a format must come before the rules that read a key name.
func TestRules_KeyNameRulesComeLast(t *testing.T) {
	seenKeyNameRule := false
	for _, rule := range Rules {
		if rule.Category != CategorySecrets {
			continue
		}
		if isKeyNameRule(rule.ID) {
			seenKeyNameRule = true
		} else if seenKeyNameRule {
			t.Errorf("secrets rule %q comes after a key-name rule; move it before them so a format rule wins a tie", rule.ID)
		}
	}
	if !seenKeyNameRule {
		t.Fatal("no key-name rule is compiled; restore key_name_secret, url_query_secret and cookie_header")
	}
}

// TestRedactJSON_KeyRedactionIsObserved pins what an observer sees for a value
// replaced because of its key: one child RedactText record, linked to the
// RedactJSON call, that names the rule, its category and its index in Rules.
func TestRedactJSON_KeyRedactionIsObserved(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).ObservedJSONKeys {
		t.Run(row.ID, func(t *testing.T) {
			var records []Observation
			run, err := NewRun(mustNewRedactor(t, Standard, nil), "run", func(record Observation) error {
				records = append(records, record)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, status := run.RedactJSON("call", decodeJSONFixture(t, row.ID, row.JSON)); status != DeliveryOK {
				t.Fatalf("RedactJSON delivery status = %v, want DeliveryOK", status)
			}
			var parent uint64
			for _, record := range records {
				if record.Operation == OperationRedactJSON {
					parent = record.CallID
				}
			}
			if parent == 0 {
				t.Fatalf("no RedactJSON record was delivered (records: %+v)", records)
			}
			want := RuleDetection{Rule: RuleIdentity{ID: row.Rule, Origin: RuleOriginBuiltin, Index: slices.IndexFunc(Rules, func(rule Rule) bool { return rule.ID == row.Rule })}, Category: row.Category, Count: 1}
			seen := 0
			for _, record := range records {
				for _, detection := range record.Rules {
					if detection.Count == 0 {
						continue
					}
					seen++
					if detection != want {
						t.Errorf("detection = %+v, want %+v", detection, want)
					}
					if record.Operation != OperationRedactText || record.ParentCallID != parent || record.CorrelationID != "call" || record.RegexDetected.Value != 1 {
						t.Errorf("key redaction record = %+v, want a RedactText child of call %d with one detection", record, parent)
					}
				}
			}
			if seen != 1 {
				t.Errorf("observer saw %d detections, want exactly 1 of %s (records: %+v)", seen, row.Rule, records)
			}
		})
	}
}

// TestRedactText_ObservedDetectionsFollowOverlaps pins that an observer is told
// of the matches that remain after a key-name match and the matches around it
// are settled, not of one that detection dropped.
func TestRedactText_ObservedDetectionsFollowOverlaps(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).ObservedText {
		t.Run(row.ID, func(t *testing.T) {
			got := make(map[string]int)
			detected := 0
			run, err := NewRun(mustNewRedactor(t, Standard, nil), "run", func(record Observation) error {
				for _, detection := range record.Rules {
					if detection.Count > 0 {
						got[detection.Rule.ID] += detection.Count
					}
				}
				detected += record.RegexDetected.Value
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, status := run.RedactText("call", row.Input); status != DeliveryOK {
				t.Fatalf("RedactText delivery status = %v, want DeliveryOK", status)
			}
			total := 0
			for _, count := range row.Detections {
				total += count
			}
			if !reflect.DeepEqual(got, row.Detections) || detected != total {
				t.Errorf("observed detections = %v (total %d), want exactly %v", got, detected, row.Detections)
			}
		})
	}
}

// TestRedactJSON_KeyRuleMustBeActive pins that RedactJSON replaces a value
// because of its key only while the rule that does so is active at the
// configured level. No built-in level switches these rules off, so the test
// raises the rule's minimum level in a copy of the rule table.
func TestRedactJSON_KeyRuleMustBeActive(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).InactiveJSONKeyRules {
		t.Run(row.ID, func(t *testing.T) {
			original := Rules
			Rules = slices.Clone(Rules)
			t.Cleanup(func() { Rules = original })
			index := slices.IndexFunc(Rules, func(rule Rule) bool { return rule.ID == row.Rule })
			if index < 0 {
				t.Fatalf("fixture rule %q is not compiled", row.Rule)
			}
			input := decodeJSONFixture(t, row.ID, row.JSON)
			active := mustNewRedactor(t, Standard, nil)
			if got := active.RedactJSON(input); reflect.DeepEqual(got, input) || active.Report().Counts[row.Rule] != 1 {
				t.Fatalf("RedactJSON(%s) = %#v with the rule active; the fixture must be one the rule redacts", row.JSON, got)
			}
			Rules[index].MinimumLevel = Maximum
			inactive := mustNewRedactor(t, Standard, nil)
			if got := inactive.RedactJSON(input); !reflect.DeepEqual(got, input) {
				t.Errorf("RedactJSON(%s) = %#v with %s inactive, want it unchanged", row.JSON, got, row.Rule)
			}
			if count := inactive.Report().Counts[row.Rule]; count != 0 {
				t.Errorf("Report() counts %d redactions of the inactive rule %s", count, row.Rule)
			}
		})
	}
}

// TestRedactJSON_KeyListsAreClosed pins the exact membership of the two lists
// RedactJSON reads an object key by.
func TestRedactJSON_KeyListsAreClosed(t *testing.T) {
	sets := loadRedactorBehaviorFixtures(t).JSONKeySets
	for _, list := range []struct {
		name      string
		got, want []string
	}{
		{"jwkPrivateMembers", jwkPrivateMembers, sets.JWKPrivateMembers},
		{"headerValueKeys", headerValueKeys, sets.HeaderValueKeys},
	} {
		got, want := slices.Sorted(slices.Values(list.got)), slices.Sorted(slices.Values(list.want))
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want exactly %v, the json_key_sets list of the redactor behavior fixture", list.name, got, want)
		}
	}
}

// TestRedactText_StandardOutputFixtures pins the exact output of RedactText at
// standard for each row, and that a second pass leaves that output as it is.
func TestRedactText_StandardOutputFixtures(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).TextOutputs {
		t.Run(row.ID, func(t *testing.T) {
			redactor := mustNewRedactor(t, Standard, nil)
			got := redactor.RedactText(row.Input)
			if got != row.Want {
				t.Errorf("RedactText(%q) = %q, want %q: %s", row.Input, got, row.Want, row.Why)
			}
			if again := redactor.RedactText(got); again != got {
				t.Errorf("second RedactText pass over %q = %q; redaction must be idempotent", got, again)
			}
		})
	}
}

// TestRules_ValueRuleReplacementIsPlaceholder pins that the Replacement of a
// rule that replaces a value is the placeholder Redact writes, with no group
// reference, so a reader of the rule table shows what the output holds; and
// that the recovery path still keeps the name in front of the value.
func TestRules_ValueRuleReplacementIsPlaceholder(t *testing.T) {
	for _, row := range loadRedactorBehaviorFixtures(t).ValueRuleReplacements {
		t.Run(row.ID, func(t *testing.T) {
			rule := findRuleByID(row.ID)
			if rule == nil {
				t.Fatalf("fixture rule %q is not compiled", row.ID)
			}
			if rule.Replacement != row.Placeholder {
				t.Errorf("Replacement = %q, want the placeholder %q", rule.Replacement, row.Placeholder)
			}
			if value, ok := valueRules[rule.Pattern]; !ok || value.placeholder != row.Placeholder {
				t.Errorf("value rule entry = %+v (present %v), want placeholder %q", value, ok, row.Placeholder)
			}
			if got := applyRule(*rule, row.RecoveryInput); got != row.RecoveryOutput {
				t.Errorf("recovery applyRule(%q) = %q, want %q: %s", row.RecoveryInput, got, row.RecoveryOutput, row.Why)
			}
		})
	}
}

// Sizes and tolerance of TestRedactText_LinearTimeFixtures. The larger input
// is linearTimeFactor times the smaller one, so time that follows the length
// grows by that factor and time that follows its square grows by its square.
// The test allows twice the linear growth: a ratio above
// linearTimeMaxRatio fails, which is still half of what quadratic time gives.
const (
	linearTimeSmallBytes = 16 << 10
	linearTimeFactor     = 4
	linearTimeMaxRatio   = 2 * linearTimeFactor
	linearTimeRuns       = 3
)

// TestRedactText_LinearTimeFixtures pins that the time RedactText takes on a
// long run of settings with no space between them grows with the length of
// the run and not with its square. It compares two sizes of the same input
// instead of a time budget, so a slow machine does not fail it. Each size is
// timed linearTimeRuns times and the fastest run counts, which keeps a pause
// of the machine out of the ratio.
func TestRedactText_LinearTimeFixtures(t *testing.T) {
	if testing.Short() {
		t.Skip("times RedactText on inputs of up to 64 KiB")
	}
	redactor := mustNewRedactor(t, Standard, nil)
	fastest := func(input string) time.Duration {
		best := time.Duration(math.MaxInt64)
		for range linearTimeRuns {
			start := time.Now()
			redactor.RedactText(input)
			best = min(best, time.Since(start))
		}
		return max(best, time.Microsecond)
	}
	for _, row := range loadRedactorBehaviorFixtures(t).LinearTime {
		t.Run(row.ID, func(t *testing.T) {
			copies := linearTimeSmallBytes / len(row.Unit)
			small := fastest(strings.Repeat(row.Unit, copies))
			large := fastest(strings.Repeat(row.Unit, copies*linearTimeFactor))
			if ratio := float64(large) / float64(small); ratio > linearTimeMaxRatio {
				t.Errorf("RedactText took %v on %d copies of %q and %v on %d times as many: a ratio of %.1f, more than %d; the time must follow the length of the input (%s)", small, copies, row.Unit, large, linearTimeFactor, ratio, linearTimeMaxRatio, row.Why)
			}
		})
	}
}
