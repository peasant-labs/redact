package redact

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

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

// TestRedactJSON_KeyRedactionIsObserved pins that a value replaced because of
// its key reaches the observer: one child record that names the rule.
func TestRedactJSON_KeyRedactionIsObserved(t *testing.T) {
	var records []Observation
	run, err := NewRun(mustNewRedactor(t, Standard, nil), "run", func(record Observation) error {
		records = append(records, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, status := run.RedactJSON("call", decodeJSONFixture(t, "observed key redaction", `{"db_password": "canaryJsonPw0rd!2026"}`)); status != DeliveryOK {
		t.Fatalf("RedactJSON delivery status = %v, want DeliveryOK", status)
	}
	var seen int
	for _, record := range records {
		for _, detection := range record.Rules {
			if detection.Rule.ID == keyNameSecretRuleID {
				seen += detection.Count
				if record.Operation != OperationRedactText || record.ParentCallID == 0 || record.RegexDetected.Value != 1 {
					t.Errorf("key redaction record = %+v, want a child RedactText record with one detection", record)
				}
			}
		}
	}
	if seen != 1 {
		t.Errorf("observer saw %d detections of %s, want 1 (records: %+v)", seen, keyNameSecretRuleID, records)
	}
}
