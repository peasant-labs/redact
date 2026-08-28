package redact

import (
	_ "embed"
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
