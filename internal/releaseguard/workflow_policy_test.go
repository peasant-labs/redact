package releaseguard

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/workflow_policy.yaml
var workflowPolicyYAML []byte

type workflowPolicyFixture struct {
	Name     string `yaml:"name"`
	Kind     string `yaml:"kind"`
	File     string `yaml:"file"`
	Job      string `yaml:"job"`
	Step     string `yaml:"step"`
	Contains string `yaml:"contains"`
	Workflow string `yaml:"workflow"`
	Want     bool   `yaml:"want"`
}

const (
	workflowPolicyFixtureCount        = 13
	workflowPolicyLiteralFixtureCount = 6
	workflowPolicyGateFixtureCount    = 7
	workflowPolicyFileGateCount       = 4

	workflowPolicyLiteralKind = "literal"
	workflowPolicyGateKind    = "release_check"
)

var expectedWorkflowPolicyFixtureNames = map[string]struct{}{
	"release_pr_exact_merge_checkout": {},
	"release_pr_gate":                 {},
	"release_pr_tag_gate":             {},
	"release_tag_exact_checkout":      {},
	"release_tag_gate":                {},
	"final_rc_ancestry":               {},
	"final_rc_green_evidence":         {},
	"normal_pr_quality_gate":          {},
	"tag_commit_identity":             {},
	"tag_ref_identity":                {},
	"echo_only_release_check":         {},
	"comment_only_release_check":      {},
	"missing_release_check":           {},
}

var requiredWorkflowGateFiles = map[string]struct{}{
	".github/workflows/release-pr.yml": {},
	".github/workflows/release.yml":    {},
	".github/workflows/tests.yml":      {},
}

type workflowDocument struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string `yaml:"name"`
	Run  string `yaml:"run"`
}

type workflowRun struct {
	Job  string
	Step string
	Body string
}

func TestWorkflowPolicyFixtures(t *testing.T) {
	var fixtures []workflowPolicyFixture
	if err := yaml.Unmarshal(workflowPolicyYAML, &fixtures); err != nil {
		t.Fatalf("parse testdata/workflow_policy.yaml: %v; fix the YAML syntax", err)
	}
	if err := validateWorkflowPolicyFixtures(fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			contents := workflowPolicyFixtureContents(t, fixture)
			switch fixture.Kind {
			case workflowPolicyLiteralKind:
				if !strings.Contains(string(contents), fixture.Contains) {
					t.Errorf("%s lacks required release policy %q", fixture.File, fixture.Contains)
				}
			case workflowPolicyGateKind:
				runs, err := parseWorkflowRuns(contents)
				if err != nil {
					t.Fatal(err)
				}
				matches := workflowRunsForStep(runs, fixture.Job, fixture.Step)
				got := len(matches) == 1 && hasExecutableReleaseCheck(matches)
				if got != fixture.Want {
					t.Errorf("job %q step %q executable release-check = %v, want %v", fixture.Job, fixture.Step, got, fixture.Want)
				}
			default:
				t.Fatalf("unsupported workflow policy fixture kind %q", fixture.Kind)
			}
		})
	}
}

func TestWorkflowPolicyRejectsEchoMutation(t *testing.T) {
	var fixtures []workflowPolicyFixture
	if err := yaml.Unmarshal(workflowPolicyYAML, &fixtures); err != nil {
		t.Fatalf("parse testdata/workflow_policy.yaml: %v; fix the YAML syntax", err)
	}
	if err := validateWorkflowPolicyFixtures(fixtures); err != nil {
		t.Fatal(err)
	}

	workflowFiles := make(map[string]struct{})
	for _, fixture := range fixtures {
		if fixture.Kind == workflowPolicyGateKind && fixture.Want && fixture.File != "" {
			workflowFiles[fixture.File] = struct{}{}
		}
	}
	if len(workflowFiles) != len(requiredWorkflowGateFiles) {
		t.Fatalf("release-check mutation coverage has %d workflow files, want %d", len(workflowFiles), len(requiredWorkflowGateFiles))
	}

	files := make([]string, 0, len(workflowFiles))
	for file := range workflowFiles {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		contents, err := os.ReadFile(filepath.Join("..", "..", file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		beforeRuns, err := parseWorkflowRuns(contents)
		if err != nil {
			t.Fatalf("parse %s before mutation: %v", file, err)
		}
		if !hasExecutableReleaseCheck(beforeRuns) {
			t.Fatalf("%s has no executable release-check command before mutation", file)
		}
		replacements := bytes.Count(contents, []byte("make release-check"))
		if replacements == 0 {
			t.Fatalf("%s has no release-check command text to mutate", file)
		}

		mutated := bytes.ReplaceAll(contents, []byte("make release-check"), []byte("echo make release-check"))
		afterRuns, err := parseWorkflowRuns(mutated)
		if err != nil {
			t.Fatalf("parse %s after inert mutation: %v", file, err)
		}
		if hasExecutableReleaseCheck(afterRuns) {
			t.Errorf("%s still passes after mutating %d release-check command(s) to echo", file, replacements)
		} else {
			t.Logf("%s: mutated %d release-check command(s); structural gate rejected inert echo invocation", file, replacements)
		}
	}
}

func validateWorkflowPolicyFixtures(fixtures []workflowPolicyFixture) error {
	if len(fixtures) != workflowPolicyFixtureCount {
		return fmt.Errorf("workflow policy fixture count = %d, want %d; restore the missing or extra row", len(fixtures), workflowPolicyFixtureCount)
	}
	if len(expectedWorkflowPolicyFixtureNames) != workflowPolicyFixtureCount {
		return fmt.Errorf("workflow policy identity guard has %d names, want %d; update the guard deliberately", len(expectedWorkflowPolicyFixtureNames), workflowPolicyFixtureCount)
	}

	seen := make(map[string]struct{}, len(fixtures))
	literalCount := 0
	gateCount := 0
	fileGateCount := 0
	fileGateCounts := make(map[string]int)
	for _, fixture := range fixtures {
		if strings.TrimSpace(fixture.Name) == "" {
			return fmt.Errorf("workflow policy fixture has an empty identity; give every row a stable descriptive name")
		}
		if _, exists := seen[fixture.Name]; exists {
			return fmt.Errorf("workflow policy fixture identity %q is duplicated; rename one row", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
		if _, expected := expectedWorkflowPolicyFixtureNames[fixture.Name]; !expected {
			return fmt.Errorf("workflow policy fixture identity %q is not in the identity guard; update the guard deliberately", fixture.Name)
		}

		switch fixture.Kind {
		case workflowPolicyLiteralKind:
			literalCount++
			if fixture.File == "" || fixture.Contains == "" || fixture.Workflow != "" || fixture.Job != "" || fixture.Step != "" {
				return fmt.Errorf("literal workflow policy fixture %q must specify only file and contains", fixture.Name)
			}
		case workflowPolicyGateKind:
			gateCount++
			if fixture.Job == "" || fixture.Step == "" {
				return fmt.Errorf("release-check workflow policy fixture %q must specify a job and step", fixture.Name)
			}
			if fixture.Want {
				if fixture.File == "" || fixture.Workflow != "" {
					return fmt.Errorf("positive release-check workflow policy fixture %q must specify a workflow file", fixture.Name)
				}
				fileGateCount++
				fileGateCounts[fixture.File]++
			} else if fixture.File != "" || fixture.Workflow == "" {
				return fmt.Errorf("negative release-check workflow policy fixture %q must specify an inline workflow", fixture.Name)
			}
		default:
			return fmt.Errorf("workflow policy fixture %q has unsupported kind %q", fixture.Name, fixture.Kind)
		}
	}
	for name := range expectedWorkflowPolicyFixtureNames {
		if _, exists := seen[name]; !exists {
			return fmt.Errorf("workflow policy identity %q is missing; restore the fixture row", name)
		}
	}
	if literalCount != workflowPolicyLiteralFixtureCount {
		return fmt.Errorf("workflow policy literal fixture count = %d, want %d; restore the changed rows", literalCount, workflowPolicyLiteralFixtureCount)
	}
	if gateCount != workflowPolicyGateFixtureCount {
		return fmt.Errorf("workflow policy release-check fixture count = %d, want %d; restore the changed rows", gateCount, workflowPolicyGateFixtureCount)
	}
	if fileGateCount != workflowPolicyFileGateCount {
		return fmt.Errorf("workflow policy file gate count = %d, want %d; restore the changed rows", fileGateCount, workflowPolicyFileGateCount)
	}
	for file := range requiredWorkflowGateFiles {
		if fileGateCounts[file] == 0 {
			return fmt.Errorf("workflow policy fixtures do not cover required gate workflow %q", file)
		}
	}
	return nil
}

func workflowPolicyFixtureContents(t *testing.T, fixture workflowPolicyFixture) []byte {
	t.Helper()
	if fixture.File != "" {
		contents, err := os.ReadFile(filepath.Join("..", "..", fixture.File))
		if err != nil {
			t.Fatalf("read %s: %v", fixture.File, err)
		}
		return contents
	}
	return []byte(fixture.Workflow)
}

func parseWorkflowRuns(contents []byte) ([]workflowRun, error) {
	var document workflowDocument
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return nil, fmt.Errorf("parse GitHub Actions workflow YAML: %w", err)
	}
	if len(document.Jobs) == 0 {
		return nil, fmt.Errorf("parse GitHub Actions workflow YAML: no jobs found")
	}

	runs := make([]workflowRun, 0)
	for jobName, job := range document.Jobs {
		for _, step := range job.Steps {
			if strings.TrimSpace(step.Run) == "" {
				continue
			}
			runs = append(runs, workflowRun{Job: jobName, Step: step.Name, Body: step.Run})
		}
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].Job != runs[j].Job {
			return runs[i].Job < runs[j].Job
		}
		return runs[i].Step < runs[j].Step
	})
	return runs, nil
}

func workflowRunsForStep(runs []workflowRun, job, step string) []workflowRun {
	matches := make([]workflowRun, 0, 1)
	for _, run := range runs {
		if run.Job == job && run.Step == step {
			matches = append(matches, run)
		}
	}
	return matches
}

func hasExecutableReleaseCheck(runs []workflowRun) bool {
	for _, run := range runs {
		for _, line := range strings.Split(run.Body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "make" && fields[1] == "release-check" {
				return true
			}
		}
	}
	return false
}
