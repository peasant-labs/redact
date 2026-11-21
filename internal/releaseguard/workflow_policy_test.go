package releaseguard

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/workflow_policy.yaml
var workflowPolicyYAML []byte

type workflowPolicyFixture struct {
	Name      string `yaml:"name"`
	Kind      string `yaml:"kind"`
	File      string `yaml:"file"`
	Job       string `yaml:"job"`
	Step      string `yaml:"step"`
	Contains  string `yaml:"contains"`
	Path      string `yaml:"path"`
	Value     string `yaml:"value"`
	Workflow  string `yaml:"workflow"`
	FetchTags bool   `yaml:"fetch_tags"`
	Want      bool   `yaml:"want"`
}

const (
	workflowPolicyLiteralKind         = "literal"
	workflowPolicyGateKind            = "release_check"
	workflowPolicyValueKind           = "workflow_value"
	workflowPolicyHistoryCheckoutKind = "history_checkout"
)

var expectedWorkflowPolicyFixtureNames = map[string]struct{}{
	"release_tag_exact_checkout":             {},
	"release_tag_gate":                       {},
	"normal_pr_quality_gate":                 {},
	"tag_commit_identity":                    {},
	"tag_ref_identity":                       {},
	"echo_only_release_check":                {},
	"comment_only_release_check":             {},
	"missing_release_check":                  {},
	"release_guard_history_checkout":         {},
	"release_verify_history_checkout":        {},
	"tests_changes_history_checkout":         {},
	"title_guard_history_checkout":           {},
	"release_batch_plan_history_checkout":    {},
	"release_batch_verify_history_checkout":  {},
	"release_batch_release_history_checkout": {},
	"cut_release_prepare_history_checkout":   {},
	"cut_release_cut_history_checkout":       {},
	"shallow_history_checkout":               {},
	"misplaced_history_checkout":             {},
	"missing_tags_history_checkout":          {},
	"wrong_repository_history_checkout":      {},
	"wrong_path_history_checkout":            {},
}

var requiredWorkflowGateFiles = map[string]struct{}{
	".github/workflows/release.yml": {},
	".github/workflows/tests.yml":   {},
}

type workflowDocument struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Run  string            `yaml:"run"`
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
			case workflowPolicyValueKind:
				got, err := workflowValueAtPath(contents, fixture.Path)
				if err != nil {
					t.Fatal(err)
				}
				if !workflowValueMatches(got, fixture.Value) {
					t.Errorf("%s path %q = %q, want %q (whitespace-normalized)", fixture.File, fixture.Path, workflowValueString(got), fixture.Value)
				}
			case workflowPolicyHistoryCheckoutKind:
				got, err := hasStepScopedHistoryCheckout(contents, fixture.Job, fixture.Step, fixture.FetchTags)
				if err != nil {
					t.Fatal(err)
				}
				if got != fixture.Want {
					t.Errorf("job %q step %q history checkout = %v, want %v", fixture.Job, fixture.Step, got, fixture.Want)
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
	seen := make(map[string]struct{}, len(fixtures))
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
			if fixture.File == "" || fixture.Contains == "" || fixture.Workflow != "" || fixture.Job != "" || fixture.Step != "" {
				return fmt.Errorf("literal workflow policy fixture %q must specify only file and contains", fixture.Name)
			}
		case workflowPolicyGateKind:
			if fixture.Job == "" || fixture.Step == "" {
				return fmt.Errorf("release-check workflow policy fixture %q must specify a job and step", fixture.Name)
			}
			if fixture.Want {
				if fixture.File == "" || fixture.Workflow != "" {
					return fmt.Errorf("positive release-check workflow policy fixture %q must specify a workflow file", fixture.Name)
				}
				fileGateCounts[fixture.File]++
			} else if fixture.File != "" || fixture.Workflow == "" {
				return fmt.Errorf("negative release-check workflow policy fixture %q must specify an inline workflow", fixture.Name)
			}
		case workflowPolicyValueKind:
			if fixture.File == "" || fixture.Path == "" || fixture.Value == "" || fixture.Workflow != "" || fixture.Job != "" || fixture.Step != "" || fixture.Contains != "" {
				return fmt.Errorf("workflow-value fixture %q must specify only file, path, and value", fixture.Name)
			}
		case workflowPolicyHistoryCheckoutKind:
			if fixture.Job == "" || fixture.Step == "" {
				return fmt.Errorf("history-checkout workflow policy fixture %q must specify a job and step", fixture.Name)
			}
			if fixture.Want {
				if fixture.File == "" || fixture.Workflow != "" {
					return fmt.Errorf("positive history-checkout workflow policy fixture %q must specify a workflow file", fixture.Name)
				}
			} else if fixture.File != "" || fixture.Workflow == "" {
				return fmt.Errorf("negative history-checkout workflow policy fixture %q must specify an inline workflow", fixture.Name)
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

// workflowValueAtPath resolves a dotted path (e.g. "concurrency.group") against
// a GitHub Actions workflow document. It walks yaml.Node mappings so that keys
// like `on` keep their literal spelling instead of being coerced. A scalar
// resolves to its string; a sequence resolves to its scalar items, so a fixture
// can assert membership (e.g. "edited" in on.pull_request.types).
func workflowValueAtPath(contents []byte, path string) (any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(contents, &root); err != nil {
		return nil, fmt.Errorf("parse GitHub Actions workflow YAML: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("parse GitHub Actions workflow YAML: empty document")
	}
	node := root.Content[0]
	for _, segment := range strings.Split(path, ".") {
		if node.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("workflow path %q: %q is not a mapping", path, segment)
		}
		found := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == segment {
				node = node.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("workflow path %q: no key %q", path, segment)
		}
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value, nil
	case yaml.SequenceNode:
		values := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("workflow path %q: non-scalar sequence item", path)
			}
			values = append(values, item.Value)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("workflow path %q: unsupported node kind", path)
	}
}

func normalizeWorkflowValue(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// workflowValueMatches compares whitespace-normalized values: exact equality
// for a scalar, membership for a sequence.
func workflowValueMatches(got any, want string) bool {
	want = normalizeWorkflowValue(want)
	switch v := got.(type) {
	case string:
		return normalizeWorkflowValue(v) == want
	case []string:
		for _, item := range v {
			if normalizeWorkflowValue(item) == want {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func workflowValueString(got any) string {
	switch v := got.(type) {
	case string:
		return v
	case []string:
		return "[" + strings.Join(v, ", ") + "]"
	default:
		return fmt.Sprintf("%v", got)
	}
}

func hasStepScopedHistoryCheckout(contents []byte, jobName, stepName string, requireTags bool) (bool, error) {
	var document workflowDocument
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return false, fmt.Errorf("parse GitHub Actions workflow YAML: %w", err)
	}
	if len(document.Jobs) == 0 {
		return false, fmt.Errorf("parse GitHub Actions workflow YAML: no jobs found")
	}
	job, ok := document.Jobs[jobName]
	if !ok {
		return false, nil
	}
	var matches []workflowStep
	for _, step := range job.Steps {
		if step.Name == stepName {
			matches = append(matches, step)
		}
	}
	if len(matches) != 1 {
		return false, nil
	}
	step := matches[0]
	if !strings.HasPrefix(step.Uses, "actions/checkout@") {
		return false, nil
	}
	if step.With["fetch-depth"] != "0" {
		return false, nil
	}
	if requireTags && step.With["fetch-tags"] != "true" {
		return false, nil
	}
	if strings.TrimSpace(step.With["repository"]) != "" {
		return false, nil
	}
	if strings.TrimSpace(step.With["path"]) != "" {
		return false, nil
	}
	return true, nil
}

//go:embed testdata/private-install.yaml
var privateInstallFixture []byte

type privateWorkflow struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}
type privateInstallConfig struct {
	Prefix   string `yaml:"prefix_pattern"`
	Install  string `yaml:"install_pattern"`
	Path     string `yaml:"path_pattern"`
	Workflow string `yaml:"workflow"`
	Job      string `yaml:"job"`
	Step     string `yaml:"step"`
}

// The runner tool cache is shared; verify the pinned job-private ast-grep install step.
func TestWorkflowPrivateNpmInstall(t *testing.T) {
	checkPrivateNpmInstall(t, privateInstallFixture)
	checkPrivateNpmInstall(t, privateInstallReleaseFixture)
}

//go:embed testdata/private-install-release.yaml
var privateInstallReleaseFixture []byte

func checkPrivateNpmInstall(t *testing.T, dataFixture []byte) {
	var f privateInstallConfig
	if err := yaml.Unmarshal(dataFixture, &f); err != nil {
		t.Fatal(err)
	}
	continuation := regexp.MustCompile(`\\\n\s*`)
	normalize := func(s string) string { return continuation.ReplaceAllString(s, " ") }
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", f.Workflow))
	if err != nil {
		t.Fatal(err)
	}
	var doc privateWorkflow
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var target []string
	if value, ok := doc.Jobs[f.Job]; ok {
		for _, step := range value.Steps {
			if step.Name == f.Step {
				target = append(target, normalize(step.Run))
			}
		}
	}
	if len(target) != 1 {
		t.Fatalf("%s job %s: found %d install steps, want 1", f.Workflow, f.Job, len(target))
	}
	for _, pattern := range []string{f.Prefix, f.Install, f.Path} {
		if !regexp.MustCompile(pattern).MatchString(target[0]) {
			t.Errorf("%s job %s step %s lacks private install invariant %q", f.Workflow, f.Job, f.Step, pattern)
		}
	}
}
