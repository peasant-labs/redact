package releaseguard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/verdict_inheritance.yaml
var verdictInheritanceYAML []byte

type verdictInheritanceFixture struct {
	VerdictMarkers struct {
		Version int      `yaml:"version"`
		Names   []string `yaml:"names"`
	} `yaml:"verdict_markers"`
	PolicyFile    string `yaml:"policy_file"`
	WorkflowFile  string `yaml:"workflow_file"`
	AggregatorJob string `yaml:"aggregator_job"`
	FullSuiteJob  string `yaml:"full_suite_job"`
	MergeGateStep string `yaml:"merge_gate_step"`
	MarkerSteps   []struct {
		Name string `yaml:"name"`
		If   string `yaml:"if"`
	} `yaml:"marker_steps"`
	HeavyJobs []struct {
		Job string `yaml:"job"`
		If  string `yaml:"if"`
	} `yaml:"heavy_jobs"`
	ClassifierJob         string            `yaml:"classifier_job"`
	InheritStep           string            `yaml:"inherit_step"`
	ClassifyStep          string            `yaml:"classify_step"`
	PrecheckStep          string            `yaml:"precheck_step"`
	ReleaseConfig         string            `yaml:"release_config"`
	ToolIf                string            `yaml:"tool_if"`
	ToolSteps             []string          `yaml:"tool_steps"`
	ClassifierPermissions map[string]string `yaml:"classifier_permissions"`
	PrecheckCases         []precheckCase    `yaml:"precheck_cases"`
	MergeGateCases        []mergeGateCase   `yaml:"merge_gate_cases"`
}

type precheckCase struct {
	Name          string `yaml:"name"`
	Event         string `yaml:"event"`
	GroupRef      string `yaml:"group_ref"`
	PRAuthorType  string `yaml:"pr_author_type"`
	PRHeadRef     string `yaml:"pr_head_ref"`
	GHHead        string `yaml:"gh_head"`
	GHExit        int    `yaml:"gh_exit"`
	ExpectedGH    string `yaml:"expected_gh"`
	ExpectedBuild string `yaml:"expected_build"`
	ExpectedExit  int    `yaml:"expected_exit"`
}

// requiredPrecheckCases is the deletion guard for precheck_cases.
var requiredPrecheckCases = map[string]struct{}{
	"human-pr-skips-build":                     {},
	"human-pr-on-release-branch-skips-build":   {},
	"dependabot-pr-skips-build":                {},
	"cut-release-bot-pr-skips-build":           {},
	"release-bot-pr-builds":                    {},
	"normal-merge-group-skips-build":           {},
	"release-merge-group-builds":               {},
	"unreadable-queue-ref-builds-for-classify": {},
	"failed-head-lookup-fails-the-step":        {},
	"push-skips-build":                         {},
}

type mergeGateCase struct {
	Name             string  `yaml:"name"`
	Event            string  `yaml:"event"`
	ReleaseCandidate *string `yaml:"release_candidate"`
	ReleaseOnly      *string `yaml:"release_only"`
	Inherit          *string `yaml:"inherit"`
	ResultsJSON      string  `yaml:"results_json"`
	ExpectedExit     int     `yaml:"expected_exit"`
	ExpectedError    string  `yaml:"expected_error"`
	ExpectedMarker   string  `yaml:"expected_marker"`
}

// requiredMergeGateCases is the deletion guard for merge_gate_cases: every
// accepted state and every refusal the gate must keep.
var requiredMergeGateCases = map[string]struct{}{
	"full-gate-passes":                                  {},
	"push-full-gate-passes":                             {},
	"test-failure-is-refused":                           {},
	"lint-failure-is-refused":                           {},
	"cancelled-test-is-refused":                         {},
	"runner-failure-is-refused":                         {},
	"failed-classifier-is-refused":                      {},
	"skipped-classifier-is-refused":                     {},
	"skipped-test-without-inheritance-is-refused":       {},
	"skipped-lint-without-inheritance-is-refused":       {},
	"missing-candidate-is-refused":                      {},
	"unknown-release-only-is-refused":                   {},
	"unknown-inherit-is-refused":                        {},
	"release-candidate-not-release-only-runs-full-gate": {},
	"release-candidate-without-inheritance-needs-test":  {},
	"inherited-merge-group-release-passes":              {},
	"inherited-pull-request-release-passes":             {},
	"inherited-test-ran-is-refused":                     {},
	"inherited-lint-ran-is-refused":                     {},
	"inherited-without-release-only-is-refused":         {},
	"inherited-without-candidate-is-refused":            {},
	"inherited-on-push-is-refused":                      {},
}

// requiredHeavyJobs names every job an inherited verdict replaces.
var requiredHeavyJobs = map[string]struct{}{
	"determine-runner": {},
	"test":             {},
	"lint":             {},
}

func loadVerdictInheritanceFixture(t *testing.T) verdictInheritanceFixture {
	t.Helper()
	var fixture verdictInheritanceFixture
	decoder := yaml.NewDecoder(bytes.NewReader(verdictInheritanceYAML))
	decoder.KnownFields(true)
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("parse the embedded verdict inheritance fixture: %v; fix the fixture", err)
	}
	if fixture.VerdictMarkers.Version != 1 || len(fixture.VerdictMarkers.Names) == 0 {
		t.Fatalf("the fixture mirrors marker set version %d with %d names; infra's pinned set is version 1", fixture.VerdictMarkers.Version, len(fixture.VerdictMarkers.Names))
	}
	return fixture
}

func readWorkflowJobs(t *testing.T, file string) *yaml.Node {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		t.Fatalf("parse %s: %v", file, err)
	}
	jobs := provenanceMappingChild(doc.Content[0], "jobs")
	if jobs == nil {
		t.Fatalf("%s has no jobs", file)
	}
	return jobs
}

func nodeScalar(node *yaml.Node, key string) string {
	if child := provenanceMappingChild(node, key); child != nil {
		return child.Value
	}
	return ""
}

// TestMergeGateVerdict runs the actual merge-gate shell step with fixture
// needs results, and checks that on every passing state exactly one marker
// step's condition, read from the workflow, holds.
func TestMergeGateVerdict(t *testing.T) {
	fixture := loadVerdictInheritanceFixture(t)
	jobs := readWorkflowJobs(t, fixture.WorkflowFile)
	steps := provenanceMappingChild(provenanceMappingChild(jobs, fixture.AggregatorJob), "steps")
	if steps == nil {
		t.Fatalf("jobs.%s has no steps", fixture.AggregatorJob)
	}
	var script string
	markerIfs := make(map[string]string)
	for _, step := range steps.Content {
		name := nodeScalar(step, "name")
		if name == fixture.MergeGateStep {
			script = nodeScalar(step, "run")
		}
		if slices.Contains(fixture.VerdictMarkers.Names, name) {
			markerIfs[name] = nodeScalar(step, "if")
		}
	}
	if script == "" {
		t.Fatalf("jobs.%s has no step %q with a run script", fixture.AggregatorJob, fixture.MergeGateStep)
	}
	if len(markerIfs) != len(fixture.VerdictMarkers.Names) {
		t.Fatalf("jobs.%s carries %d of the %d marker steps", fixture.AggregatorJob, len(markerIfs), len(fixture.VerdictMarkers.Names))
	}

	seen := make(map[string]struct{}, len(fixture.MergeGateCases))
	for _, c := range fixture.MergeGateCases {
		if c.Name == "" {
			t.Fatal("a merge-gate case has no name; give every row a stable name")
		}
		if _, dup := seen[c.Name]; dup {
			t.Fatalf("merge-gate case %q is duplicated; rename one row", c.Name)
		}
		seen[c.Name] = struct{}{}
		if _, required := requiredMergeGateCases[c.Name]; !required {
			t.Fatalf("merge-gate case %q is not in requiredMergeGateCases; add it to the guard deliberately", c.Name)
		}
		t.Run(c.Name, func(t *testing.T) {
			candidate := caseValue(c.ReleaseCandidate)
			releaseOnly := caseValue(c.ReleaseOnly)
			inherit := caseValue(c.Inherit)
			event := c.Event
			if event == "" {
				event = "merge_group"
			}
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"RESULTS="+c.ResultsJSON,
				"EVENT="+event,
				"RELEASE_CANDIDATE="+candidate,
				"RELEASE_ONLY="+releaseOnly,
				"INHERIT="+inherit,
			)
			out, err := cmd.CombinedOutput()
			exit := 0
			if err != nil {
				var failure *exec.ExitError
				if !errors.As(err, &failure) {
					t.Fatalf("execute merge-gate: %v\n%s", err, out)
				}
				exit = failure.ExitCode()
			}
			if exit != c.ExpectedExit {
				t.Fatalf("merge-gate exit = %d, want %d:\n%s", exit, c.ExpectedExit, out)
			}
			if c.ExpectedExit != 0 {
				if c.ExpectedError == "" || c.ExpectedMarker != "" {
					t.Fatal("a reject row names its expected_error and no expected_marker")
				}
				if !strings.Contains(string(out), "::error::merge-gate: "+c.ExpectedError) {
					t.Fatalf("merge-gate output lacks the refusal %q:\n%s", c.ExpectedError, out)
				}
				return
			}
			if c.ExpectedMarker == "" {
				t.Fatal("an accepting row names the marker step that must run")
			}
			var results map[string]struct {
				Result string `json:"result"`
			}
			if err := json.Unmarshal([]byte(c.ResultsJSON), &results); err != nil {
				t.Fatalf("parse results_json: %v", err)
			}
			state := map[string]string{"needs.changes.outputs.inherit": inherit}
			for job, r := range results {
				state["needs."+job+".result"] = r.Result
			}
			var running []string
			for _, name := range fixture.VerdictMarkers.Names {
				holds, err := evalMarkerCondition(markerIfs[name], state)
				if err != nil {
					t.Fatalf("marker step %q: %v", name, err)
				}
				if holds {
					running = append(running, name)
				}
			}
			if len(running) != 1 || running[0] != c.ExpectedMarker {
				t.Fatalf("marker steps whose condition holds = %q, want exactly [%q]", running, c.ExpectedMarker)
			}
		})
	}
	for name := range requiredMergeGateCases {
		if _, ok := seen[name]; !ok {
			t.Errorf("required merge-gate case %q is missing; restore the fixture row", name)
		}
	}
}

// classifierStep returns the classifier job's step with the given id.
func classifierStep(t *testing.T, jobs *yaml.Node, job, id string) *yaml.Node {
	t.Helper()
	steps := provenanceMappingChild(provenanceMappingChild(jobs, job), "steps")
	if steps == nil {
		t.Fatalf("jobs.%s has no steps", job)
	}
	for _, step := range steps.Content {
		if nodeScalar(step, "id") == id {
			return step
		}
	}
	t.Fatalf("jobs.%s has no step with id %s", job, id)
	return nil
}

// readStepOutputs parses a GITHUB_OUTPUT file of key=value lines.
func readStepOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read step outputs: %v", err)
	}
	outputs := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			outputs[key] = value
		}
	}
	return outputs
}

// TestChangesPreCheck runs the real pre-check step with a stub gh, and for
// every run it filters out, the real classify and inherit steps after it:
// those must record no candidate and no inheritance without calling
// release-intent or git, so an ordinary run never builds the tool.
func TestChangesPreCheck(t *testing.T) {
	fixture := loadVerdictInheritanceFixture(t)
	jobs := readWorkflowJobs(t, fixture.WorkflowFile)
	precheck := classifierStep(t, jobs, fixture.ClassifierJob, fixture.PrecheckStep)
	classify := classifierStep(t, jobs, fixture.ClassifierJob, fixture.ClassifyStep)
	inherit := classifierStep(t, jobs, fixture.ClassifierJob, fixture.InheritStep)
	releaseBranch := nodeScalar(provenanceMappingChild(precheck, "env"), "RELEASE_BRANCH")
	if releaseBranch == "" {
		t.Fatalf("step %s sets no RELEASE_BRANCH", fixture.PrecheckStep)
	}

	seen := make(map[string]struct{}, len(fixture.PrecheckCases))
	for _, c := range fixture.PrecheckCases {
		if c.Name == "" {
			t.Fatal("a pre-check case has no name; give every row a stable name")
		}
		if _, dup := seen[c.Name]; dup {
			t.Fatalf("pre-check case %q is duplicated; rename one row", c.Name)
		}
		seen[c.Name] = struct{}{}
		if _, required := requiredPrecheckCases[c.Name]; !required {
			t.Fatalf("pre-check case %q is not in requiredPrecheckCases; add it to the guard deliberately", c.Name)
		}
		t.Run(c.Name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			logs := filepath.Join(dir, "logs")
			runnerTemp := filepath.Join(dir, "runner")
			for _, d := range []string{bin, logs, runnerTemp} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stubs := map[string]string{
				filepath.Join(bin, "gh"):                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STUB_LOGS/gh\"\n[ \"$STUB_GH_EXIT\" = 0 ] || exit \"$STUB_GH_EXIT\"\nprintf '%s\\n' \"$STUB_GH_HEAD\"\n",
				filepath.Join(bin, "git"):                   "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STUB_LOGS/git\"\nexit 97\n",
				filepath.Join(runnerTemp, "release-intent"): "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STUB_LOGS/release-intent\"\nexit 97\n",
			}
			for path, body := range stubs {
				if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			event := c.Event
			if event == "" {
				event = "merge_group"
			}
			env := append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"STUB_LOGS="+logs,
				"STUB_GH_HEAD="+c.GHHead,
				"STUB_GH_EXIT="+strconv.Itoa(c.GHExit),
				"RUNNER_TEMP="+runnerTemp,
				"GITHUB_REPOSITORY=peasant-labs/redact",
				"EVENT="+event,
				"GROUP_REF="+c.GroupRef,
				"PR_AUTHOR_TYPE="+c.PRAuthorType,
				"PR_HEAD_REF="+c.PRHeadRef,
				"PR_NUMBER=7",
				"RELEASE_BRANCH="+releaseBranch,
				"BASE=1111111111111111111111111111111111111111",
				"HEAD=2222222222222222222222222222222222222222",
			)
			runStep := func(name, script, output string, extra ...string) (int, string) {
				cmd := exec.Command("bash", "-c", script)
				cmd.Env = append(append(slices.Clone(env), "GITHUB_OUTPUT="+output), extra...)
				out, err := cmd.CombinedOutput()
				if err != nil {
					var failure *exec.ExitError
					if !errors.As(err, &failure) {
						t.Fatalf("execute %s: %v\n%s", name, err, out)
					}
					return failure.ExitCode(), string(out)
				}
				return 0, string(out)
			}

			precheckOut := filepath.Join(dir, "precheck.out")
			exit, out := runStep(fixture.PrecheckStep, nodeScalar(precheck, "run"), precheckOut)
			if exit != c.ExpectedExit {
				t.Fatalf("pre-check exit = %d, want %d:\n%s", exit, c.ExpectedExit, out)
			}
			ghLog, _ := os.ReadFile(filepath.Join(logs, "gh"))
			if got := strings.TrimSpace(string(ghLog)); got != c.ExpectedGH {
				t.Errorf("pre-check gh calls = %q, want %q", got, c.ExpectedGH)
			}
			if c.ExpectedExit != 0 {
				return
			}
			if got := readStepOutputs(t, precheckOut)["build"]; got != c.ExpectedBuild {
				t.Fatalf("pre-check build = %q, want %q:\n%s", got, c.ExpectedBuild, out)
			}
			if c.ExpectedBuild == "true" {
				return
			}

			classifyOut := filepath.Join(dir, "classify.out")
			if exit, out := runStep(fixture.ClassifyStep, nodeScalar(classify, "run"), classifyOut, "BUILD=false"); exit != 0 {
				t.Fatalf("classify step exit = %d:\n%s", exit, out)
			}
			candidate := readStepOutputs(t, classifyOut)["candidate"]
			inheritOut := filepath.Join(dir, "inherit.out")
			if exit, out := runStep(fixture.InheritStep, nodeScalar(inherit, "run"), inheritOut, "CANDIDATE="+candidate); exit != 0 {
				t.Fatalf("inherit step exit = %d:\n%s", exit, out)
			}
			outputs := readStepOutputs(t, inheritOut)
			outputs["candidate"] = candidate
			for _, key := range []string{"candidate", "release_only", "inherit"} {
				if outputs[key] != "false" {
					t.Errorf("a filtered-out run records %s=%q, want \"false\"", key, outputs[key])
				}
			}
			for _, tool := range []string{"release-intent", "git", "gh"} {
				if tool == "gh" && c.ExpectedGH != "" {
					continue
				}
				if _, err := os.Stat(filepath.Join(logs, tool)); err == nil {
					t.Errorf("a filtered-out run called %s", tool)
				}
			}
		})
	}
	for name := range requiredPrecheckCases {
		if _, ok := seen[name]; !ok {
			t.Errorf("required pre-check case %q is missing; restore the fixture row", name)
		}
	}
}

func caseValue(value *string) string {
	if value == nil {
		return "false"
	}
	return *value
}

// evalMarkerCondition evaluates the only expression shape the marker steps
// use: `&&`-joined comparisons of a needs context value with a quoted
// literal. Anything else is an error, so a reshaped condition fails the test
// instead of being misread.
func evalMarkerCondition(condition string, state map[string]string) (bool, error) {
	if strings.TrimSpace(condition) == "" {
		return false, fmt.Errorf("has no if; every marker step needs its own condition")
	}
	holds := true
	for _, clause := range strings.Split(condition, "&&") {
		fields := strings.Fields(clause)
		if len(fields) != 3 || (fields[1] != "==" && fields[1] != "!=") {
			return false, fmt.Errorf("clause %q is not `<needs value> ==|!= '<literal>'`", strings.TrimSpace(clause))
		}
		got, ok := state[fields[0]]
		if !ok {
			return false, fmt.Errorf("clause %q reads %s, which the fixture state does not carry", strings.TrimSpace(clause), fields[0])
		}
		literal := strings.Trim(fields[2], "'")
		if (got == literal) != (fields[1] == "==") {
			holds = false
		}
	}
	return holds, nil
}

// TestVerdictInheritanceWiring pins the tests.yml wiring that inheritance
// relies on: the aggregator's final steps equal infra's marker set with their
// conditions, every job the inherited verdict replaces is skipped exactly
// when it is inherited, the classifier and its proof step always run, and the
// queue policy opts in with the same aggregator and full-suite job.
func TestVerdictInheritanceWiring(t *testing.T) {
	fixture := loadVerdictInheritanceFixture(t)
	jobs := readWorkflowJobs(t, fixture.WorkflowFile)

	names := make([]string, 0, len(fixture.MarkerSteps))
	for _, m := range fixture.MarkerSteps {
		names = append(names, m.Name)
	}
	if !slices.Equal(names, fixture.VerdictMarkers.Names) {
		t.Fatalf("marker_steps %q differ from infra's marker set version %d %q", names, fixture.VerdictMarkers.Version, fixture.VerdictMarkers.Names)
	}
	aggregator := provenanceMappingChild(jobs, fixture.AggregatorJob)
	if aggregator == nil {
		t.Fatalf("jobs.%s is missing", fixture.AggregatorJob)
	}
	if provenanceMappingChild(aggregator, "continue-on-error") != nil {
		t.Errorf("jobs.%s must not continue on error", fixture.AggregatorJob)
	}
	steps := provenanceMappingChild(aggregator, "steps")
	if steps == nil || len(steps.Content) < len(fixture.MarkerSteps) {
		t.Fatalf("jobs.%s has fewer steps than the %d marker steps", fixture.AggregatorJob, len(fixture.MarkerSteps))
	}
	tail := steps.Content[len(steps.Content)-len(fixture.MarkerSteps):]
	for i, m := range fixture.MarkerSteps {
		if got := nodeScalar(tail[i], "name"); got != m.Name {
			t.Errorf("jobs.%s final step %d is %q, want %q", fixture.AggregatorJob, i, got, m.Name)
		}
		if got := nodeScalar(tail[i], "if"); got != m.If {
			t.Errorf("marker step %q if = %q, want %q", m.Name, got, m.If)
		}
	}

	var needs []string
	if node := provenanceMappingChild(aggregator, "needs"); node != nil {
		for _, item := range node.Content {
			needs = append(needs, item.Value)
		}
	}
	if !slices.Contains(needs, fixture.FullSuiteJob) || !slices.Contains(needs, fixture.ClassifierJob) {
		t.Errorf("jobs.%s needs %q; it must need %s and %s", fixture.AggregatorJob, needs, fixture.ClassifierJob, fixture.FullSuiteJob)
	}

	heavy := make(map[string]struct{}, len(fixture.HeavyJobs))
	for _, h := range fixture.HeavyJobs {
		heavy[h.Job] = struct{}{}
		job := provenanceMappingChild(jobs, h.Job)
		if job == nil {
			t.Errorf("jobs.%s is missing", h.Job)
			continue
		}
		if got := nodeScalar(job, "if"); got != h.If {
			t.Errorf("jobs.%s if = %q, want %q", h.Job, got, h.If)
		}
	}
	for name := range requiredHeavyJobs {
		if _, ok := heavy[name]; !ok {
			t.Errorf("heavy job %q is missing from the fixture; restore the row", name)
		}
	}
	if _, ok := heavy[fixture.FullSuiteJob]; !ok {
		t.Errorf("the full-suite job %s is not gated on inheritance", fixture.FullSuiteJob)
	}
	// A job the aggregator needs that the inherited verdict does not replace
	// would rerun on every release candidate, or be skipped without proof.
	for _, need := range needs {
		if _, ok := heavy[need]; !ok && need != fixture.ClassifierJob {
			t.Errorf("jobs.%s needs %s, which is neither the classifier nor a heavy job gated on inheritance", fixture.AggregatorJob, need)
		}
	}

	classifier := provenanceMappingChild(jobs, fixture.ClassifierJob)
	if classifier == nil {
		t.Fatalf("jobs.%s is missing", fixture.ClassifierJob)
	}
	if provenanceMappingChild(classifier, "if") != nil || provenanceMappingChild(classifier, "continue-on-error") != nil {
		t.Errorf("jobs.%s must always run: no if and no continue-on-error", fixture.ClassifierJob)
	}
	permissions := provenanceMappingChild(classifier, "permissions")
	for scope, level := range fixture.ClassifierPermissions {
		if got := nodeScalar(permissions, scope); got != level {
			t.Errorf("jobs.%s permission %s = %q, want %q", fixture.ClassifierJob, scope, got, level)
		}
	}
	toolSteps := make(map[string]bool, len(fixture.ToolSteps))
	for _, name := range fixture.ToolSteps {
		toolSteps[name] = false
	}
	for _, step := range provenanceMappingChild(classifier, "steps").Content {
		name := nodeScalar(step, "name")
		buildsTool := strings.Contains(nodeScalar(step, "run"), "go build") ||
			nodeScalar(provenanceMappingChild(step, "with"), "repository") == "peasant-labs/infra" ||
			strings.Contains(nodeScalar(step, "uses"), "setup-go")
		if _, listed := toolSteps[name]; listed {
			toolSteps[name] = true
		} else if buildsTool {
			t.Errorf("jobs.%s step %q fetches or builds the tool but is not a tool_steps row gated on the pre-check", fixture.ClassifierJob, name)
			continue
		}
		if !buildsTool {
			if _, listed := toolSteps[name]; listed {
				t.Errorf("jobs.%s step %q is a tool_steps row but neither fetches nor builds the tool", fixture.ClassifierJob, name)
			}
			continue
		}
		if got := nodeScalar(step, "if"); got != fixture.ToolIf {
			t.Errorf("jobs.%s step %q if = %q, want the pre-check %q", fixture.ClassifierJob, name, got, fixture.ToolIf)
		}
	}
	for name, present := range toolSteps {
		if !present {
			t.Errorf("jobs.%s has no tool step %q", fixture.ClassifierJob, name)
		}
	}

	configData, err := os.ReadFile(filepath.Join("..", "..", fixture.ReleaseConfig))
	if err != nil {
		t.Fatalf("read %s: %v", fixture.ReleaseConfig, err)
	}
	var config struct {
		BotBranches struct {
			Release string `yaml:"release"`
		} `yaml:"bot_branches"`
	}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		t.Fatalf("parse %s: %v", fixture.ReleaseConfig, err)
	}
	precheck := classifierStep(t, jobs, fixture.ClassifierJob, fixture.PrecheckStep)
	if got := nodeScalar(provenanceMappingChild(precheck, "env"), "RELEASE_BRANCH"); config.BotBranches.Release == "" || got != config.BotBranches.Release {
		t.Errorf("pre-check RELEASE_BRANCH = %q, want %s bot_branches.release %q", got, fixture.ReleaseConfig, config.BotBranches.Release)
	}

	found := false
	for _, step := range provenanceMappingChild(classifier, "steps").Content {
		if nodeScalar(step, "id") != fixture.InheritStep {
			continue
		}
		found = true
		if provenanceMappingChild(step, "if") != nil || provenanceMappingChild(step, "continue-on-error") != nil {
			t.Errorf("jobs.%s step %s must have no if and no continue-on-error", fixture.ClassifierJob, fixture.InheritStep)
		}
		if !strings.Contains(nodeScalar(step, "run"), "release-intent\" inherit-verdict") {
			t.Errorf("jobs.%s step %s does not run release-intent inherit-verdict", fixture.ClassifierJob, fixture.InheritStep)
		}
	}
	if !found {
		t.Errorf("jobs.%s has no step with id %s", fixture.ClassifierJob, fixture.InheritStep)
	}

	policyData, err := os.ReadFile(filepath.Join("..", "..", fixture.PolicyFile))
	if err != nil {
		t.Fatalf("read %s: %v", fixture.PolicyFile, err)
	}
	var policy struct {
		Queue struct {
			InheritVerdict struct {
				Context      string `yaml:"context"`
				FullSuiteJob string `yaml:"full_suite_job"`
			} `yaml:"inherit_verdict"`
		} `yaml:"queue"`
	}
	if err := yaml.Unmarshal(policyData, &policy); err != nil {
		t.Fatalf("parse %s: %v", fixture.PolicyFile, err)
	}
	if got := policy.Queue.InheritVerdict; got.Context != fixture.AggregatorJob || got.FullSuiteJob != fixture.FullSuiteJob {
		t.Errorf("%s inherit_verdict = %+v, want context %s and full_suite_job %s", fixture.PolicyFile, got, fixture.AggregatorJob, fixture.FullSuiteJob)
	}
}
