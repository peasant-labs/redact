package releaseguard

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/workflow_policy.yaml
var workflowPolicyYAML []byte

type workflowPolicyFixture struct {
	Name     string `yaml:"name"`
	File     string `yaml:"file"`
	Contains string `yaml:"contains"`
}

func TestWorkflowPolicyFixtures(t *testing.T) {
	var fixtures []workflowPolicyFixture
	if err := yaml.Unmarshal(workflowPolicyYAML, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 9 {
		t.Fatalf("fixture count = %d, want 9", len(fixtures))
	}
	seen := map[string]bool{}
	for _, fixture := range fixtures {
		if fixture.Name == "" || seen[fixture.Name] {
			t.Fatalf("empty or duplicate fixture name %q", fixture.Name)
		}
		seen[fixture.Name] = true
		contents, err := os.ReadFile(filepath.Join("..", "..", fixture.File))
		if err != nil {
			t.Fatalf("read %s: %v", fixture.File, err)
		}
		if !strings.Contains(string(contents), fixture.Contains) {
			t.Errorf("%s lacks required release policy %q", fixture.File, fixture.Contains)
		}
	}
}
