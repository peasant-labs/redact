//go:build cgo

// Compiled only in cgo builds: these tests exercise TreeSitterAnonymizer and the
// Maximum-level pipeline, which require the cgo-only tree_sitter.go. In !cgo
// builds the Maximum level is rejected at construction (covered by the untagged
// maximum_available_test.go negative gate).

package redact

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Compile-time guard
// ---------------------------------------------------------------------------

// TestTreeSitterAnonymizer_CompileTimeGuard verifies the compile-time interface
// check embedded in tree_sitter.go compiles cleanly. No runtime assertion needed —
// if the guard fails, the package will not compile.
func TestTreeSitterAnonymizer_CompileTimeGuard(_ *testing.T) {
	// var _ ASTAnonymizer = (*TreeSitterAnonymizer)(nil)  — already in tree_sitter.go
	// var _ ASTAnonymizer = (*FallbackAnonymizer)(nil)     — already in tree_sitter.go
}

// ---------------------------------------------------------------------------
// Per-language anonymization tests
// ---------------------------------------------------------------------------

func TestTreeSitterAnonymizer_Go(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	input := `func processUser(db *sql.DB) error { return nil }`
	output, err := anon.AnonymizeCode(LangGo, input)
	if err != nil {
		t.Fatalf("TreeSitterAnonymizer_Go: unexpected error: %v", err)
	}
	// Function name should be replaced.
	if strings.Contains(output, "processUser") {
		t.Errorf("TreeSitterAnonymizer_Go: identifier 'processUser' was NOT anonymized in: %q", output)
	}
	// Variable 'db' should be replaced. The identifier appears as "(db *" in the
	// input, so check that exact context to avoid a vacuous assertion.
	if strings.Contains(output, "(db ") {
		t.Errorf("TreeSitterAnonymizer_Go: identifier 'db' was NOT anonymized in: %q", output)
	}
	// Keywords must be preserved.
	if !strings.Contains(output, "func") {
		t.Errorf("TreeSitterAnonymizer_Go: keyword 'func' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("TreeSitterAnonymizer_Go: keyword 'return' missing in: %q", output)
	}
	if !strings.Contains(output, "nil") {
		t.Errorf("TreeSitterAnonymizer_Go: identifier 'nil' should be preserved as keyword: %q", output)
	}
	// Structural validity: braces must be balanced.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("TreeSitterAnonymizer_Go: unbalanced braces in: %q", output)
	}
}

func TestTreeSitterAnonymizer_Python(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	input := "def process(data):\n    return data.strip()"
	output, err := anon.AnonymizeCode(LangPython, input)
	if err != nil {
		t.Fatalf("TreeSitterAnonymizer_Python: unexpected error: %v", err)
	}
	// Identifiers should be replaced.
	if strings.Contains(output, "process") {
		t.Errorf("TreeSitterAnonymizer_Python: identifier 'process' was NOT anonymized in: %q", output)
	}
	// Keyword 'def' must be preserved.
	if !strings.Contains(output, "def") {
		t.Errorf("TreeSitterAnonymizer_Python: keyword 'def' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("TreeSitterAnonymizer_Python: keyword 'return' missing in: %q", output)
	}
	// Structural validity: Python indentation must be preserved.
	lines := strings.Split(output, "\n")
	if len(lines) >= 2 && !strings.HasPrefix(lines[1], " ") {
		t.Errorf("TreeSitterAnonymizer_Python: indentation lost on line 2: %q", lines[1])
	}
	// Colon must be preserved (Python block syntax).
	if !strings.Contains(output, ":") {
		t.Errorf("TreeSitterAnonymizer_Python: colon missing from output: %q", output)
	}
}

func TestTreeSitterAnonymizer_TypeScript(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	input := `function fetchUserData(userId: number): string {
    const response = apiClient.get(userId);
    return response.toString();
}`
	output, err := anon.AnonymizeCode(LangTypeScript, input)
	if err != nil {
		t.Fatalf("TreeSitterAnonymizer_TypeScript: unexpected error: %v", err)
	}
	// User-defined identifiers should be replaced.
	if strings.Contains(output, "fetchUserData") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: identifier 'fetchUserData' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "userId") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: identifier 'userId' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "apiClient") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: identifier 'apiClient' was NOT anonymized in: %q", output)
	}
	// TypeScript keywords must be preserved.
	if !strings.Contains(output, "function") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: keyword 'function' missing in: %q", output)
	}
	if !strings.Contains(output, "const") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: keyword 'const' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: keyword 'return' missing in: %q", output)
	}
	// Structural validity.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("TreeSitterAnonymizer_TypeScript: unbalanced braces in: %q", output)
	}
}

func TestTreeSitterAnonymizer_JavaScript(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	input := `function fetchData(userId) {
    const response = apiClient.get(userId);
    return response;
}`
	output, err := anon.AnonymizeCode(LangJavaScript, input)
	if err != nil {
		t.Fatalf("TreeSitterAnonymizer_JavaScript: unexpected error: %v", err)
	}
	// User-defined identifiers should be replaced.
	if strings.Contains(output, "fetchData") {
		t.Errorf("TreeSitterAnonymizer_JavaScript: identifier 'fetchData' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "userId") {
		t.Errorf("TreeSitterAnonymizer_JavaScript: identifier 'userId' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "apiClient") {
		t.Errorf("TreeSitterAnonymizer_JavaScript: identifier 'apiClient' was NOT anonymized in: %q", output)
	}
	// Keywords must be preserved.
	if !strings.Contains(output, "function") {
		t.Errorf("TreeSitterAnonymizer_JavaScript: keyword 'function' missing in: %q", output)
	}
	if !strings.Contains(output, "const") {
		t.Errorf("TreeSitterAnonymizer_JavaScript: keyword 'const' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("TreeSitterAnonymizer_JavaScript: keyword 'return' missing in: %q", output)
	}
}

func TestTreeSitterAnonymizer_Bash(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	input := `function deployService() {
    local serviceName="myapp"
    echo "Deploying ${serviceName}"
    if docker build -t "${serviceName}" .; then
        return 0
    fi
}`
	output, err := anon.AnonymizeCode(LangBash, input)
	if err != nil {
		t.Fatalf("TreeSitterAnonymizer_Bash: unexpected error: %v", err)
	}
	// User-defined identifiers should be replaced.
	if strings.Contains(output, "deployService") {
		t.Errorf("TreeSitterAnonymizer_Bash: identifier 'deployService' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "serviceName") {
		t.Errorf("TreeSitterAnonymizer_Bash: identifier 'serviceName' was NOT anonymized in: %q", output)
	}
	// Bash keywords must be preserved.
	if !strings.Contains(output, "function") {
		t.Errorf("TreeSitterAnonymizer_Bash: keyword 'function' missing in: %q", output)
	}
	if !strings.Contains(output, "local") {
		t.Errorf("TreeSitterAnonymizer_Bash: keyword 'local' missing in: %q", output)
	}
	if !strings.Contains(output, "echo") {
		t.Errorf("TreeSitterAnonymizer_Bash: keyword 'echo' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("TreeSitterAnonymizer_Bash: keyword 'return' missing in: %q", output)
	}
	// Structural validity.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("TreeSitterAnonymizer_Bash: unbalanced braces in: %q", output)
	}
}

func TestTreeSitterAnonymizer_UnknownLang(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	input := "some_unknown_code()"
	output, err := anon.AnonymizeCode(LangUnknown, input)
	if err != nil {
		t.Fatalf("TreeSitterAnonymizer_UnknownLang: unexpected error: %v", err)
	}
	if output != input {
		t.Errorf("TreeSitterAnonymizer_UnknownLang: expected unchanged output; got %q, want %q", output, input)
	}
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

// TestTreeSitterAnonymizer_Deterministic_SameSession verifies that the same
// identifier receives the same anonymous name across two calls on the same instance.
func TestTreeSitterAnonymizer_Deterministic_SameSession(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	codeA := `func processUser() {}`
	codeB := `func processUser(id int) {}`

	outA, err := anon.AnonymizeCode(LangGo, codeA)
	if err != nil {
		t.Fatal(err)
	}
	outB, err := anon.AnonymizeCode(LangGo, codeB)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(outA, "processUser") {
		t.Errorf("Deterministic_SameSession: 'processUser' not anonymized in outA: %q", outA)
	}
	if strings.Contains(outB, "processUser") {
		t.Errorf("Deterministic_SameSession: 'processUser' not anonymized in outB: %q", outB)
	}

	// Both calls share the same anonymizer, so the replacement must be identical.
	nameA := extractWordAfter(outA, "func ")
	nameB := extractWordAfter(outB, "func ")

	if nameA == "" || nameB == "" {
		t.Fatalf("Deterministic_SameSession: could not extract replacement name from %q / %q", outA, outB)
	}
	if nameA != nameB {
		t.Errorf("Deterministic_SameSession: same identifier got different names: %q vs %q", nameA, nameB)
	}
}

func TestTreeSitterAnonymizer_Deterministic_CrossInstance(t *testing.T) {
	code := `func processUser() {}`

	anon1 := NewTreeSitterAnonymizer()
	out1, err := anon1.AnonymizeCode(LangGo, code)
	if err != nil {
		t.Fatal(err)
	}

	anon2 := NewTreeSitterAnonymizer()
	out2, err := anon2.AnonymizeCode(LangGo, code)
	if err != nil {
		t.Fatal(err)
	}

	if out1 != out2 {
		t.Errorf("Deterministic_CrossInstance: outputs differ:\n  got:  %q\n  want: %q", out1, out2)
	}
}

// ---------------------------------------------------------------------------
// Concurrency test
// ---------------------------------------------------------------------------

// TestTreeSitterAnonymizer_Concurrency spawns 10 goroutines calling AnonymizeCode
// concurrently on the same instance. Must pass -race detector.
func TestTreeSitterAnonymizer_Concurrency(t *testing.T) {
	anon := NewTreeSitterAnonymizer()
	code := `func processUser(db *sql.DB) error { return nil }`

	const goroutines = 10
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			results[i], errs[i] = anon.AnonymizeCode(LangGo, code)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("Concurrency: goroutine %d returned error: %v", i, err)
		}
	}
	for i, out := range results {
		if strings.Contains(out, "processUser") {
			t.Errorf("Concurrency: goroutine %d did not anonymize 'processUser': %q", i, out)
		}
	}
	// All outputs must be identical (deterministic under concurrent access).
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Errorf("Concurrency: goroutine %d output differs from goroutine 0:\n  got:  %q\n  want: %q", i, results[i], results[0])
		}
	}
}

// ---------------------------------------------------------------------------
// Fallback tests
// ---------------------------------------------------------------------------

// TestFallbackAnonymizer_UsesSecondaryOnError verifies that when the primary
// anonymizer returns an error, the fallback is used and produces valid output.
func TestFallbackAnonymizer_UsesSecondaryOnError(t *testing.T) {
	primary := &alwaysErrorAnonymizer{}
	fallback := NewRegexAnonymizer()
	fa := NewFallbackAnonymizer(primary, fallback)

	input := `func processUser() {}`
	output, err := fa.AnonymizeCode(LangGo, input)
	if err != nil {
		t.Fatalf("FallbackAnonymizer: unexpected error: %v", err)
	}
	// RegexAnonymizer should have replaced the identifier.
	if strings.Contains(output, "processUser") {
		t.Errorf("FallbackAnonymizer: identifier 'processUser' not replaced by fallback: %q", output)
	}
}

// TestFallbackAnonymizer_UsesPrimaryOnSuccess verifies that when the primary
// anonymizer succeeds, its output is used (not the fallback's).
func TestFallbackAnonymizer_UsesPrimaryOnSuccess(t *testing.T) {
	primary := &fixedOutputAnonymizer{output: "REPLACED"}
	fallback := &alwaysErrorAnonymizer{}
	fa := NewFallbackAnonymizer(primary, fallback)

	output, err := fa.AnonymizeCode(LangGo, "anything")
	if err != nil {
		t.Fatalf("FallbackAnonymizer: unexpected error: %v", err)
	}
	if output != "REPLACED" {
		t.Errorf("FallbackAnonymizer: expected primary output %q, got %q", "REPLACED", output)
	}
}

// TestFallbackAnonymizer_TreeSitterWithRegexFallback is an end-to-end test that
// uses TreeSitterAnonymizer as primary and RegexAnonymizer as fallback (same as
// production wiring). Verifies the combined path produces anonymized output.
func TestFallbackAnonymizer_TreeSitterWithRegexFallback(t *testing.T) {
	fa := NewFallbackAnonymizer(NewTreeSitterAnonymizer(), NewRegexAnonymizer())

	input := `func processUser(db *sql.DB) error { return nil }`
	output, err := fa.AnonymizeCode(LangGo, input)
	if err != nil {
		t.Fatalf("FallbackAnonymizer_TreeSitterWithRegexFallback: unexpected error: %v", err)
	}
	if strings.Contains(output, "processUser") {
		t.Errorf("FallbackAnonymizer_TreeSitterWithRegexFallback: 'processUser' not anonymized: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Integration test: RedactText at Maximum uses tree-sitter
// ---------------------------------------------------------------------------

// TestDefaultRedactor_TreeSitterAtMaximum verifies that the production wiring
// (NewRedactor at Maximum) uses TreeSitterAnonymizer, resulting in identifiers
// being replaced rather than the whole block being masked.
func TestDefaultRedactor_TreeSitterAtMaximum(t *testing.T) {
	r := mustNewRedactor(t, Maximum, nil)
	input := "Here is code:\n```go\nfunc processUser(db *sql.DB) error { return nil }\n```\nEnd."
	got := r.RedactText(input)

	// At Maximum with tree-sitter: identifiers should be anonymized.
	if strings.Contains(got, "processUser") {
		t.Errorf("TreeSitterAtMaximum: identifier 'processUser' was NOT anonymized in: %q", got)
	}
	// The code block must NOT be replaced with <CODE_BLOCK> — tree-sitter preserves structure.
	if strings.Contains(got, "<CODE_BLOCK>") {
		t.Errorf("TreeSitterAtMaximum: block was masked instead of AST-anonymized: %q", got)
	}
	// The 'go' fence label must be preserved.
	if !strings.Contains(got, "```go\n") {
		t.Errorf("TreeSitterAtMaximum: 'go' language hint missing from output: %q", got)
	}
}

// TestDefaultRedactor_TreeSitterKeywordPreservation verifies that Go keywords
// survive anonymization at Maximum level.
func TestDefaultRedactor_TreeSitterKeywordPreservation(t *testing.T) {
	r := mustNewRedactor(t, Maximum, nil)
	input := "Code:\n```go\nfunc processUser() error { return nil }\n```"
	got := r.RedactText(input)

	for _, kw := range []string{"func", "return", "nil"} {
		if !strings.Contains(got, kw) {
			t.Errorf("TreeSitterKeywordPreservation: keyword %q missing from output: %q", kw, got)
		}
	}
}

// TestDefaultRedactor_TreeSitterAllLanguages runs a smoke test for all 5 languages
// through the full NewRedactor(Maximum) pipeline.
func TestDefaultRedactor_TreeSitterAllLanguages(t *testing.T) {
	tests := loadTreeSitterFixtures(t).AllLanguages

	for _, tt := range tests {
		t.Run(tt.ID, func(t *testing.T) {
			r := mustNewRedactor(t, Maximum, nil)
			fenced := "Code:\n```" + tt.Language + "\n" + tt.Input + "\n```"
			got := r.RedactText(fenced)

			for _, absent := range tt.MustAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("lang=%s: identifier %q was NOT anonymized in: %q", tt.Language, absent, got)
				}
			}
			for _, present := range tt.MustPresent {
				if !strings.Contains(got, present) {
					t.Errorf("lang=%s: keyword/structure %q missing from: %q", tt.Language, present, got)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test helpers (anonymizer stubs for fallback tests)
// ---------------------------------------------------------------------------

// alwaysErrorAnonymizer always returns an error.
type alwaysErrorAnonymizer struct{}

func (a *alwaysErrorAnonymizer) AnonymizeCode(_ SupportedLang, code string) (string, error) {
	return code, errors.New("always-error anonymizer")
}

// fixedOutputAnonymizer always returns a fixed string.
type fixedOutputAnonymizer struct{ output string }

func (f *fixedOutputAnonymizer) AnonymizeCode(_ SupportedLang, _ string) (string, error) {
	return f.output, nil
}
