package redact

import (
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// SupportedLang tests
// ---------------------------------------------------------------------------

func TestSupportedLang_IsSupported(t *testing.T) {
	tests := []struct {
		lang      SupportedLang
		supported bool
	}{
		{LangGo, true},
		{LangPython, true},
		{LangTypeScript, true},
		{LangJavaScript, true},
		{LangBash, true},
		{LangUnknown, false},
		{SupportedLang("ruby"), false},
	}
	for _, tt := range tests {
		t.Run(tt.lang.String(), func(t *testing.T) {
			if got := tt.lang.IsSupported(); got != tt.supported {
				t.Errorf("SupportedLang(%q).IsSupported() = %v, want %v", tt.lang, got, tt.supported)
			}
		})
	}
}

func TestParseLangHint(t *testing.T) {
	tests := []struct {
		hint string
		want SupportedLang
	}{
		{"go", LangGo},
		{"golang", LangGo},
		{"python", LangPython},
		{"py", LangPython},
		{"typescript", LangTypeScript},
		{"ts", LangTypeScript},
		{"javascript", LangJavaScript},
		{"js", LangJavaScript},
		{"bash", LangBash},
		{"sh", LangBash},
		{"shell", LangBash},
		{"zsh", LangBash},
		{"ruby", LangUnknown},
		{"haskell", LangUnknown},
		{"", LangUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.hint, func(t *testing.T) {
			if got := ParseLangHint(tt.hint); got != tt.want {
				t.Errorf("ParseLangHint(%q) = %q, want %q", tt.hint, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Code block extraction tests
// ---------------------------------------------------------------------------

func TestExtractCodeBlocks_Go(t *testing.T) {
	text := "before\n```go\nfunc main() { fmt.Println(\"hello\") }\n```\nafter"
	blocks := ExtractCodeBlocks(text)
	if len(blocks) != 1 {
		t.Fatalf("ExtractCodeBlocks: got %d blocks, want 1", len(blocks))
	}
	if blocks[0].Lang != LangGo {
		t.Errorf("ExtractCodeBlocks: Lang = %q, want %q", blocks[0].Lang, LangGo)
	}
	if !strings.Contains(blocks[0].Content, "func main()") {
		t.Errorf("ExtractCodeBlocks: Content = %q, want containing 'func main()'", blocks[0].Content)
	}
}

func TestExtractCodeBlocks_Multiple(t *testing.T) {
	text := "intro\n```go\npackage main\n```\nmiddle\n```python\ndef hello(): pass\n```\nend"
	blocks := ExtractCodeBlocks(text)
	if len(blocks) != 2 {
		t.Fatalf("ExtractCodeBlocks_Multiple: got %d blocks, want 2", len(blocks))
	}
	if blocks[0].Lang != LangGo {
		t.Errorf("block[0].Lang = %q, want %q", blocks[0].Lang, LangGo)
	}
	if blocks[1].Lang != LangPython {
		t.Errorf("block[1].Lang = %q, want %q", blocks[1].Lang, LangPython)
	}
}

func TestExtractCodeBlocks_NoFence(t *testing.T) {
	text := "plain text with no code blocks"
	blocks := ExtractCodeBlocks(text)
	if len(blocks) != 0 {
		t.Errorf("ExtractCodeBlocks_NoFence: got %d blocks, want 0", len(blocks))
	}
}

func TestExtractCodeBlocks_UnknownLang(t *testing.T) {
	text := "text\n```ruby\nputs 'hello'\n```\nmore"
	blocks := ExtractCodeBlocks(text)
	if len(blocks) != 1 {
		t.Fatalf("ExtractCodeBlocks_UnknownLang: got %d blocks, want 1", len(blocks))
	}
	if blocks[0].Lang != LangUnknown {
		t.Errorf("block.Lang = %q, want %q (LangUnknown)", blocks[0].Lang, LangUnknown)
	}
}

func TestExtractCodeBlocks_Offsets(t *testing.T) {
	// Verify Start/End byte offsets point to the correct positions in the source text.
	text := "before\n```go\nfunc main() {}\n```\nafter"
	blocks := ExtractCodeBlocks(text)
	if len(blocks) != 1 {
		t.Fatalf("ExtractCodeBlocks_Offsets: got %d blocks, want 1", len(blocks))
	}
	b := blocks[0]

	// The substring from Start to End must be the full fence including backticks.
	fence := text[b.Start:b.End]
	if !strings.HasPrefix(fence, "```go") {
		t.Errorf("ExtractCodeBlocks_Offsets: fence does not start with '```go': %q", fence)
	}
	if !strings.HasSuffix(fence, "```") {
		t.Errorf("ExtractCodeBlocks_Offsets: fence does not end with '```': %q", fence)
	}
	// End > Start
	if b.End <= b.Start {
		t.Errorf("ExtractCodeBlocks_Offsets: End (%d) <= Start (%d)", b.End, b.Start)
	}
	// Content must appear inside the fence boundaries.
	if !strings.Contains(fence, b.Content) {
		t.Errorf("ExtractCodeBlocks_Offsets: content %q not found inside fence %q", b.Content, fence)
	}
}

// ---------------------------------------------------------------------------
// anonymizeCodeBlocks fence preservation tests
// ---------------------------------------------------------------------------

func TestAnonymizeCodeBlocks_UnsupportedLangPreservesFence(t *testing.T) {
	anon := NewRegexAnonymizer()
	// A code block with an unsupported language hint ("ruby") must be written
	// back verbatim — the "ruby" label must not be silently stripped.
	input := "text\n```ruby\nputs 'hello world'\n```\nafter"
	got := anonymizeCodeBlocks(anon, input)
	if got != input {
		t.Errorf("anonymizeCodeBlocks: unsupported lang fence modified:\n got:  %q\n want: %q", got, input)
	}
}

func TestAnonymizeCodeBlocks_NoLangHintPreservesFence(t *testing.T) {
	anon := NewRegexAnonymizer()
	// A code block with no language hint (empty fence) must be written back
	// verbatim.
	input := "text\n```\nsome code\n```\nafter"
	got := anonymizeCodeBlocks(anon, input)
	if got != input {
		t.Errorf("anonymizeCodeBlocks: empty-lang fence modified:\n got:  %q\n want: %q", got, input)
	}
}

func TestAnonymizeCodeBlocks_SupportedLangRewritesFence(t *testing.T) {
	anon := NewRegexAnonymizer()
	// A code block with a supported language that has identifiers to anonymize
	// should have its fence reconstructed with anonymized content.
	input := "text\n```go\nfunc processUser() {}\n```\nafter"
	got := anonymizeCodeBlocks(anon, input)
	// The identifier should be anonymized (not left as "processUser").
	if strings.Contains(got, "processUser") {
		t.Errorf("anonymizeCodeBlocks: Go identifier not anonymized in: %q", got)
	}
	// The "go" language hint must be preserved in the rewritten fence.
	if !strings.Contains(got, "```go\n") {
		t.Errorf("anonymizeCodeBlocks: 'go' lang hint missing from rewritten fence: %q", got)
	}
}

// TestAnonymizeCodeBlocks_ErrorPreservesBlock verifies that when AnonymizeCode
// returns an error, the original fence is written verbatim.
func TestAnonymizeCodeBlocks_ErrorPreservesBlock(t *testing.T) {
	anon := &errorAnonymizer{}
	input := "text\n```go\nfunc processUser() {}\n```\nafter"
	got := anonymizeCodeBlocks(anon, input)
	// On error the block must be preserved exactly as it appears in the input.
	if got != input {
		t.Errorf("anonymizeCodeBlocks: error path modified input:\n got:  %q\n want: %q", got, input)
	}
}

// errorAnonymizer always returns an error from AnonymizeCode.
type errorAnonymizer struct{}

func (e *errorAnonymizer) AnonymizeCode(_ SupportedLang, code string) (string, error) {
	return code, &mockAnonymizerError{}
}

// mockAnonymizerError is a sentinel error for testing the error path.
type mockAnonymizerError struct{}

func (m *mockAnonymizerError) Error() string { return "mock anonymizer error" }

// ---------------------------------------------------------------------------
// Anonymization correctness tests
// ---------------------------------------------------------------------------

func TestASTAnonymizer_Go(t *testing.T) {
	anon := NewRegexAnonymizer()
	input := `func processUser(db *sql.DB) error { return nil }`
	output, err := anon.AnonymizeCode(LangGo, input)
	if err != nil {
		t.Fatalf("ASTAnonymizer_Go: unexpected error: %v", err)
	}
	// Function name should be replaced.
	if strings.Contains(output, "processUser") {
		t.Errorf("ASTAnonymizer_Go: identifier 'processUser' was NOT anonymized in: %q", output)
	}
	// Keywords must be preserved.
	if !strings.Contains(output, "func") {
		t.Errorf("ASTAnonymizer_Go: keyword 'func' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("ASTAnonymizer_Go: keyword 'return' missing in: %q", output)
	}
	// Structural validity: braces must be balanced.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("ASTAnonymizer_Go: unbalanced braces in: %q", output)
	}
}

func TestASTAnonymizer_Python(t *testing.T) {
	anon := NewRegexAnonymizer()
	input := `def process(data):
    return data.strip()`
	output, err := anon.AnonymizeCode(LangPython, input)
	if err != nil {
		t.Fatalf("ASTAnonymizer_Python: unexpected error: %v", err)
	}
	// Identifiers should be replaced.
	if strings.Contains(output, "process") {
		t.Errorf("ASTAnonymizer_Python: identifier 'process' was NOT anonymized in: %q", output)
	}
	// Keyword 'def' must be preserved.
	if !strings.Contains(output, "def") {
		t.Errorf("ASTAnonymizer_Python: keyword 'def' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("ASTAnonymizer_Python: keyword 'return' missing in: %q", output)
	}
	// Structural validity: Python indentation uses leading spaces — the indented
	// line must still start with whitespace after anonymization.
	lines := strings.Split(output, "\n")
	if len(lines) >= 2 && !strings.HasPrefix(lines[1], " ") {
		t.Errorf("ASTAnonymizer_Python: indentation lost on line 2: %q", lines[1])
	}
	// Colons must be preserved (Python block syntax).
	if !strings.Contains(output, ":") {
		t.Errorf("ASTAnonymizer_Python: colon missing from output: %q", output)
	}
}

func TestASTAnonymizer_TypeScript(t *testing.T) {
	anon := NewRegexAnonymizer()
	input := `function fetchUserData(userId: number): Promise<string> {
    const response = await apiClient.get(userId);
    return response.toString();
}`
	output, err := anon.AnonymizeCode(LangTypeScript, input)
	if err != nil {
		t.Fatalf("ASTAnonymizer_TypeScript: unexpected error: %v", err)
	}
	// User-defined identifiers should be replaced.
	if strings.Contains(output, "fetchUserData") {
		t.Errorf("ASTAnonymizer_TypeScript: identifier 'fetchUserData' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "userId") {
		t.Errorf("ASTAnonymizer_TypeScript: identifier 'userId' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "apiClient") {
		t.Errorf("ASTAnonymizer_TypeScript: identifier 'apiClient' was NOT anonymized in: %q", output)
	}
	// TypeScript keywords must be preserved.
	if !strings.Contains(output, "function") {
		t.Errorf("ASTAnonymizer_TypeScript: keyword 'function' missing in: %q", output)
	}
	if !strings.Contains(output, "const") {
		t.Errorf("ASTAnonymizer_TypeScript: keyword 'const' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("ASTAnonymizer_TypeScript: keyword 'return' missing in: %q", output)
	}
	// Structural validity: braces must be balanced.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("ASTAnonymizer_TypeScript: unbalanced braces in: %q", output)
	}
}

func TestASTAnonymizer_Bash(t *testing.T) {
	anon := NewRegexAnonymizer()
	input := `function deployService() {
    local serviceName="myapp"
    echo "Deploying ${serviceName}"
    if docker build -t "${serviceName}" .; then
        return 0
    fi
}`
	output, err := anon.AnonymizeCode(LangBash, input)
	if err != nil {
		t.Fatalf("ASTAnonymizer_Bash: unexpected error: %v", err)
	}
	// User-defined identifiers should be replaced.
	if strings.Contains(output, "deployService") {
		t.Errorf("ASTAnonymizer_Bash: identifier 'deployService' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "serviceName") {
		t.Errorf("ASTAnonymizer_Bash: identifier 'serviceName' was NOT anonymized in: %q", output)
	}
	// Bash keywords must be preserved.
	if !strings.Contains(output, "function") {
		t.Errorf("ASTAnonymizer_Bash: keyword 'function' missing in: %q", output)
	}
	if !strings.Contains(output, "local") {
		t.Errorf("ASTAnonymizer_Bash: keyword 'local' missing in: %q", output)
	}
	if !strings.Contains(output, "echo") {
		t.Errorf("ASTAnonymizer_Bash: keyword 'echo' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("ASTAnonymizer_Bash: keyword 'return' missing in: %q", output)
	}
	// Structural validity: braces must be balanced.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("ASTAnonymizer_Bash: unbalanced braces in: %q", output)
	}
}

func TestASTAnonymizer_UnknownLang(t *testing.T) {
	anon := NewRegexAnonymizer()
	input := "some_unknown_code()"
	output, err := anon.AnonymizeCode(LangUnknown, input)
	if err != nil {
		t.Fatalf("ASTAnonymizer_UnknownLang: unexpected error: %v", err)
	}
	if output != input {
		t.Errorf("ASTAnonymizer_UnknownLang: expected unchanged output; got %q, want %q", output, input)
	}
}

func TestASTAnonymizer_JavaScript(t *testing.T) {
	anon := NewRegexAnonymizer()
	// JavaScript uses the same keyword set as TypeScript.
	input := `function fetchUserData(userId) {
    const response = apiClient.get(userId);
    return response.toString();
}`
	output, err := anon.AnonymizeCode(LangJavaScript, input)
	if err != nil {
		t.Fatalf("ASTAnonymizer_JavaScript: unexpected error: %v", err)
	}
	// User-defined identifiers should be replaced.
	if strings.Contains(output, "fetchUserData") {
		t.Errorf("ASTAnonymizer_JavaScript: identifier 'fetchUserData' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "userId") {
		t.Errorf("ASTAnonymizer_JavaScript: identifier 'userId' was NOT anonymized in: %q", output)
	}
	if strings.Contains(output, "apiClient") {
		t.Errorf("ASTAnonymizer_JavaScript: identifier 'apiClient' was NOT anonymized in: %q", output)
	}
	// JavaScript keywords must be preserved.
	if !strings.Contains(output, "function") {
		t.Errorf("ASTAnonymizer_JavaScript: keyword 'function' missing in: %q", output)
	}
	if !strings.Contains(output, "const") {
		t.Errorf("ASTAnonymizer_JavaScript: keyword 'const' missing in: %q", output)
	}
	if !strings.Contains(output, "return") {
		t.Errorf("ASTAnonymizer_JavaScript: keyword 'return' missing in: %q", output)
	}
	// Structural validity: braces must be balanced.
	if strings.Count(output, "{") != strings.Count(output, "}") {
		t.Errorf("ASTAnonymizer_JavaScript: unbalanced braces in: %q", output)
	}
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

// TestASTAnonymizer_Deterministic_SameSession verifies that the same identifier
// receives the same anonymous name across two calls on the same anonymizer instance.
// The check uses a direct string search for the known replacement pattern rather
// than fragile whitespace-splitting.
func TestASTAnonymizer_Deterministic_SameSession(t *testing.T) {
	anon := NewRegexAnonymizer()
	// Anonymize two code blocks that both contain "processUser".
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

	// Both outputs must not contain the original identifier.
	if strings.Contains(outA, "processUser") {
		t.Errorf("Deterministic_SameSession: 'processUser' not anonymized in outA: %q", outA)
	}
	if strings.Contains(outB, "processUser") {
		t.Errorf("Deterministic_SameSession: 'processUser' not anonymized in outB: %q", outB)
	}

	// Extract the replacement name: it is the identifier that appears after "func "
	// in the output. Both outputs share the same anonymizer, so the replacement
	// must be identical.
	//
	// We find the replacement by searching for "func " and then extracting the
	// next word (stopping at '(' or space). This is robust against changing
	// counter values but depends on the presence of the "func" keyword — which
	// is guaranteed to be preserved.
	nameA := extractWordAfter(outA, "func ")
	nameB := extractWordAfter(outB, "func ")

	if nameA == "" || nameB == "" {
		t.Fatalf("Deterministic_SameSession: could not extract replacement name from %q / %q", outA, outB)
	}
	if nameA != nameB {
		t.Errorf("Deterministic_SameSession: same identifier got different names: %q vs %q", nameA, nameB)
	}
}

// extractWordAfter finds needle in s and returns the next run of identifier
// characters (\w+) after it. Returns "" if not found.
func extractWordAfter(s, needle string) string {
	idx := strings.Index(s, needle)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(needle):]
	end := strings.IndexAny(rest, "( \t\n")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

func TestExtractWordAfter(t *testing.T) {
	tests := []struct {
		s      string
		needle string
		want   string
	}{
		{"func processUser() {}", "func ", "processUser"},
		{"func id1() {}", "func ", "id1"},
		{"no match here", "func ", ""},
		{"func ", "func ", ""},   // nothing after needle
		{"func ()", "func ", ""}, // delimiter immediately after needle
		{"abc func end", "func ", "end"},
		{"prefix func word\n", "func ", "word"},
	}
	for _, tt := range tests {
		got := extractWordAfter(tt.s, tt.needle)
		if got != tt.want {
			t.Errorf("extractWordAfter(%q, %q) = %q, want %q", tt.s, tt.needle, got, tt.want)
		}
	}
}

func TestASTAnonymizer_Deterministic_CrossInstance(t *testing.T) {
	code := `func processUser() {}`

	anon1 := NewRegexAnonymizer()
	out1, err := anon1.AnonymizeCode(LangGo, code)
	if err != nil {
		t.Fatal(err)
	}

	anon2 := NewRegexAnonymizer()
	out2, err := anon2.AnonymizeCode(LangGo, code)
	if err != nil {
		t.Fatal(err)
	}

	if out1 != out2 {
		t.Errorf("Deterministic_CrossInstance: outputs differ: %q vs %q", out1, out2)
	}
}

// ---------------------------------------------------------------------------
// Concurrency test at Maximum level
// ---------------------------------------------------------------------------

// TestASTAnonymizer_ConcurrencyMaximum spawns 10 goroutines calling AnonymizeCode
// concurrently on the same instance. Passes -race detector.
func TestASTAnonymizer_ConcurrencyMaximum(t *testing.T) {
	anon := NewRegexAnonymizer()
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
			t.Errorf("ConcurrencyMaximum: goroutine %d returned error: %v", i, err)
		}
	}
	for i, out := range results {
		if strings.Contains(out, "processUser") {
			t.Errorf("ConcurrencyMaximum: goroutine %d did not anonymize 'processUser': %q", i, out)
		}
	}
	// All outputs must be identical (deterministic under concurrent access).
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Errorf("ConcurrencyMaximum: goroutine %d output differs from goroutine 0:\n  got:  %q\n  want: %q", i, results[i], results[0])
		}
	}
}

// ---------------------------------------------------------------------------
// Integration with DefaultRedactor
// ---------------------------------------------------------------------------

func TestDefaultRedactor_ASTAtMaximum(t *testing.T) {
	r := mustNewRedactor(t, Maximum, nil)
	input := "Here is code:\n```go\nfunc processUser(db *sql.DB) error { return nil }\n```\nEnd."
	got := r.RedactText(input)

	// At Maximum: identifiers in the code block should be anonymized.
	if strings.Contains(got, "processUser") {
		t.Errorf("ASTAtMaximum: identifier 'processUser' was NOT anonymized in: %q", got)
	}
	// The code block should NOT be entirely replaced with <CODE_BLOCK> at Maximum.
	// AST anonymization preserves structure — it replaces identifiers, not the whole block.
	if strings.Contains(got, "<CODE_BLOCK>") {
		t.Errorf("ASTAtMaximum: code block was masked to <CODE_BLOCK> instead of AST-anonymized: %q", got)
	}
}

func TestDefaultRedactor_ASTNotAtStandard(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	input := "Here is code:\n```go\nfunc processUser(db *sql.DB) error { return nil }\n```\nEnd."
	got := r.RedactText(input)

	// At Standard: v1 code block masking applies, not AST anonymization.
	// The code block should be replaced with <CODE_BLOCK>.
	if strings.Contains(got, "processUser") {
		// processUser should be gone (masked by <CODE_BLOCK>)
		t.Errorf("ASTNotAtStandard: identifier 'processUser' visible at Standard level: %q", got)
	}
	if !strings.Contains(got, "<CODE_BLOCK>") {
		t.Errorf("ASTNotAtStandard: expected <CODE_BLOCK> masking at Standard level: %q", got)
	}
}
