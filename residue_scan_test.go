package redact

import (
	_ "embed"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/residue_scan.yaml
var residueScanFixtureData []byte

// residueScanFixtureDocument groups the reviewed residue-switch and cap rows.
// Both families carry an exact-membership name manifest; see requireFixtureNames.
type residueScanFixtureDocument struct {
	RequiredParityIDs []string                   `yaml:"required_parity_ids"`
	Parity            []residueScanParityFixture `yaml:"parity"`
	RequiredLimitIDs  []string                   `yaml:"required_limit_ids"`
	Limit             []residueScanLimitFixture  `yaml:"limit"`
}

// residueScanParityFixture pins one input through a default redactor and a
// WithResidue(false) redactor. WantResidue says whether the default redactor is
// expected to leave any residue warning for the input.
type residueScanParityFixture struct {
	ID          string         `yaml:"id"`
	Why         string         `yaml:"why"`
	Level       RedactionLevel `yaml:"level"`
	Input       string         `yaml:"input"`
	WantResidue bool           `yaml:"want_residue"`
}

// residueScanLimitFixture builds one input from Repeat copies of Input joined
// by Separator and runs it Passes times against a single redactor.
type residueScanLimitFixture struct {
	ID                  string         `yaml:"id"`
	Why                 string         `yaml:"why"`
	Level               RedactionLevel `yaml:"level"`
	Input               string         `yaml:"input"`
	Separator           string         `yaml:"separator"`
	Repeat              int            `yaml:"repeat"`
	Passes              int            `yaml:"passes"`
	WantWarnings        int            `yaml:"want_warnings"`
	WantWarningsDropped int            `yaml:"want_warnings_dropped"`
}

func loadResidueScanFixtures(t *testing.T) residueScanFixtureDocument {
	t.Helper()

	var fixtures residueScanFixtureDocument
	if err := yaml.Unmarshal(residueScanFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/residue_scan.yaml while loading residue scan fixtures: %v", err)
	}

	parityIDs := make([]string, len(fixtures.Parity))
	for i, row := range fixtures.Parity {
		parityIDs[i] = row.ID
	}
	limitIDs := make([]string, len(fixtures.Limit))
	for i, row := range fixtures.Limit {
		limitIDs[i] = row.ID
	}
	if err := requireFixtureNames("testdata/residue_scan.yaml", "required_parity_ids", fixtures.RequiredParityIDs, parityIDs); err != nil {
		t.Fatal(err)
	}
	if err := requireFixtureNames("testdata/residue_scan.yaml", "required_limit_ids", fixtures.RequiredLimitIDs, limitIDs); err != nil {
		t.Fatal(err)
	}

	for _, row := range fixtures.Parity {
		checkFixtureLevel(t, row.ID, row.Level)
		if row.Input == "" {
			t.Fatalf("residue scan parity fixture %q has empty input", row.ID)
		}
		if row.Why == "" {
			t.Fatalf("residue scan parity fixture %q has no why; state what the row protects", row.ID)
		}
	}
	for _, row := range fixtures.Limit {
		checkFixtureLevel(t, row.ID, row.Level)
		if row.Input == "" || row.Separator == "" {
			t.Fatalf("residue scan limit fixture %q must define input and separator", row.ID)
		}
		if row.Repeat < 1 || row.Passes < 1 {
			t.Fatalf("residue scan limit fixture %q must repeat and pass at least once", row.ID)
		}
		if row.WantWarnings < 0 || row.WantWarnings > DefaultResidueWarningLimit {
			t.Fatalf("residue scan limit fixture %q wants %d warnings, outside 0..%d", row.ID, row.WantWarnings, DefaultResidueWarningLimit)
		}
		if row.WantWarningsDropped < 0 {
			t.Fatalf("residue scan limit fixture %q has a negative dropped count", row.ID)
		}
	}
	return fixtures
}

// countingResidueDetector wraps a real detector and records how often the
// redactor asks it to scan.
type countingResidueDetector struct {
	inner ResidueDetector
	calls int
}

func (d *countingResidueDetector) Scan(text string) []ResidueWarning {
	d.calls++
	return d.inner.Scan(text)
}

func newResidueScanRedactor(t *testing.T, level RedactionLevel, opts ...Option) *DefaultRedactor {
	t.Helper()
	if level == Maximum && !MaximumAvailable {
		t.Skipf("redact: Maximum level unavailable without cgo; the residue switch is covered at Minimal and Standard")
	}
	r, err := NewRedactor(level, nil, XDGPaths{}, opts...)
	if err != nil {
		t.Fatalf("NewRedactor(%s): %v", level, err)
	}
	return r.(*DefaultRedactor)
}

func TestResidueScan_DisabledSkipsScanAndKeepsOutput(t *testing.T) {
	fixtures := loadResidueScanFixtures(t)
	for _, row := range fixtures.Parity {
		t.Run(row.ID, func(t *testing.T) {
			enabled := newResidueScanRedactor(t, row.Level)
			if enabled.residueDetector == nil {
				t.Fatal("default redactor did not construct a residue detector")
			}
			enabledCounter := &countingResidueDetector{inner: NewResidueDetector()}
			enabled.residueDetector = enabledCounter

			enabledOutput := enabled.RedactText(row.Input)
			if enabledCounter.calls != 1 {
				t.Fatalf("default redactor scanned residue %d times, want 1", enabledCounter.calls)
			}
			enabledReport := enabled.Report()
			if row.WantResidue && len(enabledReport.Warnings) == 0 {
				t.Fatalf("default redactor produced no residue warning for %q", row.Input)
			}
			if !row.WantResidue && len(enabledReport.Warnings) != 0 {
				t.Fatalf("default redactor produced unexpected residue warnings for %q: %v", row.Input, enabledReport.Warnings)
			}
			if enabledReport.WarningsDropped != 0 {
				t.Fatalf("small fixture dropped %d warnings, want 0", enabledReport.WarningsDropped)
			}

			disabled := newResidueScanRedactor(t, row.Level, WithResidue(false))
			if disabled.residueDetector != nil {
				t.Fatal("WithResidue(false) still constructed a residue detector")
			}
			// Inject a counting detector anyway: the constructor flag, not a nil
			// detector, must be what prevents the scan.
			disabledCounter := &countingResidueDetector{inner: NewResidueDetector()}
			disabled.residueDetector = disabledCounter

			disabledOutput := disabled.RedactText(row.Input)
			if disabledCounter.calls != 0 {
				t.Fatalf("WithResidue(false) scanned residue %d times, want 0", disabledCounter.calls)
			}
			if disabledOutput != enabledOutput {
				t.Fatalf("residue switch changed output:\n enabled: %q\ndisabled: %q", enabledOutput, disabledOutput)
			}
			disabledReport := disabled.Report()
			if len(disabledReport.Warnings) != 0 || disabledReport.WarningsDropped != 0 {
				t.Fatalf("WithResidue(false) retained warnings=%v dropped=%d, want none", disabledReport.Warnings, disabledReport.WarningsDropped)
			}
		})
	}
}

func TestResidueScan_WarningLimitBoundsReport(t *testing.T) {
	fixtures := loadResidueScanFixtures(t)
	for _, row := range fixtures.Limit {
		t.Run(row.ID, func(t *testing.T) {
			parts := make([]string, row.Repeat)
			for i := range parts {
				parts[i] = row.Input
			}
			input := strings.Join(parts, row.Separator)

			r := newResidueScanRedactor(t, row.Level)
			for pass := 0; pass < row.Passes; pass++ {
				r.RedactText(input)
			}

			report := r.Report()
			if len(report.Warnings) != row.WantWarnings {
				t.Fatalf("retained %d warning strings, want %d (cap %d)", len(report.Warnings), row.WantWarnings, DefaultResidueWarningLimit)
			}
			if report.WarningsDropped != row.WantWarningsDropped {
				t.Fatalf("dropped count = %d, want %d after %d passes", report.WarningsDropped, row.WantWarningsDropped, row.Passes)
			}
		})
	}
}

// TestResidueScan_LimitIsExported pins the cap the fixture expectations encode,
// so changing the constant is a deliberate, reviewed fixture change.
func TestResidueScan_LimitIsExported(t *testing.T) {
	if DefaultResidueWarningLimit != 256 {
		t.Fatalf("DefaultResidueWarningLimit = %d, want 256; update testdata/residue_scan.yaml in the same change", DefaultResidueWarningLimit)
	}
}

// TestResidueScan_OptionComposesWithScannerBuffers guards that the new
// constructor option does not disturb the existing scanner option plumbing.
func TestResidueScan_OptionComposesWithScannerBuffers(t *testing.T) {
	base, err := NewRedactor(Standard, nil, XDGPaths{}, WithScannerBufSize(1024, 2048))
	if err != nil {
		t.Fatalf("NewRedactor with scanner buffers: %v", err)
	}
	combined, err := NewRedactor(Standard, nil, XDGPaths{}, WithScannerBufSize(1024, 2048), WithResidue(false))
	if err != nil {
		t.Fatalf("NewRedactor with scanner buffers and residue off: %v", err)
	}
	if got := combined.(*DefaultRedactor).scannerConfig; got != base.(*DefaultRedactor).scannerConfig {
		t.Fatalf("WithResidue changed the scanner configuration: got %+v want %+v", got, base.(*DefaultRedactor).scannerConfig)
	}
	if combined.(*DefaultRedactor).residueEnabled {
		t.Fatal("WithResidue(false) did not disable the residue scan")
	}
}
