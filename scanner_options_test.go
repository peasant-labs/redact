package redact_test

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/peasant-labs/redact"
	"gopkg.in/yaml.v3"
)

//go:embed testdata/scanner_options.yaml
var scannerOptionsYAML []byte

type scannerOptionFixture struct {
	Name                 string `yaml:"name"`
	ConstructorInit      int    `yaml:"constructor_init"`
	ConstructorMax       int    `yaml:"constructor_max"`
	ConstructorExplicit  bool   `yaml:"constructor_explicit"`
	CallInit             int    `yaml:"call_init"`
	CallMax              int    `yaml:"call_max"`
	CallExplicit         bool   `yaml:"call_explicit"`
	PayloadSize          int    `yaml:"payload_size"`
	WantConstructorError bool   `yaml:"want_constructor_error"`
	WantError            bool   `yaml:"want_error"`
}

func loadScannerOptionFixtures(t *testing.T) []scannerOptionFixture {
	t.Helper()
	var fixtures []scannerOptionFixture
	if err := yaml.Unmarshal(scannerOptionsYAML, &fixtures); err != nil {
		t.Fatalf("load scanner option fixtures: %v", err)
	}
	if len(fixtures) != 11 {
		t.Fatalf("scanner option fixture count = %d, want 11", len(fixtures))
	}
	seen := make(map[string]struct{}, len(fixtures))
	for _, fixture := range fixtures {
		if fixture.Name == "" {
			t.Fatal("scanner option fixture has empty name")
		}
		if _, duplicate := seen[fixture.Name]; duplicate {
			t.Fatalf("duplicate scanner option fixture %q", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
	}
	return fixtures
}

func TestScannerOptions(t *testing.T) {
	if redact.DefaultScannerInitBuf != 64*1024 || redact.DefaultScannerMaxLine != 10*1024*1024 {
		t.Fatalf("scanner defaults changed: initial=%d maximum=%d", redact.DefaultScannerInitBuf, redact.DefaultScannerMaxLine)
	}
	for _, fixture := range loadScannerOptionFixtures(t) {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			var constructorOptions []redact.Option
			if fixture.ConstructorExplicit || fixture.ConstructorInit != 0 || fixture.ConstructorMax != 0 {
				constructorOptions = append(constructorOptions, redact.WithScannerBufSize(fixture.ConstructorInit, fixture.ConstructorMax))
			}
			r, err := redact.NewRedactor(redact.Standard, nil, redact.XDGPaths{}, constructorOptions...)
			if fixture.WantConstructorError {
				assertActionableScannerError(t, err)
				return
			}
			if err != nil {
				t.Fatalf("NewRedactor: %v", err)
			}
			payload := []byte(fmt.Sprintf("{\"message\":\"%s\"}\n", strings.Repeat("x", fixture.PayloadSize)))
			var callOptions []redact.RedactJSONLBytesOption
			if fixture.CallExplicit || fixture.CallInit != 0 || fixture.CallMax != 0 {
				callOptions = append(callOptions, redact.WithRedactScannerBufSize(fixture.CallInit, fixture.CallMax))
			}
			got, err := redact.RedactJSONLBytes(r, payload, callOptions...)
			if fixture.WantError {
				assertActionableScannerError(t, err)
				if !bytes.Equal(got, payload) {
					t.Fatal("failed scan did not preserve the exact original bytes")
				}
				return
			}
			if err != nil {
				t.Fatalf("RedactJSONLBytes: %v", err)
			}
			if len(got) == 0 {
				t.Fatal("successful scan returned empty output")
			}
		})
	}
}

func TestScannerOptionsRejectNilAndRemainIsolated(t *testing.T) {
	if _, err := redact.NewRedactor(redact.Standard, nil, redact.XDGPaths{}, nil); err == nil {
		t.Fatal("NewRedactor accepted a nil option")
	} else {
		assertActionableScannerError(t, err)
	}
	r, err := redact.NewRedactor(redact.Standard, nil, redact.XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("{\"message\":\"safe\"}\n")
	if got, err := redact.RedactJSONLBytes(r, payload, nil); err == nil || !bytes.Equal(got, payload) {
		t.Fatal("RedactJSONLBytes did not reject nil option while preserving input")
	} else {
		assertActionableScannerError(t, err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(limit int) {
			defer wg.Done()
			got, callErr := redact.RedactJSONLBytes(r, payload, redact.WithRedactScannerBufSize(1, limit))
			if callErr != nil || len(got) == 0 {
				t.Errorf("isolated concurrent option failed: %v", callErr)
			}
		}(1024 + i)
	}
	wg.Wait()
}

func assertActionableScannerError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected scanner configuration error")
	}
	for _, field := range []string{"what:", "why:", "where:", "when:", "means:", "fix:"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error %q lacks actionable field %q", err, field)
		}
	}
}
