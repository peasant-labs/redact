//go:build no_re2

package redact

import "testing"

func TestEngineDefaultGoRegexp(t *testing.T) {
	if _, ok := selectEngine().(goRegexpEngine); !ok || selectEngine().Identity() != EngineGoRegexp {
		t.Fatal("no_re2 builds must select go-regexp")
	}
	if EngineIdentity() != EngineGoRegexp {
		t.Fatalf("EngineIdentity() = %q, want %q", EngineIdentity(), EngineGoRegexp)
	}
	r, err := NewRedactor(Standard, nil, XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewTitlePipeline()
	if err != nil {
		t.Fatal(err)
	}
	if r.(*DefaultRedactor).patterns != nil || p.patterns != nil {
		t.Fatal("no_re2 public constructors must reuse the original stdlib patterns")
	}
	if d := NewResidueDetector().(*DefaultResidueDetector); d.patterns != nil {
		t.Fatal("no_re2 NewResidueDetector must reuse the original stdlib patterns")
	}
}
