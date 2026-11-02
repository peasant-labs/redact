//go:build no_re2

package redact

import "testing"

func TestEngineDefaultGoRegexp(t *testing.T) {
	if _, ok := selectEngine().(goRegexpEngine); !ok || selectEngine().Identity() != engineGoRegexp {
		t.Fatal("no_re2 builds must select go-regexp")
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
}
