package redact

import (
	"errors"
	"testing"
)

func TestEngineDefaultRemainsStdlib(t *testing.T) {
	r, err := NewRedactor(Standard, nil, XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	defaultRedactor := r.(*DefaultRedactor)
	if defaultRedactor.engineName != engineGoRegexp || defaultRedactor.patterns != nil {
		t.Fatal("NewRedactor must reuse the original stdlib patterns by default")
	}
	if selectEngine().Identity() != engineGoRegexp || engineGoRegexp != "go-regexp" || engineGoRE2 != "go-re2" {
		t.Fatal("engine identities or stdlib default changed")
	}
}

type rejectingEngine struct {
	goRegexpEngine
	err error
}

func (e rejectingEngine) Compile(string) (compiled, error) { return nil, e.err }

func TestEngineCompileFailureRefusesConstruction(t *testing.T) {
	cause := errors.New("engine compiler unavailable")
	e := rejectingEngine{err: cause}
	if r, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{}); r != nil || !errors.Is(err, cause) {
		t.Fatalf("redactor = %v, %v; want no partial redactor and wrapped compiler error", r, err)
	}
	if p, err := newTitlePipelineWithEngine(e); p != nil || !errors.Is(err, cause) {
		t.Fatalf("title pipeline = %v, %v; want no partial pipeline and wrapped compiler error", p, err)
	}
}
