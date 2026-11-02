//go:build !no_re2

package redact

import (
	_ "embed"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_benchmark.yaml
var engineBenchmarkData []byte

var (
	engineBenchmarkRedactor Redactor
	engineBenchmarkMatches  []Match
)

func BenchmarkRedactorConstruction(b *testing.B) {
	benchmarkEngines(b, func(b *testing.B, e engine) {
		b.ReportAllocs()
		for b.Loop() {
			r, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{})
			if err != nil {
				b.Fatal(err)
			}
			engineBenchmarkRedactor = r
		}
	})
}

func BenchmarkFirstDetection(b *testing.B) {
	var fixture struct {
		Input string `yaml:"input"`
	}
	if err := yaml.Unmarshal(engineBenchmarkData, &fixture); err != nil {
		b.Fatal(err)
	}
	if fixture.Input == "" {
		b.Fatal("restore the synthetic input in testdata/engine_benchmark.yaml before measuring first detection")
	}
	benchmarkEngines(b, func(b *testing.B, e engine) {
		b.ReportAllocs()
		for b.Loop() {
			r, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{})
			if err != nil {
				b.Fatal(err)
			}
			engineBenchmarkMatches = r.Detect(fixture.Input)
		}
	})
}

func benchmarkEngines(b *testing.B, run func(*testing.B, engine)) {
	b.Helper()
	for _, name := range AllEngines() {
		var e engine
		switch name {
		case engineGoRegexp:
			e = goRegexpEngine{}
		case engineGoRE2:
			e = goRE2Engine{}
		default:
			b.Fatalf("add benchmark construction for registered engine %q", name)
		}
		b.Run(string(name), func(b *testing.B) { run(b, e) })
	}
}
