//go:build !no_re2

package redact

import re2 "github.com/wasilibs/go-re2"

// goRE2Engine uses the dependency's pure-Go WASM translation; it does not
// require cgo. no_re2 excludes the adapter and its dependency from the build.
type goRE2Engine struct{}

func selectDefaultEngine() engine { return goRE2Engine{} }

func (goRE2Engine) Compile(pattern string) (compiled, error) {
	re, err := re2.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return re, nil
}
func (goRE2Engine) Identity() engineName { return engineGoRE2 }

var _ engine = goRE2Engine{}
var _ compiled = (*re2.Regexp)(nil)
