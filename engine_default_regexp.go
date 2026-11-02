//go:build no_re2

package redact

func selectDefaultEngine() engine { return goRegexpEngine{} }
