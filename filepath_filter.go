package redact

// FilePathFilter reports whether entropy detection should be suppressed for a
// given source file path. This interface exists as an architectural anchor for
// future integration: once the transcript schema exposes per-turn source paths,
// wire this into detectEntropyInWords to skip entropy scanning on lock files
// (e.g. package-lock.json, go.sum, yarn.lock) and generated files (e.g. swagger.json).
// See URD R8 (unified-schema-kak3).
type FilePathFilter interface {
	SuppressEntropy(sourcePath string) bool
}

// NoopFilePathFilter is the current production implementation.
// It always returns false, meaning entropy detection runs unconditionally.
// Replace with a path-aware implementation when per-turn source paths are available.
type NoopFilePathFilter struct{}

func (NoopFilePathFilter) SuppressEntropy(_ string) bool { return false }

var _ FilePathFilter = NoopFilePathFilter{}
