package releaseguard

import (
	"fmt"
	"regexp"
)

type Kind string

const (
	Prerelease Kind = "prerelease"
	Final      Kind = "final"
)

var (
	versionCore = `(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)`
	tagPattern  = regexp.MustCompile(`^v(` + versionCore + `)(?:-rc([1-9][0-9]*))?$`)
)

// ClassifyTag reports whether a release tag names a prerelease or a final
// version, and returns the tag's bare version prefix. The title grammar moved
// to the shared release-intent tool; only the tag classifier stays local
// because the tag-triggered release workflow uses it.

func ClassifyTag(tag string) (Kind, string, error) {
	match := tagPattern.FindStringSubmatch(tag)
	if match == nil {
		return "", "", fmt.Errorf("release tag %q is invalid; use vX.Y.Z or vX.Y.Z-rcN with a positive rc number", tag)
	}
	if match[5] != "" {
		return Prerelease, "v" + match[1], nil
	}
	return Final, "v" + match[1], nil
}
