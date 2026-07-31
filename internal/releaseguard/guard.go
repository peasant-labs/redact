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
	versionCore  = `(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)`
	titlePattern = regexp.MustCompile(`^release\((v` + versionCore + `(?:-rc[1-9][0-9]*)?)\): [^\r\n]+$`)
	tagPattern   = regexp.MustCompile(`^v(` + versionCore + `)(?:-rc([1-9][0-9]*))?$`)
)

func VersionFromTitle(title string) (string, error) {
	match := titlePattern.FindStringSubmatch(title)
	if match == nil {
		return "", fmt.Errorf("release title %q is invalid; use release(vX.Y.Z[-rcN]): summary with a positive rc number", title)
	}
	return match[1], nil
}

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
