package redact

import (
	"fmt"
	"strings"
)

// actionableError describes a failure in terms the caller can diagnose and fix.
// It is internal implementation machinery rather than part of the public redact
// API. cause is optional and remains available through errors.Is/errors.As.
type actionableError struct {
	what  string
	why   string
	where string
	when  string
	means string
	fix   string
	cause error
}

func (e *actionableError) Error() string {
	if e == nil {
		return "<nil>"
	}
	parts := []string{
		fmt.Sprintf("what: %s", e.what),
		fmt.Sprintf("why: %s", e.why),
		fmt.Sprintf("where: %s", e.where),
		fmt.Sprintf("when: %s", e.when),
		fmt.Sprintf("means: %s", e.means),
		fmt.Sprintf("fix: %s", e.fix),
	}
	if e.cause != nil {
		parts = append(parts, fmt.Sprintf("cause: %s", e.cause))
	}
	return strings.Join(parts, "\n")
}

func (e *actionableError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}
