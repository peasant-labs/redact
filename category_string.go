package redact

import "fmt"

// CategoryString is the canonical rendered form of a redaction category. It is
// shared by API responses, generated fixtures, and any other consumer that
// needs stable category labels.
type CategoryString string

const (
	CategoryStringCredential CategoryString = "CREDENTIAL"
	CategoryStringPII        CategoryString = "PII"
	CategoryStringPath       CategoryString = "PATH"
	CategoryStringInternal   CategoryString = "INTERNAL"
)

func (s CategoryString) String() string { return string(s) }

// String returns the category's canonical rendered form. Invalid categories
// return the zero value, never a valid fallback. Call Validate at trust
// boundaries before rendering values that did not originate in this package.
func (c Category) String() CategoryString {
	switch c {
	case CategorySecrets:
		return CategoryStringCredential
	case CategoryPII:
		return CategoryStringPII
	case CategoryPaths:
		return CategoryStringPath
	case CategoryProject:
		return CategoryStringInternal
	default:
		return ""
	}
}

// Validate rejects category values outside the canonical enumeration with an
// actionable error. Consumers should call it before String at trust boundaries.
func (c Category) Validate() error {
	if c.IsValid() {
		return nil
	}
	return &actionableError{
		what:  fmt.Sprintf("redaction category %q has no canonical category string", c),
		why:   "every semantic redaction category must map to exactly one canonical rendered category",
		where: "redact.Category.Validate",
		when:  "validating a redaction category before rendering it for a consumer",
		means: "the caller must stop rather than silently mislabel sensitive content",
		fix:   "add the Category.String mapping and matching consumer category member, then update testdata/category_strings.yaml",
	}
}
