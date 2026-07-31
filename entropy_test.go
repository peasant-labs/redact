package redact

import (
	"math"
	"strings"
	"testing"
)

func TestEntropyBehavior(t *testing.T) {
	fixtures, err := loadEntropyFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixtures.Behavior {
		t.Run(tc.ID, func(t *testing.T) {
			r := mustNewRedactor(t, tc.Level, nil)
			got := r.RedactText(tc.Input)
			if redacted := strings.Contains(got, "<HIGH_ENTROPY>"); redacted != tc.Redacted {
				t.Errorf("RedactText(%q) = %q, high-entropy redacted=%t, want %t (entropy=%.2f)", tc.Input, got, redacted, tc.Redacted, shannonEntropy(tc.Input))
			}
		})
	}
}

func TestShannonEntropyFormula(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("shannonEntropy(empty) = %f, want 0", got)
	}
	if got := shannonEntropy("aaaa"); got != 0 {
		t.Errorf("shannonEntropy(repeated character) = %f, want 0", got)
	}
	if got := shannonEntropy("abababab"); got < 0.99 || got > 1.01 {
		t.Errorf("shannonEntropy(equal two-character distribution) = %f, want approximately 1.0", got)
	}
}

func TestEntropyPrefilters(t *testing.T) {
	fixtures, err := loadEntropyFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixtures.Prefilters {
		t.Run(tc.ID, func(t *testing.T) {
			var got bool
			switch tc.Family {
			case entropyFamilyUUID:
				got = isPotentialUUID(tc.Input)
			case entropyFamilySequential:
				got = isSequentialString(tc.Input)
			case entropyFamilyDollarPrefix:
				got = isPrefixedWithDollarSign(tc.Input)
			}
			if got != tc.Matched {
				t.Errorf("%s prefilter(%q) = %t, want %t", tc.Family, tc.Input, got, tc.Matched)
			}
			if tc.DetectUnchanged && detectEntropy(tc.Input) != tc.Input {
				t.Errorf("detectEntropy(%q) changed a token accepted by the %s prefilter", tc.Input, tc.Family)
			}
		})
	}
}

func TestCharsetEntropyThresholds(t *testing.T) {
	fixtures, err := loadEntropyFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixtures.CharsetEntropy {
		t.Run(tc.ID, func(t *testing.T) {
			charset, threshold := b64Charset, b64Threshold
			if tc.Family == entropyFamilyHex {
				charset, threshold = hexCharset, hexThreshold
			}
			entropy := shannonEntropyOverCharset(tc.Input, charset)
			if tc.ThresholdRelation == entropyThresholdAbove && entropy <= threshold {
				t.Fatalf("fixture precondition: %s entropy %.4f must exceed %.1f", tc.Family, entropy, threshold)
			}
			if tc.ThresholdRelation == entropyThresholdBelow && entropy >= threshold {
				t.Fatalf("fixture precondition: %s entropy %.4f must be below %.1f", tc.Family, entropy, threshold)
			}
			got := detectEntropy(tc.Input)
			if redacted := got == "<HIGH_ENTROPY>"; redacted != tc.DetectRedacted {
				t.Errorf("detectEntropy(%q) = %q, redacted=%t, want %t", tc.Input, got, redacted, tc.DetectRedacted)
			}
		})
	}
}

func TestHexAllDigitPenalty(t *testing.T) {
	s := "0123456789"
	rawHex := shannonEntropyOverCharset(s, hexCharset)
	penalty := 1.2 / math.Log2(float64(len(s)))
	effective := rawHex - penalty
	if effective >= hexThreshold {
		t.Errorf("all-digit penalty for %q: raw=%.4f penalty=%.4f effective=%.4f, want effective below %.1f", s, rawHex, penalty, effective, hexThreshold)
	}
}

func TestShannonEntropyOverCharsetIdenticalCharacters(t *testing.T) {
	if got := shannonEntropyOverCharset("aaaaaa", hexCharset); got != 0.0 {
		t.Errorf("shannonEntropyOverCharset(identical hex characters) = %.4f, want 0.0", got)
	}
}

func TestNoopFilePathFilterNeverSuppresses(t *testing.T) {
	fixtures, err := loadEntropyFixtures()
	if err != nil {
		t.Fatal(err)
	}
	f := NoopFilePathFilter{}
	for _, tc := range fixtures.Paths {
		t.Run(tc.ID, func(t *testing.T) {
			if f.SuppressEntropy(tc.Path) {
				t.Errorf("NoopFilePathFilter.SuppressEntropy(%q) = true, want false", tc.Path)
			}
		})
	}
}

func TestEntropyFixtureIdentityValidation(t *testing.T) {
	fixtures, err := loadEntropyFixtures()
	if err != nil {
		t.Fatal(err)
	}
	fixtures.Behavior[0].ID = ""
	if err := validateEntropyFixtures(fixtures); err == nil || !strings.Contains(err.Error(), "empty id") {
		t.Fatalf("empty fixture identity validation error = %v, want actionable empty-id rejection", err)
	}

	fixtures, err = loadEntropyFixtures()
	if err != nil {
		t.Fatal(err)
	}
	fixtures.Paths[0].ID = fixtures.Prefilters[0].ID
	if err := validateEntropyFixtures(fixtures); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("duplicate fixture identity validation error = %v, want actionable duplicate-id rejection", err)
	}
}
