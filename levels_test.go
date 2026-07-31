package redact

import "testing"

func TestRedactionLevel_Ord(t *testing.T) {
	tests := []struct {
		name  string
		level RedactionLevel
		want  int
	}{
		{"minimal", Minimal, 0},
		{"standard", Standard, 1},
		{"maximum", Maximum, 2},
		{"unknown", RedactionLevel("bogus"), -1},
		{"empty", RedactionLevel(""), -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.level.Ord(); got != tt.want {
				t.Errorf("RedactionLevel(%q).Ord() = %d, want %d", tt.level, got, tt.want)
			}
		})
	}
}

func TestRedactionLevel_Max(t *testing.T) {
	tests := []struct {
		name string
		a    RedactionLevel
		b    RedactionLevel
		want RedactionLevel
	}{
		{"minimal_vs_standard", Minimal, Standard, Standard},
		{"standard_vs_minimal", Standard, Minimal, Standard},
		{"maximum_vs_standard", Maximum, Standard, Maximum},
		{"standard_vs_maximum", Standard, Maximum, Maximum},
		{"standard_vs_standard", Standard, Standard, Standard},
		{"minimal_vs_minimal", Minimal, Minimal, Minimal},
		{"maximum_vs_maximum", Maximum, Maximum, Maximum},
		{"minimal_vs_maximum", Minimal, Maximum, Maximum},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Max(tt.a, tt.b); got != tt.want {
				t.Errorf("Max(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestRedactionLevel_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		level RedactionLevel
		valid bool
	}{
		{"minimal", Minimal, true},
		{"standard", Standard, true},
		{"maximum", Maximum, true},
		{"empty", RedactionLevel(""), false},
		{"unknown", RedactionLevel("bogus"), false},
		{"capitalized", RedactionLevel("Minimal"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.level.IsValid(); got != tt.valid {
				t.Errorf("RedactionLevel(%q).IsValid() = %v, want %v", tt.level, got, tt.valid)
			}
		})
	}
}
