package redact

import "testing"

func TestRedactionLevel_Ord(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}

	for _, fixture := range fixtures.Ord {
		t.Run(fixture.ID, func(t *testing.T) {
			if got := fixture.Level.Ord(); got != fixture.Want {
				t.Errorf("RedactionLevel(%q).Ord() = %d, want %d", fixture.Level, got, fixture.Want)
			}
			if got := fixture.Level.String(); got != fixture.WantString {
				t.Errorf("RedactionLevel(%q).String() = %q, want %q", fixture.Level, got, fixture.WantString)
			}
		})
	}
}

func TestRedactionLevel_Max(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}

	for _, fixture := range fixtures.Max {
		t.Run(fixture.ID, func(t *testing.T) {
			if got := Max(fixture.A, fixture.B); got != fixture.Want {
				t.Errorf("Max(%q, %q) = %q, want %q", fixture.A, fixture.B, got, fixture.Want)
			}
		})
	}
}

func TestRedactionLevel_IsValid(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}

	for _, fixture := range fixtures.Valid {
		t.Run(fixture.ID, func(t *testing.T) {
			if got := fixture.Level.IsValid(); got != fixture.Want {
				t.Errorf("RedactionLevel(%q).IsValid() = %v, want %v", fixture.Level, got, fixture.Want)
			}
		})
	}
}
