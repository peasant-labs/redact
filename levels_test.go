package redact

import "testing"

func TestAllRedactionLevels(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}
	levels := AllRedactionLevels()
	if len(levels) != len(fixtures.ClosedSet) {
		t.Fatalf("AllRedactionLevels has %d entries, want %d", len(levels), len(fixtures.ClosedSet))
	}
	for ordinal, want := range fixtures.ClosedSet {
		got := levels[ordinal]
		if got != want || !got.IsValid() || got.Ord() != ordinal {
			t.Errorf("level enumeration entry %d is inconsistent", ordinal)
		}
	}
}

func TestAllRedactionLevels_ReturnsIndependentCopy(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}

	mutated := AllRedactionLevels()
	mutated[0] = RedactionLevel("changed-by-caller")
	mutated = append(mutated, RedactionLevel("added-by-caller"))

	fresh := AllRedactionLevels()
	if len(fresh) != len(fixtures.ClosedSet) {
		t.Fatalf("caller mutation changed enumeration length to %d", len(fresh))
	}
	for ordinal, want := range fixtures.ClosedSet {
		level := fresh[ordinal]
		if level != want || !level.IsValid() || level.Ord() != ordinal {
			t.Errorf("caller mutation changed canonical level behavior at ordinal %d", ordinal)
		}
		_, constructorErr := NewRedactor(level, nil, XDGPaths{})
		if level == Maximum && !MaximumAvailable {
			if constructorErr == nil {
				t.Errorf("caller mutation bypassed Maximum refusal without cgo")
			}
		} else if constructorErr != nil {
			t.Errorf("caller mutation made constructor reject canonical level at ordinal %d", ordinal)
		}
	}
	if got := Max(Minimal, Standard); got != Standard {
		t.Errorf("caller mutation changed Max(Minimal, Standard)")
	}
	if got := Max(Standard, Maximum); got != Maximum {
		t.Errorf("caller mutation changed Max(Standard, Maximum)")
	}
}

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
