package db

import (
	"strings"
	"testing"
)

func TestValidate_Clean(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	errs := Validate(db)
	for _, e := range errs {
		t.Errorf("unexpected validation error: %v", e)
	}
}

func TestValidate_BadInfoGoal(t *testing.T) {
	db, err := loadSingleFixture(t, "testdata/broken/bad-enum.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	errs := Validate(db)
	if !anyContains(errs, "info_goal") {
		t.Errorf("expected info_goal error, got: %v", errs)
	}
}

func TestValidate_MissingDescription(t *testing.T) {
	db, err := loadSingleFixture(t, "testdata/broken/missing-required.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	errs := Validate(db)
	if !anyContains(errs, "description") {
		t.Errorf("expected description error, got: %v", errs)
	}
}

func TestValidate_ReturnsAllErrors(t *testing.T) {
	// bad-enum.yaml has an invalid info_goal.
	// We ensure it finds at least the info_goal error without stopping.
	db, err := loadSingleFixture(t, "testdata/broken/bad-enum.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	errs := Validate(db)
	if len(errs) == 0 {
		t.Error("expected at least one validation error")
	}
}

func TestValidate_ValidEntry_NoErrors(t *testing.T) {
	// Build a minimal valid entry in-memory.
	db := newDatabase()
	minTraversal := 0
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:          "test-valid",
			Name:        "Test Valid",
			Description: "A valid entry for testing.",
			Path:        "/etc/test",
			OS:          []string{"linux"},
			InfoGoal:    InfoGoalConfig,
			Privilege:   PrivilegeAny,
			Confirm: Confirm{
				Type:     ConfirmTypeKeyword,
				Patterns: []string{"test"},
			},
			MinTraversal: &minTraversal,
		},
		SourceFile: "test",
		GroupID:    "test-group",
	})
	errs := Validate(db)
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid entry, got: %v", errs)
	}
}

func TestValidate_InvalidID_SpecialChars(t *testing.T) {
	db := newDatabase()
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:          "INVALID_ID",
			Name:        "Test",
			Description: "desc",
			Path:        "/etc/test",
			OS:          []string{"linux"},
			InfoGoal:    InfoGoalConfig,
			Privilege:   PrivilegeAny,
			Confirm:     Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"x"}},
		},
		SourceFile: "test",
	})
	errs := Validate(db)
	if !anyContains(errs, "id") {
		t.Errorf("expected id validation error, got: %v", errs)
	}
}

func TestValidate_InvalidPrivilege(t *testing.T) {
	db := newDatabase()
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:          "test-priv",
			Name:        "Test",
			Description: "desc",
			Path:        "/etc/test",
			OS:          []string{"linux"},
			InfoGoal:    InfoGoalConfig,
			Privilege:   "super-root",
			Confirm:     Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"x"}},
		},
		SourceFile: "test",
	})
	errs := Validate(db)
	if !anyContains(errs, "privilege") {
		t.Errorf("expected privilege error, got: %v", errs)
	}
}

func TestValidate_EmptyConfirmPatterns(t *testing.T) {
	db := newDatabase()
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:          "test-confirm",
			Name:        "Test",
			Description: "desc",
			Path:        "/etc/test",
			OS:          []string{"linux"},
			InfoGoal:    InfoGoalConfig,
			Privilege:   PrivilegeAny,
			Confirm:     Confirm{Type: ConfirmTypeKeyword, Patterns: nil},
		},
		SourceFile: "test",
	})
	errs := Validate(db)
	if !anyContains(errs, "confirm") {
		t.Errorf("expected confirm.patterns error, got: %v", errs)
	}
}

func TestValidate_InvalidOS(t *testing.T) {
	db := newDatabase()
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:          "test-os",
			Name:        "Test",
			Description: "desc",
			Path:        "/etc/test",
			OS:          []string{"amiga"},
			InfoGoal:    InfoGoalConfig,
			Privilege:   PrivilegeAny,
			Confirm:     Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"x"}},
		},
		SourceFile: "test",
	})
	errs := Validate(db)
	if !anyContains(errs, "os") {
		t.Errorf("expected os error, got: %v", errs)
	}
}

func TestValidate_NegativeMinTraversal(t *testing.T) {
	neg := -1
	db := newDatabase()
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:           "test-mt",
			Name:         "Test",
			Description:  "desc",
			Path:         "/etc/test",
			OS:           []string{"linux"},
			InfoGoal:     InfoGoalConfig,
			Privilege:    PrivilegeAny,
			Confirm:      Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"x"}},
			MinTraversal: &neg,
		},
		SourceFile: "test",
	})
	errs := Validate(db)
	if !anyContains(errs, "min_traversal") {
		t.Errorf("expected min_traversal error, got: %v", errs)
	}
}

func TestValidate_RelativePath_Unix(t *testing.T) {
	db := newDatabase()
	db.entries = append(db.entries, CompiledEntry{
		Entry: Entry{
			ID:          "test-relpath",
			Name:        "Test",
			Description: "desc",
			Path:        "etc/passwd", // relative — should fail
			OS:          []string{"linux"},
			InfoGoal:    InfoGoalConfig,
			Privilege:   PrivilegeAny,
			Confirm:     Confirm{Type: ConfirmTypeKeyword, Patterns: []string{"x"}},
		},
		SourceFile: "test",
	})
	errs := Validate(db)
	if !anyContains(errs, "path") {
		t.Errorf("expected path error for relative unix path, got: %v", errs)
	}
}

func anyContains(errs []ValidationError, field string) bool {
	for _, e := range errs {
		if strings.Contains(e.Field, field) || strings.Contains(e.Message, field) {
			return true
		}
	}
	return false
}
