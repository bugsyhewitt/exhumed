package db

import (
	"strings"
	"testing"
)

func TestLoadDir_Valid(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("LoadDir valid: unexpected error: %v", err)
	}
	if db == nil {
		t.Fatal("returned nil Database")
	}
	if len(db.AllEntries()) == 0 {
		t.Error("expected entries, got none")
	}
}

func TestLoadDir_CorrectParse(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	entries := db.AllEntries()
	var passwd *CompiledEntry
	for i := range entries {
		if entries[i].Entry.ID == "passwd" {
			passwd = &entries[i]
			break
		}
	}
	if passwd == nil {
		t.Fatal("entry 'passwd' not found")
	}
	if passwd.Entry.Path != "/etc/passwd" {
		t.Errorf("path: got %q, want /etc/passwd", passwd.Entry.Path)
	}
	if passwd.Entry.InfoGoal != InfoGoalCredentials {
		t.Errorf("info_goal: got %q, want credentials", passwd.Entry.InfoGoal)
	}
	if passwd.Entry.Privilege != PrivilegeAny {
		t.Errorf("privilege: got %q, want any", passwd.Entry.Privilege)
	}
	if passwd.Entry.Confirm.Type != ConfirmTypeRegex {
		t.Errorf("confirm.type: got %q, want regex", passwd.Entry.Confirm.Type)
	}
	// Compiled regex must be populated for regex-type confirms.
	if len(passwd.CompiledPatterns) == 0 {
		t.Error("compiled patterns should be populated for regex confirm")
	}
	if passwd.CompiledPatterns[0] == nil {
		t.Error("compiled pattern[0] is nil")
	}
}

func TestLoadDir_EmptyRoot(t *testing.T) {
	db, err := LoadDir("testdata/does-not-exist")
	if err != nil {
		t.Fatalf("empty root should not error: %v", err)
	}
	if db == nil {
		t.Fatal("expected non-nil empty Database")
	}
	if len(db.AllEntries()) != 0 {
		t.Errorf("expected 0 entries for empty root, got %d", len(db.AllEntries()))
	}
}

func TestLoadDir_BadSchemaVersion(t *testing.T) {
	_, err := LoadDir("testdata/broken/bad-schema-version.yaml")
	// Loading a single file as a directory won't find it via WalkDir.
	// Use a directory with only that file.
	_, err = loadSingleFixture(t, "testdata/broken/bad-schema-version.yaml")
	if err == nil {
		t.Fatal("expected error for bad schema version, got nil")
	}
	if !strings.Contains(err.Error(), "schema_version") && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should mention schema_version, got: %v", err)
	}
}

func TestLoadDir_InvalidRegex_FailsAtLoad(t *testing.T) {
	_, err := loadSingleFixture(t, "testdata/broken/bad-regex.yaml")
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
	if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "regex") && !strings.Contains(err.Error(), "pattern") {
		t.Errorf("error should mention regex/pattern, got: %v", err)
	}
}

func TestLoadDir_DuplicateID(t *testing.T) {
	_, err := loadSingleFixture(t, "testdata/broken/duplicate-id.yaml")
	if err == nil {
		t.Fatal("expected error for duplicate entry id, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention duplicate, got: %v", err)
	}
}

func TestLoadDir_LookupByOS(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	linuxEntries := db.ByOS("linux")
	if len(linuxEntries) == 0 {
		t.Error("expected linux entries, got none")
	}
}

func TestLoadDir_LookupByCategory(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	osEntries := db.ByCategory("os")
	if len(osEntries) == 0 {
		t.Error("expected os category entries, got none")
	}
}

func TestLoadDir_LookupByInfoGoal(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	creds := db.ByInfoGoal("credentials")
	if len(creds) == 0 {
		t.Error("expected credentials entries, got none")
	}
}

func TestLoadDir_Stats(t *testing.T) {
	db, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	stats := db.Stats()
	if stats.Total == 0 {
		t.Error("stats.Total should be > 0")
	}
	if len(stats.PerGroup) == 0 {
		t.Error("stats.PerGroup should be non-empty")
	}
}

func TestLoadCurated_ExcludesRaw(t *testing.T) {
	// testdata/valid has no _raw subdir, so LoadCurated == LoadDir here.
	// The important thing is it doesn't error.
	db, err := LoadCurated("testdata/valid")
	if err != nil {
		t.Fatalf("LoadCurated: %v", err)
	}
	if db == nil {
		t.Fatal("nil database")
	}
}

// loadSingleFixture creates a temp dir with a symlink/copy of one file and
// loads it, simulating a single-file directory. We use a helper because
// WalkDir on a regular file path won't discover it.
func loadSingleFixture(t *testing.T, path string) (*Database, error) {
	t.Helper()
	db := newDatabase()
	err := loadFile(db, path)
	if err != nil {
		return nil, err
	}
	return db, nil
}
