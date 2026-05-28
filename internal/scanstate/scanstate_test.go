package scanstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFingerprint_OrderIndependent(t *testing.T) {
	a := Fingerprint([]string{"linux-passwd", "php-config", "ssh-key"})
	b := Fingerprint([]string{"ssh-key", "linux-passwd", "php-config"})
	if a != b {
		t.Fatalf("fingerprint not order-independent: %q vs %q", a, b)
	}
}

func TestFingerprint_ContentSensitive(t *testing.T) {
	a := Fingerprint([]string{"linux-passwd", "php-config"})
	b := Fingerprint([]string{"linux-passwd", "php-config", "extra-entry"})
	if a == b {
		t.Fatal("fingerprint should change when entry set changes")
	}
}

func TestFingerprint_NoDelimiterCollision(t *testing.T) {
	// "ab"+"c" must not hash the same as "a"+"bc".
	a := Fingerprint([]string{"ab", "c"})
	b := Fingerprint([]string{"a", "bc"})
	if a == b {
		t.Fatal("delimiter collision: distinct id sets produced identical fingerprints")
	}
}

func TestLoad_FreshWhenMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	s, err := Load(path, "http://t/?f=FUZZ", "FUZZ", "fp1")
	if err != nil {
		t.Fatalf("Load fresh: %v", err)
	}
	if s.AttemptedCount() != 0 {
		t.Fatalf("fresh state should have 0 attempted, got %d", s.AttemptedCount())
	}
	if s.Attempted("anything") {
		t.Fatal("fresh state should not report any entry attempted")
	}
}

func TestRecord_PersistsAndSkips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	s, err := Load(path, "http://t/?f=FUZZ", "FUZZ", "fp1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if err := s.Record("entry-a", nil); err != nil {
		t.Fatalf("Record entry-a: %v", err)
	}
	if err := s.Record("entry-b", &Hit{EntryID: "entry-b", Path: "/etc/passwd", Technique: "dotdot", Status: 200}); err != nil {
		t.Fatalf("Record entry-b: %v", err)
	}

	// Reload from disk: attempted set and hits must survive.
	s2, err := Load(path, "http://t/?f=FUZZ", "FUZZ", "fp1")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !s2.Attempted("entry-a") || !s2.Attempted("entry-b") {
		t.Fatal("reloaded state lost attempted entries")
	}
	if s2.Attempted("entry-c") {
		t.Fatal("reloaded state reports never-attempted entry as attempted")
	}
	if s2.AttemptedCount() != 2 {
		t.Fatalf("attempted count = %d, want 2", s2.AttemptedCount())
	}
	hits := s2.Hits()
	if len(hits) != 1 || hits[0].EntryID != "entry-b" || hits[0].Path != "/etc/passwd" {
		t.Fatalf("hits not persisted correctly: %+v", hits)
	}
}

func TestRecord_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	s, _ := Load(path, "t", "FUZZ", "fp1")
	_ = s.Record("dup", nil)
	_ = s.Record("dup", nil)
	if s.AttemptedCount() != 1 {
		t.Fatalf("duplicate Record should not double-count: got %d", s.AttemptedCount())
	}
	if len(s.AttemptedEntryIDs) != 1 {
		t.Fatalf("AttemptedEntryIDs has duplicates: %v", s.AttemptedEntryIDs)
	}
}

func TestLoad_RefusesTargetMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	s, _ := Load(path, "http://old/?f=FUZZ", "FUZZ", "fp1")
	_ = s.Record("e1", nil)

	_, err := Load(path, "http://new/?f=FUZZ", "FUZZ", "fp1")
	if err == nil {
		t.Fatal("expected refusal on target mismatch")
	}
	if !strings.Contains(err.Error(), "targets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_RefusesMarkerMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	s, _ := Load(path, "t", "FUZZ", "fp1")
	_ = s.Record("e1", nil)

	_, err := Load(path, "t", "INJECT", "fp1")
	if err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("expected marker-mismatch refusal, got: %v", err)
	}
}

func TestLoad_RefusesDBMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	s, _ := Load(path, "t", "FUZZ", "fp1")
	_ = s.Record("e1", nil)

	_, err := Load(path, "t", "FUZZ", "fp2")
	if err == nil || !strings.Contains(err.Error(), "database") {
		t.Fatalf("expected db-mismatch refusal, got: %v", err)
	}
}

func TestLoad_RefusesNewerFormatVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	future := map[string]any{
		"format_version": FormatVersion + 1,
		"target":         "t",
		"marker":         "FUZZ",
		"db_fingerprint": "fp1",
	}
	data, _ := json.Marshal(future)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path, "t", "FUZZ", "fp1")
	if err == nil || !strings.Contains(err.Error(), "format_version") {
		t.Fatalf("expected format-version refusal, got: %v", err)
	}
}

func TestLoad_RejectsCorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resume.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, "t", "FUZZ", "fp1")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("expected parse error, got: %v", err)
	}
}

func TestFlush_AtomicNoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resume.json")
	s, _ := Load(path, "t", "FUZZ", "fp1")
	if err := s.Record("e1", nil); err != nil {
		t.Fatalf("Record: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-resume-") {
			t.Fatalf("temp file leaked after atomic flush: %s", e.Name())
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("final resume file missing: %v", err)
	}
}
