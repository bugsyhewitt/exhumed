package feed_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/feed"
)

// ── Manifest parse/serialize ──────────────────────────────────────────────────

func TestManifest_RoundTrip(t *testing.T) {
	m := feed.Manifest{
		SchemaVersion: 1,
		DBVersion:     "2026-05-17",
		Files: []feed.FileEntry{
			{Name: "linux-os.yaml", SHA256: "abc123"},
			{Name: "linux-proc.yaml", SHA256: "def456"},
		},
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m2 feed.Manifest
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m2.DBVersion != m.DBVersion {
		t.Errorf("version mismatch: got %q, want %q", m2.DBVersion, m.DBVersion)
	}
	if len(m2.Files) != len(m.Files) {
		t.Errorf("file count: got %d, want %d", len(m2.Files), len(m.Files))
	}
}

// ── Checksum verification ─────────────────────────────────────────────────────

func TestUpdate_GoodChecksum(t *testing.T) {
	dir := t.TempDir()
	content := []byte("linux-os yaml content here\nname: test\n")
	hash := sha256hex(content)

	// Write a "remote" feed directory.
	feedDir := t.TempDir()
	writeFile(t, filepath.Join(feedDir, "linux-os.yaml"), content)
	m := feed.Manifest{
		SchemaVersion: 1,
		DBVersion:     "2026-05-17",
		Files:         []feed.FileEntry{{Name: "linux-os.yaml", SHA256: hash}},
	}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	// Serve via httptest.
	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{
		FeedURL:         srv.URL + "/manifest.json",
		CacheDir:        dir,
		SupportedSchema: 1,
	}
	changed, err := feed.Update(cfg)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if !changed {
		t.Error("expected Update to report a change (first install)")
	}
	// Verify the file was written to cache dir.
	if _, err := os.Stat(filepath.Join(dir, "linux-os.yaml")); err != nil {
		t.Errorf("expected linux-os.yaml in cache dir: %v", err)
	}
}

func TestUpdate_TamperedFileFails(t *testing.T) {
	dir := t.TempDir()
	content := []byte("legitimate content")
	tampered := []byte("TAMPERED content")
	hash := sha256hex(content) // hash of legitimate, but we'll serve tampered

	feedDir := t.TempDir()
	writeFile(t, filepath.Join(feedDir, "linux-os.yaml"), tampered) // wrong content
	m := feed.Manifest{
		SchemaVersion: 1,
		DBVersion:     "2026-05-17",
		Files:         []feed.FileEntry{{Name: "linux-os.yaml", SHA256: hash}},
	}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{
		FeedURL:         srv.URL + "/manifest.json",
		CacheDir:        dir,
		SupportedSchema: 1,
	}
	_, err := feed.Update(cfg)
	if err == nil {
		t.Fatal("expected checksum verification to fail, got nil error")
	}
	if !strings.Contains(err.Error(), "checksum") && !strings.Contains(err.Error(), "sha256") && !strings.Contains(err.Error(), "hash") {
		t.Errorf("expected checksum-related error, got: %v", err)
	}
	// Existing DB must be untouched (file should not exist in cache after failure).
	if _, err := os.Stat(filepath.Join(dir, "linux-os.yaml")); err == nil {
		t.Error("tampered file should NOT have been written to cache on checksum failure")
	}
}

// ── Atomic swap: no partial state on failure ──────────────────────────────────

func TestUpdate_AtomicSwap_NoPartialState(t *testing.T) {
	dir := t.TempDir()
	// Existing valid file in cache.
	existingContent := []byte("original valid content")
	writeFile(t, filepath.Join(dir, "linux-os.yaml"), existingContent)

	// Feed has two files: first is valid, second is tampered.
	goodContent := []byte("new good content")
	badContent := []byte("bad content")
	goodHash := sha256hex(goodContent)
	wrongHash := sha256hex([]byte("different from badContent"))

	feedDir := t.TempDir()
	writeFile(t, filepath.Join(feedDir, "linux-os.yaml"), goodContent)
	writeFile(t, filepath.Join(feedDir, "linux-proc.yaml"), badContent) // hash mismatch
	m := feed.Manifest{
		SchemaVersion: 1,
		DBVersion:     "2026-05-18",
		Files: []feed.FileEntry{
			{Name: "linux-os.yaml", SHA256: goodHash},
			{Name: "linux-proc.yaml", SHA256: wrongHash},
		},
	}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{
		FeedURL:         srv.URL + "/manifest.json",
		CacheDir:        dir,
		SupportedSchema: 1,
	}
	_, err := feed.Update(cfg)
	if err == nil {
		t.Fatal("expected error from tampered second file")
	}
	// The existing linux-os.yaml must still have the ORIGINAL content.
	got, readErr := os.ReadFile(filepath.Join(dir, "linux-os.yaml"))
	if readErr != nil {
		t.Fatalf("cache file disappeared: %v", readErr)
	}
	if string(got) != string(existingContent) {
		t.Errorf("atomic swap failed: existing file was overwritten on partial failure.\ngot: %q\nwant: %q", string(got), string(existingContent))
	}
}

// ── Version comparison ────────────────────────────────────────────────────────

func TestCheck_NewerVersionAvailable(t *testing.T) {
	dir := t.TempDir()
	// Install a "current" version.
	writeFile(t, filepath.Join(dir, feed.VersionMarkerFile), []byte("2026-05-10"))

	feedDir := t.TempDir()
	m := feed.Manifest{SchemaVersion: 1, DBVersion: "2026-05-17", Files: nil}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{FeedURL: srv.URL + "/manifest.json", CacheDir: dir, SupportedSchema: 1}
	info, err := feed.Check(cfg)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !info.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=true when remote=%q > local=%q", info.RemoteVersion, info.LocalVersion)
	}
}

func TestCheck_SameVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, feed.VersionMarkerFile), []byte("2026-05-17"))

	feedDir := t.TempDir()
	m := feed.Manifest{SchemaVersion: 1, DBVersion: "2026-05-17", Files: nil}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{FeedURL: srv.URL + "/manifest.json", CacheDir: dir, SupportedSchema: 1}
	info, err := feed.Check(cfg)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if info.UpdateAvailable {
		t.Errorf("expected UpdateAvailable=false when versions match")
	}
}

func TestUpdate_OlderVersionSkipped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, feed.VersionMarkerFile), []byte("2026-05-17"))

	feedDir := t.TempDir()
	m := feed.Manifest{SchemaVersion: 1, DBVersion: "2026-05-10", Files: nil}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{FeedURL: srv.URL + "/manifest.json", CacheDir: dir, SupportedSchema: 1}
	changed, err := feed.Update(cfg)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if changed {
		t.Error("expected no change when remote is older than local")
	}
}

func TestUpdate_UnsupportedSchema_Rejected(t *testing.T) {
	dir := t.TempDir()
	feedDir := t.TempDir()
	m := feed.Manifest{SchemaVersion: 99, DBVersion: "2026-05-17", Files: nil}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{FeedURL: srv.URL + "/manifest.json", CacheDir: dir, SupportedSchema: 1}
	_, err := feed.Update(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported schema version")
	}
	if !strings.Contains(err.Error(), "schema") && !strings.Contains(err.Error(), "version") {
		t.Errorf("expected schema-related error, got: %v", err)
	}
}

// ── IsNewer version comparison (semver + date fallback) ───────────────────────

func TestIsNewer_Semver(t *testing.T) {
	tests := []struct {
		name       string
		a, b       string
		wantANewer bool
	}{
		// The headline regression: lexicographic compare ranked "1.10.0" < "1.9.0"
		// because '1' < '9' at the third character. Semver must rank 1.10.0 higher.
		{"1.10.0 beats 1.9.0", "1.10.0", "1.9.0", true},
		{"1.9.0 does not beat 1.10.0", "1.9.0", "1.10.0", false},
		{"2.0.0 beats 1.99.99", "2.0.0", "1.99.99", true},
		{"patch bump", "1.2.3", "1.2.2", true},
		{"minor bump", "1.3.0", "1.2.9", true},
		{"equal is not newer", "1.2.3", "1.2.3", false},
		{"prerelease lower than release", "1.0.0-rc1", "1.0.0", false},
		{"release higher than prerelease", "1.0.0", "1.0.0-rc1", true},
		{"empty local always newer", "1.0.0", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := feed.IsNewer(tt.a, tt.b); got != tt.wantANewer {
				t.Errorf("IsNewer(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.wantANewer)
			}
		})
	}
}

func TestIsNewer_DateFallback(t *testing.T) {
	// YYYY-MM-DD versions are not semver-shaped, so the lexicographic fallback
	// applies — which is correct for fixed-width date strings.
	tests := []struct {
		name       string
		a, b       string
		wantANewer bool
	}{
		{"newer date", "2026-05-17", "2026-05-10", true},
		{"older date", "2026-05-10", "2026-05-17", false},
		{"same date", "2026-05-17", "2026-05-17", false},
		{"year rollover", "2027-01-01", "2026-12-31", true},
		{"empty local always newer", "2026-05-17", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := feed.IsNewer(tt.a, tt.b); got != tt.wantANewer {
				t.Errorf("IsNewer(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.wantANewer)
			}
		})
	}
}

func TestIsNewer_MixedSchemesFallBackLexicographic(t *testing.T) {
	// When only one side is semver-shaped, the comparison must not panic and
	// falls back to lexicographic ordering deterministically.
	if feed.IsNewer("1.0.0", "2026-05-17") == feed.IsNewer("2026-05-17", "1.0.0") {
		// They cannot both be "newer"; if equal-and-true the result would be
		// inconsistent. "1.0.0" < "2026-05-17" lexicographically, so the date wins.
		t.Errorf("mixed-scheme comparison is not antisymmetric")
	}
	if feed.IsNewer("1.0.0", "2026-05-17") {
		t.Errorf(`expected "2026-05-17" to outrank "1.0.0" under lexicographic fallback`)
	}
}

// ── Check does NOT mutate state ───────────────────────────────────────────────

func TestCheck_DoesNotMutateCache(t *testing.T) {
	dir := t.TempDir()
	// No version marker — first-time state.

	feedDir := t.TempDir()
	m := feed.Manifest{SchemaVersion: 1, DBVersion: "2026-05-17", Files: []feed.FileEntry{{Name: "linux-os.yaml", SHA256: "abc"}}}
	manifestData, _ := json.Marshal(m)
	writeFile(t, filepath.Join(feedDir, "manifest.json"), manifestData)

	srv := httptest.NewServer(http.FileServer(http.Dir(feedDir)))
	defer srv.Close()

	cfg := feed.Config{FeedURL: srv.URL + "/manifest.json", CacheDir: dir, SupportedSchema: 1}
	_, err := feed.Check(cfg)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Version marker must NOT have been written.
	if _, err := os.Stat(filepath.Join(dir, feed.VersionMarkerFile)); err == nil {
		t.Error("Check must not write version marker to cache")
	}
	// No DB files must exist.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("Check must not write any files to cache dir; found: %v", entries)
	}
}

// helpers

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
