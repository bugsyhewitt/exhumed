package pathlist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/bugsyhewitt/exhumed/internal/detect"
	"github.com/bugsyhewitt/exhumed/internal/engine"
)

func TestParse_SkipsBlanksAndComments(t *testing.T) {
	in := strings.Join([]string{
		"# this is a comment",
		"/etc/passwd",
		"",
		"   ",
		"  /etc/shadow  ", // surrounding whitespace trimmed
		"# another comment",
		"/var/www/.env",
	}, "\n")

	entries, err := Parse(strings.NewReader(in), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	wantPaths := []string{"/etc/passwd", "/etc/shadow", "/var/www/.env"}
	if len(entries) != len(wantPaths) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(wantPaths), entries)
	}
	for i, want := range wantPaths {
		if entries[i].Entry.Path != want {
			t.Errorf("entry[%d].Path = %q, want %q", i, entries[i].Entry.Path, want)
		}
	}
}

func TestParse_DeduplicatesPreservingOrder(t *testing.T) {
	in := "/a\n/b\n/a\n/c\n/b\n"
	entries, err := Parse(strings.NewReader(in), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Entry.Path
	}
	want := []string{"/a", "/b", "/c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dedup order: got %v, want %v", got, want)
	}
}

func TestParse_InfersParser(t *testing.T) {
	cases := map[string]string{
		"/home/u/.ssh/id_rsa":             "ssh-key",
		"/etc/passwd":                     "unix-passwd",
		"/proc/self/environ":              "proc-environ",
		"/var/www/.env":                   "ini-config",
		"/etc/mysql/my.cnf":               "ini-config",
		"/app/config/app.properties":      "ini-config",
		"/var/log/apache2/access.log.txt": "generic-secrets",
	}
	for path, wantParser := range cases {
		entries, err := Parse(strings.NewReader(path+"\n"), "test")
		if err != nil {
			t.Fatalf("Parse(%q): %v", path, err)
		}
		if len(entries) != 1 {
			t.Fatalf("Parse(%q): got %d entries, want 1", path, len(entries))
		}
		if got := entries[0].Entry.Parser; got != wantParser {
			t.Errorf("inferParser(%q) = %q, want %q", path, got, wantParser)
		}
	}
}

// TestParse_EntriesAreDetectable verifies the synthetic entries carry a
// compiled weak-confirm regex so detect.Check actually fires on a readable body
// (the latent gap that would silently drop every wordlist hit if uncompiled).
func TestParse_EntriesAreDetectable(t *testing.T) {
	entries, err := Parse(strings.NewReader("/etc/passwd\n"), "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	e := entries[0]
	if e.Entry.Confirm.Type != db.ConfirmTypeRegex {
		t.Fatalf("confirm type = %q, want regex", e.Entry.Confirm.Type)
	}
	if len(e.CompiledPatterns) != 1 {
		t.Fatalf("CompiledPatterns len = %d, want 1 (uncompiled entries never hit)", len(e.CompiledPatterns))
	}

	// A non-empty 2xx body must be a hit.
	hit := detect.Check(e, engine.Result{
		StatusCode: 200,
		Body:       []byte("root:x:0:0:root:/root:/bin/bash\n"),
	})
	if !hit.Hit {
		t.Fatalf("expected hit on readable body, got Confidence=%q", hit.Confidence)
	}

	// A 404 must not be a hit.
	miss := detect.Check(e, engine.Result{StatusCode: 404, Body: []byte("Not Found")})
	if miss.Hit {
		t.Fatal("expected no hit on 404 response")
	}
}

func TestParseFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lfi.txt")
	if err := os.WriteFile(path, []byte("/etc/passwd\n# comment\n/etc/hosts\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].SourceFile != path {
		t.Errorf("SourceFile = %q, want %q", entries[0].SourceFile, path)
	}
}

func TestParseFile_MissingFileErrors(t *testing.T) {
	_, err := ParseFile(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	if err == nil {
		t.Fatal("expected error for missing wordlist file")
	}
	if !strings.Contains(err.Error(), "pathlist") {
		t.Errorf("error %q should mention pathlist", err)
	}
}
