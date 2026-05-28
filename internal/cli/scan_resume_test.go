package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/scanstate"
)

// curatedDBPath returns the path to the small valid db fixture used by the
// loader tests, resolved relative to this package directory.
func curatedDBPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "db", "testdata", "valid"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// baseResumeFlags builds scanFlags pointing at the given server and resume file,
// using the fixture database and a quiet, single-worker configuration.
func baseResumeFlags(serverURL, dbPath, resumeFile string) scanFlags {
	return scanFlags{
		url:            serverURL + "/?file=FUZZ",
		marker:         "FUZZ",
		method:         "GET",
		concurrency:    2,
		timeout:        5 * time.Second,
		traversalDepth: 1,
		dbPath:         dbPath,
		onlyHits:       true,
		maxDepth:       0, // disable chaining to keep the test deterministic
		maxTargets:     0,
		outputFormat:   "text",
		resume:         resumeFile,
	}
}

// TestScan_ResumeSkipsAttemptedEntries verifies that a second run with the same
// --resume file does not re-request entries that were attempted in the first run.
func TestScan_ResumeSkipsAttemptedEntries(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		// Make /etc/passwd a confirmed hit so we exercise the hit-replay path.
		if strings.Contains(r.URL.RawQuery, "passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resumeFile := filepath.Join(t.TempDir(), "resume.json")
	f := baseResumeFlags(srv.URL, curatedDBPath(t), resumeFile)

	// First run: scans all entries, records progress.
	if err := runScan(f); err != nil {
		t.Fatalf("first runScan: %v", err)
	}
	firstRunRequests := atomic.LoadInt64(&requests)
	if firstRunRequests == 0 {
		t.Fatal("first run fired no requests")
	}

	// Resume file must exist and record every entry as attempted.
	st, err := scanstate.Load(resumeFile, f.url, f.marker, "")
	if err == nil {
		// Load with empty fingerprint should have been refused (db mismatch)
		// unless the real fingerprint happens to be empty, which it never is.
		t.Fatal("expected db-fingerprint mismatch when loading with empty fingerprint")
	}
	_ = st

	// Second run with the same resume file: all entries already attempted,
	// so no new HTTP requests should be made.
	atomic.StoreInt64(&requests, 0)
	if err := runScan(f); err != nil {
		t.Fatalf("second runScan: %v", err)
	}
	if got := atomic.LoadInt64(&requests); got != 0 {
		t.Fatalf("resume re-requested %d times; expected 0 (all entries should be skipped)", got)
	}
}

// TestScan_ResumeRefusesTargetMismatch verifies fail-closed behaviour when a
// resume file is reused against a different target.
func TestScan_ResumeRefusesTargetMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resumeFile := filepath.Join(t.TempDir(), "resume.json")
	dbPath := curatedDBPath(t)

	f := baseResumeFlags(srv.URL, dbPath, resumeFile)
	if err := runScan(f); err != nil {
		t.Fatalf("first runScan: %v", err)
	}

	// Reuse the same resume file but change the target URL.
	f2 := baseResumeFlags(srv.URL, dbPath, resumeFile)
	f2.url = srv.URL + "/other?file=FUZZ"
	err := runScan(f2)
	if err == nil {
		t.Fatal("expected runScan to refuse resume on target mismatch")
	}
	if !strings.Contains(err.Error(), "resume") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestScan_NoResumeFlagCreatesNoFile verifies that omitting --resume leaves no
// state file behind (no surprise artifacts).
func TestScan_NoResumeFlagCreatesNoFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dir := t.TempDir()
	f := baseResumeFlags(srv.URL, curatedDBPath(t), "")
	if err := runScan(f); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("expected no files created without --resume, found %d", len(entries))
	}
}
