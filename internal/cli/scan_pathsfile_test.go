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
)

// basePathsFlags builds quiet scanFlags pointing at the given server, using an
// empty database directory so only the wordlist drives the scan. Chaining is
// disabled for determinism.
func basePathsFlags(serverURL, dbPath, pathsFile string) scanFlags {
	return scanFlags{
		url:            serverURL + "/?file=FUZZ",
		marker:         "FUZZ",
		method:         "GET",
		concurrency:    2,
		timeout:        5 * time.Second,
		traversalDepth: 1,
		dbPath:         dbPath,
		onlyHits:       true,
		maxDepth:       0,
		maxTargets:     0,
		outputFormat:   "text",
		pathsFile:      pathsFile,
	}
}

// TestScan_PathsFileFiresWordlistEntries verifies that paths from --paths-file
// are scanned and that a readable one is confirmed as a hit.
func TestScan_PathsFileFiresWordlistEntries(t *testing.T) {
	var sawSecret int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A bespoke path that exists in NO curated entry — it can only come
		// from the wordlist — returns a readable body.
		if strings.Contains(r.URL.RawQuery, "wordlist-only-secret.txt") {
			atomic.AddInt64(&sawSecret, 1)
			w.Write([]byte("this body is long enough to clear the min-body gate\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Empty DB dir so only the wordlist contributes entries.
	emptyDB := t.TempDir()
	wordlist := filepath.Join(t.TempDir(), "lfi.txt")
	if err := os.WriteFile(wordlist, []byte("# custom list\n/var/data/wordlist-only-secret.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := basePathsFlags(srv.URL, emptyDB, wordlist)
	if err := runScan(f); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if atomic.LoadInt64(&sawSecret) == 0 {
		t.Fatal("wordlist path was never requested; --paths-file did not feed the scan")
	}
}

// TestScan_PathsFileMissingErrors verifies a missing wordlist fails loudly
// rather than silently scanning the curated database only.
func TestScan_PathsFileMissingErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := basePathsFlags(srv.URL, t.TempDir(), filepath.Join(t.TempDir(), "nope.txt"))
	err := runScan(f)
	if err == nil {
		t.Fatal("expected error for missing --paths-file")
	}
	if !strings.Contains(err.Error(), "pathlist") {
		t.Fatalf("unexpected error: %v", err)
	}
}
