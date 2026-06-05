package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// slowServer returns a test server whose every response sleeps for the given
// duration before writing the noise body. Used to force the scan to take longer
// than the --max-time deadline so cancellation can be observed.
func slowServer(delay time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		_, _ = w.Write([]byte(noiseBody))
	}))
}

// baseMaxTimeFlags builds minimal scanFlags for max-time tests: a single
// worker, the curated fixture DB, text output, and no hit-only filtering so
// the test can observe whether entries were processed.
func baseMaxTimeFlags(t *testing.T, serverURL string, maxTime time.Duration) scanFlags {
	t.Helper()
	return scanFlags{
		url:            serverURL + "/?file=FUZZ",
		marker:         "FUZZ",
		method:         "GET",
		concurrency:    1,
		timeout:        5 * time.Second,
		traversalDepth: 1,
		dbPath:         curatedDBPath(t),
		onlyHits:       false,
		maxDepth:       0,
		maxTargets:     0,
		outputFormat:   "text",
		maxTime:        maxTime,
	}
}

// TestScan_MaxTimeZeroRunsToCompletion verifies that maxTime=0 (the default)
// does not install any deadline and the scan finishes normally.
func TestScan_MaxTimeZeroRunsToCompletion(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(baseMaxTimeFlags(t, srv.URL, 0)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	// Normal completion banner must appear.
	if !strings.Contains(out, "Scan complete") {
		t.Fatalf("expected 'Scan complete' in output, got:\n%s", out)
	}
	// The stopped-early banner must not appear.
	if strings.Contains(out, "max-time") {
		t.Fatalf("should not see max-time banner when maxTime=0, got:\n%s", out)
	}
}

// TestScan_MaxTimeStopsEarly verifies that a very short max-time cancels
// a scan against a slow server before all entries have been attempted.
// The slow server takes 50 ms per request; max-time is 1 ms, which expires
// before the first entry completes its batch, so the scan stops after 0
// entries (possibly 1 if the deadline races against the first dispatch).
// We assert that the "max-time reached" stop banner is present and that the
// "Scan complete" banner is absent.
func TestScan_MaxTimeStopsEarly(t *testing.T) {
	// Each request takes 50 ms; a 1 ms deadline fires before the first batch.
	srv := slowServer(50 * time.Millisecond)
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(baseMaxTimeFlags(t, srv.URL, 1*time.Millisecond)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	// The early-stop banner must appear.
	if !strings.Contains(out, "max-time") {
		t.Fatalf("expected max-time stop banner, got:\n%s", out)
	}
	// The normal completion banner must not appear.
	if strings.Contains(out, "Scan complete") {
		t.Fatalf("should not see 'Scan complete' when scan stopped early, got:\n%s", out)
	}
}

// TestScan_MaxTimeLongEnoughRunsToCompletion verifies that a max-time
// sufficiently long for the scan to finish results in normal completion,
// not the early-stop banner. A fast server + 10 s deadline should always
// finish in time.
func TestScan_MaxTimeLongEnoughRunsToCompletion(t *testing.T) {
	srv := noiseServer() // fast, no delay
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(baseMaxTimeFlags(t, srv.URL, 10*time.Second)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	// Normal completion banner must appear.
	if !strings.Contains(out, "Scan complete") {
		t.Fatalf("expected 'Scan complete' in output, got:\n%s", out)
	}
}
