package cli

import (
	"strings"
	"testing"
	"time"
)

// baseMaxRequestsFlags builds minimal scanFlags for max-requests tests.
func baseMaxRequestsFlags(t *testing.T, serverURL string, maxRequests int) scanFlags {
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
		maxRequests:    maxRequests,
	}
}

// TestScan_MaxRequestsZeroRunsToCompletion verifies that maxRequests=0 (the
// default) imposes no cap and the scan completes normally.
func TestScan_MaxRequestsZeroRunsToCompletion(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(baseMaxRequestsFlags(t, srv.URL, 0)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	// Normal completion banner must appear.
	if !strings.Contains(out, "Scan complete") {
		t.Fatalf("expected 'Scan complete' in output, got:\n%s", out)
	}
	// The stopped-early banner must not appear.
	if strings.Contains(out, "max-requests") {
		t.Fatalf("should not see max-requests banner when maxRequests=0, got:\n%s", out)
	}
}

// TestScan_MaxRequestsOneStopsAfterFirstEntry verifies that setting
// maxRequests=1 stops the scan after at most one batch of requests (i.e. one
// DB entry × traversal depth). The early-stop banner must be present and the
// "Scan complete" banner must be absent.
func TestScan_MaxRequestsOneStopsAfterFirstEntry(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	// 1 request cap: the first entry fires its payloads, bringing total ≥ 1;
	// the next entry check sees total >= maxRequests and breaks.
	out := captureStdout(t, func() {
		if err := runScan(baseMaxRequestsFlags(t, srv.URL, 1)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	// Early-stop banner must appear.
	if !strings.Contains(out, "max-requests") {
		t.Fatalf("expected max-requests stop banner, got:\n%s", out)
	}
	// Normal completion banner must not appear.
	if strings.Contains(out, "Scan complete") {
		t.Fatalf("should not see 'Scan complete' when scan stopped early, got:\n%s", out)
	}
}

// TestScan_MaxRequestsLargeEnoughRunsToCompletion verifies that a cap large
// enough to cover all entries (1 000 000) results in normal completion with no
// early-stop banner.
func TestScan_MaxRequestsLargeEnoughRunsToCompletion(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(baseMaxRequestsFlags(t, srv.URL, 1_000_000)); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	// Normal completion banner must appear.
	if !strings.Contains(out, "Scan complete") {
		t.Fatalf("expected 'Scan complete' in output, got:\n%s", out)
	}
	// Early-stop banner must not appear.
	if strings.Contains(out, "max-requests") {
		t.Fatalf("should not see max-requests banner when cap is very large, got:\n%s", out)
	}
}
