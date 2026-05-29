package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// codeNoiseFlags builds scanFlags against the curated fixture DB that DO emit
// unconfirmed responses (onlyHits=false), so --filter-code is the only thing
// that can suppress the "[responded]" stream. Chaining is disabled for
// determinism. filterSize is left empty so the status-code filter is exercised
// in isolation.
func codeNoiseFlags(t *testing.T, serverURL, filterCode string) scanFlags {
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
		filterCode:     filterCode,
	}
}

// codeNoiseServer always returns the same fixed status code with a non-matching
// body, simulating an app whose "file not found" handler answers every miss
// with a uniform status (a hard 404, a WAF 403, a 500, etc.).
func codeNoiseServer(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(noiseBody))
	}))
}

// TestScan_FilterCodeSuppressesNoise verifies that, without a filter, the
// uniform-status noise responses appear, and that naming their status code in
// --filter-code removes them entirely.
func TestScan_FilterCodeSuppressesNoise(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound) // every miss answers 404
	defer srv.Close()

	// Baseline: no filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(codeNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}
	if !strings.Contains(baseline, "status=404") {
		t.Fatalf("baseline should report status=404 noise:\n%s", baseline)
	}

	// Filtered: name the noise code — the [responded] lines vanish.
	out := captureStdout(t, func() {
		if err := runScan(codeNoiseFlags(t, srv.URL, "404")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-code 404 should have suppressed all noise, got:\n%s", out)
	}
}

// TestScan_FilterCodeRangeSuppresses verifies a range spec also filters a code
// that falls inside it (a 403 inside 400-499).
func TestScan_FilterCodeRangeSuppresses(t *testing.T) {
	srv := codeNoiseServer(http.StatusForbidden) // 403
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(codeNoiseFlags(t, srv.URL, "400-499")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("range filter 400-499 should suppress a 403, got:\n%s", out)
	}
}

// TestScan_FilterCodeNonMatchKeepsOutput verifies that a filter naming a code
// the responses do NOT carry leaves the output untouched.
func TestScan_FilterCodeNonMatchKeepsOutput(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound) // 404
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(codeNoiseFlags(t, srv.URL, "500")); err != nil { // noise is 404, not 500
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("non-matching filter should leave noise intact, got:\n%s", out)
	}
}

// TestScan_FilterCodeNeverFiltersHits verifies that a confirmed hit is reported
// while --filter-code suppresses the same-shaped noise around it. Confirmation
// in exhumed requires a 2xx status (see internal/detect), so the realistic
// scenario is an app that answers misses with a uniform 404 but returns the
// leaked file with a 200. --filter-code 404 must clear the noise without
// touching the content-confirmed hit.
func TestScan_FilterCodeNeverFiltersHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			// The leaked file comes back 200 — a genuine read.
			_, _ = w.Write([]byte(passwdBody))
			return
		}
		// Every miss answers a uniform 404 noise page.
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(noiseBody))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(codeNoiseFlags(t, srv.URL, "404")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-code, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("the 404 filter should have removed every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterCodeComposesWithFilterSize verifies the two filters are ORed:
// a response is suppressed if either the size filter OR the code filter matches.
// Here the size filter targets a length the noise does NOT have, but the code
// filter matches — so the noise is still dropped.
func TestScan_FilterCodeComposesWithFilterSize(t *testing.T) {
	srv := codeNoiseServer(http.StatusInternalServerError) // 500, body len 27
	defer srv.Close()

	f := codeNoiseFlags(t, srv.URL, "500")
	f.filterSize = "9999" // deliberately non-matching size
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("code filter should suppress noise even when size filter misses, got:\n%s", out)
	}
}

// TestScan_FilterCodeInvalidSpecErrors verifies a malformed --filter-code value
// fails before any requests fire.
func TestScan_FilterCodeInvalidSpecErrors(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound)
	defer srv.Close()

	err := runScan(codeNoiseFlags(t, srv.URL, "600")) // out of the valid 100-599 range
	if err == nil {
		t.Fatal("expected error for out-of-range --filter-code")
	}
	if !strings.Contains(err.Error(), "codefilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
