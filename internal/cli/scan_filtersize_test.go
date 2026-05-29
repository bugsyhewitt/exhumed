package cli

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything written. The scan command prints "[responded]" lines to stdout,
// so this is how the test observes filtering behaviour.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()

	_ = w.Close()
	os.Stdout = orig
	return <-done
}

// noiseFlags builds scanFlags against the curated fixture DB that DO emit
// unconfirmed responses (onlyHits=false), so the size filter is the only thing
// that can suppress the "[responded]" stream. Chaining is disabled for
// determinism.
func noiseFlags(t *testing.T, serverURL, filterSize string) scanFlags {
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
		filterSize:     filterSize,
	}
}

// noiseBody is a fixed-size 2xx body that matches NONE of the fixture DB's
// confirm patterns, so every response is an unconfirmed "[responded]" line.
const noiseBody = "soft-404 not found template" // 27 bytes, > detect.minBodyLen

// noiseServer always returns the same fixed-size 200 body, simulating an app
// whose "file not found" page is the same length for every miss.
func noiseServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(noiseBody))
	}))
}

// TestScan_FilterSizeSuppressesNoise verifies that, without a filter, the
// uniform-size noise responses appear in the output, and that naming their
// exact byte length in --filter-size removes them entirely.
func TestScan_FilterSizeSuppressesNoise(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	// Baseline: no filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(noiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Filtered: name the exact noise size — the [responded] lines vanish.
	out := captureStdout(t, func() {
		if err := runScan(noiseFlags(t, srv.URL, fmt.Sprintf("%d", len(noiseBody)))); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-size %d should have suppressed all noise, got:\n%s", len(noiseBody), out)
	}
}

// TestScan_FilterSizeRangeSuppresses verifies a range spec also filters the
// noise body whose length falls inside it.
func TestScan_FilterSizeRangeSuppresses(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(noiseFlags(t, srv.URL, "20-40")); err != nil { // 27 ∈ [20,40]
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("range filter 20-40 should suppress 27-byte body, got:\n%s", out)
	}
}

// TestScan_FilterSizeNonMatchKeepsOutput verifies that a filter naming a size
// the responses do NOT have leaves the output untouched.
func TestScan_FilterSizeNonMatchKeepsOutput(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(noiseFlags(t, srv.URL, "9999")); err != nil { // noise is 27, not 9999
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("non-matching filter should leave noise intact, got:\n%s", out)
	}
}

// TestScan_FilterSizeNeverFiltersHits verifies that a confirmed hit is reported
// even when its body length matches the --filter-size spec. Content-based
// confirmation always wins over the size noise filter.
func TestScan_FilterSizeNeverFiltersHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody))
			return
		}
		_, _ = w.Write([]byte(noiseBody))
	}))
	defer srv.Close()

	// Filter spans every plausible body length (0..10000) — it must still not
	// suppress a content-confirmed hit.
	out := captureStdout(t, func() {
		if err := runScan(noiseFlags(t, srv.URL, "0-10000")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-size, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("the all-spanning filter should have removed every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterSizeInvalidSpecErrors verifies a malformed --filter-size value
// fails before any requests fire.
func TestScan_FilterSizeInvalidSpecErrors(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	err := runScan(noiseFlags(t, srv.URL, "100-50"))
	if err == nil {
		t.Fatal("expected error for reversed --filter-size range")
	}
	if !strings.Contains(err.Error(), "respfilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
