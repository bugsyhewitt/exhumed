package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// lineNoiseFlags builds scanFlags against the curated fixture DB that DO emit
// unconfirmed responses (onlyHits=false), so --filter-lines is the only thing
// that can suppress the "[responded]" stream. Chaining is disabled for
// determinism.
func lineNoiseFlags(t *testing.T, serverURL, filterLines string) scanFlags {
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
		filterLines:    filterLines,
	}
}

// lineNoiseBody is a fixed 2-line soft-404 template (> detect.minBodyLen) that
// matches NONE of the fixture DB's confirm patterns, so every response is an
// unconfirmed "[responded]" line. Two '\n' terminators => 2 lines.
const lineNoiseBody = "soft 404 not found\nthe requested file does not exist\n" // 2 lines

// TestScan_FilterLinesSuppressesNoise verifies that, without a filter, the
// uniform line-count noise appears, and that naming its line count in
// --filter-lines removes it entirely.
func TestScan_FilterLinesSuppressesNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(lineNoiseBody))
	}))
	defer srv.Close()

	baseline := captureStdout(t, func() {
		if err := runScan(lineNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	out := captureStdout(t, func() {
		if err := runScan(lineNoiseFlags(t, srv.URL, "2")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-lines 2 should have suppressed all noise, got:\n%s", out)
	}
}

// TestScan_FilterLinesCatchesVaryingWordCount is the motivating case for the
// feature: a soft-404 whose body embeds a per-request varying MULTI-WORD
// fragment on a fixed line has a DIFFERENT byte length AND a DIFFERENT word
// count every time (so neither --filter-size nor --filter-words can pin it) but
// a CONSTANT line count. --filter-lines suppresses all of it.
func TestScan_FilterLinesCatchesVaryingWordCount(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Each response: 2 lines, second line echoes a growing whitespace-joined
		// fragment — both byte length and word count change per request, line
		// count is always 2.
		id := atomic.AddInt64(&n, 1)
		echo := strings.Repeat("tok ", int(id)) // id extra words, varying bytes
		body := fmt.Sprintf("not found\nrequest %sGET /\n", echo)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(lineNoiseFlags(t, srv.URL, "2")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-lines 2 should suppress varying-word-count 2-line noise, got:\n%s", out)
	}
}

// TestScan_FilterLinesRangeSuppresses verifies a range spec filters the noise
// whose line count falls inside it.
func TestScan_FilterLinesRangeSuppresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(lineNoiseBody)) // 2 lines
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(lineNoiseFlags(t, srv.URL, "1-5")); err != nil { // 2 ∈ [1,5]
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("range filter 1-5 should suppress 2-line body, got:\n%s", out)
	}
}

// TestScan_FilterLinesNonMatchKeepsOutput verifies a filter naming a count the
// responses do NOT have leaves the output untouched.
func TestScan_FilterLinesNonMatchKeepsOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(lineNoiseBody)) // 2 lines
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(lineNoiseFlags(t, srv.URL, "99")); err != nil { // noise is 2, not 99
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("non-matching filter should leave noise intact, got:\n%s", out)
	}
}

// TestScan_FilterLinesNeverFiltersHits verifies a confirmed hit is reported even
// when its body's line count matches the --filter-lines spec. Content-based
// confirmation always wins over the line-count noise filter.
func TestScan_FilterLinesNeverFiltersHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody))
			return
		}
		_, _ = w.Write([]byte(lineNoiseBody))
	}))
	defer srv.Close()

	// A wide range spanning every plausible line count must still not suppress a
	// content-confirmed hit.
	out := captureStdout(t, func() {
		if err := runScan(lineNoiseFlags(t, srv.URL, "0-100000")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-lines, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("the all-spanning filter should have removed every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterLinesInvalidSpecErrors verifies a malformed --filter-lines
// value fails before any requests fire.
func TestScan_FilterLinesInvalidSpecErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(lineNoiseBody))
	}))
	defer srv.Close()

	err := runScan(lineNoiseFlags(t, srv.URL, "20-10"))
	if err == nil {
		t.Fatal("expected error for reversed --filter-lines range")
	}
	if !strings.Contains(err.Error(), "linefilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
