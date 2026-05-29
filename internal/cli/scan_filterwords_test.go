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

// wordNoiseFlags builds scanFlags against the curated fixture DB that DO emit
// unconfirmed responses (onlyHits=false), so --filter-words is the only thing
// that can suppress the "[responded]" stream. Chaining is disabled for
// determinism.
func wordNoiseFlags(t *testing.T, serverURL, filterWords string) scanFlags {
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
		filterWords:    filterWords,
	}
}

// wordNoiseBody is a fixed 4-word soft-404 template (> detect.minBodyLen) that
// matches NONE of the fixture DB's confirm patterns, so every response is an
// unconfirmed "[responded]" line.
const wordNoiseBody = "soft 404 not found" // 4 words

// TestScan_FilterWordsSuppressesNoise verifies that, without a filter, the
// uniform word-count noise appears, and that naming its word count in
// --filter-words removes it entirely.
func TestScan_FilterWordsSuppressesNoise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(wordNoiseBody))
	}))
	defer srv.Close()

	baseline := captureStdout(t, func() {
		if err := runScan(wordNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	out := captureStdout(t, func() {
		if err := runScan(wordNoiseFlags(t, srv.URL, "4")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-words 4 should have suppressed all noise, got:\n%s", out)
	}
}

// TestScan_FilterWordsCatchesVaryingLength is the motivating case for the
// feature: a soft-404 whose body embeds a per-request varying token has a
// DIFFERENT byte length every time (so --filter-size cannot pin it) but a
// CONSTANT word count. --filter-words suppresses all of it.
func TestScan_FilterWordsCatchesVaryingLength(t *testing.T) {
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Each response: 5 words, last word a growing request ID — byte length
		// changes per request, word count is always 5.
		id := atomic.AddInt64(&n, 1)
		body := fmt.Sprintf("not found request id %s", strings.Repeat("x", int(id)))
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(wordNoiseFlags(t, srv.URL, "5")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-words 5 should suppress varying-length 5-word noise, got:\n%s", out)
	}
}

// TestScan_FilterWordsRangeSuppresses verifies a range spec filters the noise
// whose word count falls inside it.
func TestScan_FilterWordsRangeSuppresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(wordNoiseBody)) // 4 words
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(wordNoiseFlags(t, srv.URL, "2-6")); err != nil { // 4 ∈ [2,6]
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("range filter 2-6 should suppress 4-word body, got:\n%s", out)
	}
}

// TestScan_FilterWordsNonMatchKeepsOutput verifies a filter naming a count the
// responses do NOT have leaves the output untouched.
func TestScan_FilterWordsNonMatchKeepsOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(wordNoiseBody)) // 4 words
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(wordNoiseFlags(t, srv.URL, "99")); err != nil { // noise is 4, not 99
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("non-matching filter should leave noise intact, got:\n%s", out)
	}
}

// TestScan_FilterWordsNeverFiltersHits verifies a confirmed hit is reported even
// when its body's word count matches the --filter-words spec. Content-based
// confirmation always wins over the word-count noise filter.
func TestScan_FilterWordsNeverFiltersHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody))
			return
		}
		_, _ = w.Write([]byte(wordNoiseBody))
	}))
	defer srv.Close()

	// A wide range spanning every plausible word count must still not suppress a
	// content-confirmed hit.
	out := captureStdout(t, func() {
		if err := runScan(wordNoiseFlags(t, srv.URL, "0-100000")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-words, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("the all-spanning filter should have removed every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterWordsInvalidSpecErrors verifies a malformed --filter-words
// value fails before any requests fire.
func TestScan_FilterWordsInvalidSpecErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(wordNoiseBody))
	}))
	defer srv.Close()

	err := runScan(wordNoiseFlags(t, srv.URL, "20-10"))
	if err == nil {
		t.Fatal("expected error for reversed --filter-words range")
	}
	if !strings.Contains(err.Error(), "wordfilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
