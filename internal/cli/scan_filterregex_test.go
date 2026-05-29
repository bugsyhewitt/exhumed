package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// regexNoiseFlags builds scanFlags against the curated fixture DB that DO emit
// unconfirmed responses (onlyHits=false), so --filter-regex is the only thing
// that can suppress the "[responded]" stream. Chaining is disabled for
// determinism. filterSize and filterCode are left empty so the body-regex
// filter is exercised in isolation.
func regexNoiseFlags(t *testing.T, serverURL, filterRegex string) scanFlags {
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
		filterRegex:    filterRegex,
	}
}

// regexNoiseServer always returns a 200 with the same fixed noise body,
// simulating an app whose "file not found" handler answers every miss with a
// uniform soft-404 page (a recognisable phrase, not a status code or a fixed
// size that --filter-size/--filter-code would catch).
func regexNoiseServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(noiseBody)) // "soft-404 not found template"
	}))
}

// TestScan_FilterRegexSuppressesNoise verifies that, without a filter, the
// uniform soft-404 noise responses appear, and that naming a phrase from their
// body in --filter-regex removes them entirely.
func TestScan_FilterRegexSuppressesNoise(t *testing.T) {
	srv := regexNoiseServer()
	defer srv.Close()

	// Baseline: no filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(regexNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Filtered: name a phrase from the noise body — the [responded] lines vanish.
	out := captureStdout(t, func() {
		if err := runScan(regexNoiseFlags(t, srv.URL, "soft-404")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--filter-regex 'soft-404' should have suppressed all noise, got:\n%s", out)
	}
}

// TestScan_FilterRegexCaseInsensitive verifies an (?i) pattern matches the noise
// body regardless of case.
func TestScan_FilterRegexCaseInsensitive(t *testing.T) {
	srv := regexNoiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(regexNoiseFlags(t, srv.URL, "(?i)NOT FOUND")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("case-insensitive regex should suppress the noise, got:\n%s", out)
	}
}

// TestScan_FilterRegexNonMatchKeepsOutput verifies that a regex matching nothing
// in the response bodies leaves the output untouched.
func TestScan_FilterRegexNonMatchKeepsOutput(t *testing.T) {
	srv := regexNoiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(regexNoiseFlags(t, srv.URL, "this-phrase-never-appears")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("non-matching regex should leave noise intact, got:\n%s", out)
	}
}

// TestScan_FilterRegexNeverFiltersHits verifies that a confirmed hit is reported
// while --filter-regex suppresses the same-shaped noise around it. The leaked
// passwd file comes back 200 and is content-confirmed; the misses answer a
// uniform soft-404 body. A regex naming the noise phrase must clear the noise
// without touching the content-confirmed hit.
func TestScan_FilterRegexNeverFiltersHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read
			return
		}
		_, _ = w.Write([]byte(noiseBody)) // uniform soft-404 noise page
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(regexNoiseFlags(t, srv.URL, "soft-404")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --filter-regex, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("the 'soft-404' filter should have removed every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_FilterRegexComposesWithFilterCode verifies the filters are ORed: a
// response is suppressed if any of size/code/regex matches. Here the code filter
// targets a status the noise does NOT carry (the noise is 200), but the body
// regex matches — so the noise is still dropped.
func TestScan_FilterRegexComposesWithFilterCode(t *testing.T) {
	srv := regexNoiseServer() // 200 soft-404 body
	defer srv.Close()

	f := regexNoiseFlags(t, srv.URL, "soft-404")
	f.filterCode = "500" // deliberately non-matching status
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("body regex should suppress noise even when code filter misses, got:\n%s", out)
	}
}

// TestScan_FilterRegexInvalidSpecErrors verifies a malformed --filter-regex
// value fails before any requests fire.
func TestScan_FilterRegexInvalidSpecErrors(t *testing.T) {
	srv := regexNoiseServer()
	defer srv.Close()

	err := runScan(regexNoiseFlags(t, srv.URL, "(unclosed")) // invalid RE2
	if err == nil {
		t.Fatal("expected error for malformed --filter-regex")
	}
	if !strings.Contains(err.Error(), "bodyfilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
