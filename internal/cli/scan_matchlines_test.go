package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// multiLineNoiseBody is a fixed soft-404 template with three newline
// terminators, so linefilter/matchlines count it as 3 lines. It matches NONE of
// the fixture DB's confirm patterns, so every response is an unconfirmed
// "[responded]" line.
const multiLineNoiseBody = "soft-404\nnot found\ntemplate page\n"

// multiLineNoiseServer always returns the same fixed 3-line 200 body,
// simulating an app whose "file not found" page has a constant line count for
// every miss.
func multiLineNoiseServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(multiLineNoiseBody))
	}))
}

// matchLinesNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-lines is the only
// thing governing the "[responded]" stream. Chaining is disabled for
// determinism. The suppression filters and the other match gates are left empty
// so the positive line-count gate is exercised in isolation.
func matchLinesNoiseFlags(t *testing.T, serverURL, matchLines string) scanFlags {
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
		matchLines:     matchLines,
	}
}

// TestScan_MatchLinesKeepsOnlyAllowlisted verifies that, without a match filter,
// the uniform-line-count noise responses appear, and that naming a line count
// the noise does NOT carry drops them all — only allowlisted line counts
// survive.
func TestScan_MatchLinesKeepsOnlyAllowlisted(t *testing.T) {
	srv := multiLineNoiseServer() // every miss answers the 3-line body
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchLinesNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Match only a line count the noise does NOT have — the noise is dropped
	// because its count is not in the allowlist (the inverse of --filter-lines).
	out := captureStdout(t, func() {
		if err := runScan(matchLinesNoiseFlags(t, srv.URL, "99")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-lines 99 should drop all 3-line noise, got:\n%s", out)
	}
}

// TestScan_MatchLinesKeepsMatchingNoise verifies that naming the noise's own
// line count in --match-lines keeps the unconfirmed responses (the positive gate
// passes).
func TestScan_MatchLinesKeepsMatchingNoise(t *testing.T) {
	srv := multiLineNoiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchLinesNoiseFlags(t, srv.URL, "3")); err != nil { // body has 3 newlines
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-lines 3 should keep the noise responses, got:\n%s", out)
	}
}

// TestScan_MatchLinesRangeKeeps verifies a range spec keeps a body whose line
// count falls inside it (the 3-line noise inside 2-6).
func TestScan_MatchLinesRangeKeeps(t *testing.T) {
	srv := multiLineNoiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchLinesNoiseFlags(t, srv.URL, "2-6")); err != nil { // 3 ∈ [2,6]
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("range match 2-6 should keep a 3-line body, got:\n%s", out)
	}
}

// TestScan_MatchLinesNeverDropsHits verifies a confirmed hit is reported even
// when --match-lines names a count the hit's response body does NOT carry. The
// leaked passwd file is content-confirmed and must survive the match gate, which
// only governs the unconfirmed stream.
func TestScan_MatchLinesNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm (1 line)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read, 200
			return
		}
		_, _ = w.Write([]byte(multiLineNoiseBody)) // uniform 3-line noise
	}))
	defer srv.Close()

	// Match only a count neither body has: this drops the noise AND would drop
	// the hit if the gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(matchLinesNoiseFlags(t, srv.URL, "99")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-lines, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-lines 99 should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchLinesComposesWithMatchCode verifies the positive match gates are
// a conjunction: an unconfirmed response is kept only if BOTH its line count is
// allowlisted AND its status is allowlisted. Here the line count matches but the
// code does not, so the response is dropped.
func TestScan_MatchLinesComposesWithMatchCode(t *testing.T) {
	srv := multiLineNoiseServer() // 200, body is the 3-line noise
	defer srv.Close()

	f := matchLinesNoiseFlags(t, srv.URL, "3") // line gate passes
	f.matchCode = "500"                        // status gate fails (noise is 200)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the code gate must be dropped even when the line gate passes, got:\n%s", out)
	}
}

// TestScan_MatchLinesComposesWithFilterLines verifies the match gate runs before
// the suppression filters: --match-lines keeps the allowlisted count, then
// --filter-lines prunes it back out. With both naming the same count, the net
// result is suppression (the suppressor wins on the kept set).
func TestScan_MatchLinesComposesWithFilterLines(t *testing.T) {
	srv := multiLineNoiseServer()
	defer srv.Close()

	f := matchLinesNoiseFlags(t, srv.URL, "3") // keep: line count matches
	f.filterLines = "3"                        // then suppress: count also matches the filter
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-lines must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchLinesComposesWithMatchWords verifies --match-lines composes with
// its sibling word-count gate: the body must satisfy BOTH. The 3-line noise has
// a word count outside the named band, so even though the line gate passes the
// response is dropped — demonstrating the line gate adds a distinct dimension.
func TestScan_MatchLinesComposesWithMatchWords(t *testing.T) {
	srv := multiLineNoiseServer() // 3 lines, 5 words ("soft-404 not found template page")
	defer srv.Close()

	f := matchLinesNoiseFlags(t, srv.URL, "3") // line gate passes (3 lines)
	f.matchWords = "99"                        // word gate fails (not 99 words)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the word gate must be dropped even when the line gate passes, got:\n%s", out)
	}
}

// TestScan_MatchLinesInvalidSpecErrors verifies a malformed --match-lines value
// fails before any requests fire.
func TestScan_MatchLinesInvalidSpecErrors(t *testing.T) {
	srv := multiLineNoiseServer()
	defer srv.Close()

	err := runScan(matchLinesNoiseFlags(t, srv.URL, "20-10")) // reversed range
	if err == nil {
		t.Fatal("expected error for reversed --match-lines range")
	}
	if !strings.Contains(err.Error(), "matchlines") {
		t.Fatalf("unexpected error: %v", err)
	}
}
