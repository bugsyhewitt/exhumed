package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchWordsNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-words is the only
// thing governing the "[responded]" stream. Chaining is disabled for
// determinism. The suppression filters and the other match gates are left empty
// so the positive word-count gate is exercised in isolation.
//
// noiseBody is "soft-404 not found template" — four whitespace-separated words.
func matchWordsNoiseFlags(t *testing.T, serverURL, matchWords string) scanFlags {
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
		matchWords:     matchWords,
	}
}

// TestScan_MatchWordsKeepsOnlyAllowlisted verifies that, without a match filter,
// the uniform-word-count noise responses appear, and that naming a word count
// the noise does NOT carry drops them all — only allowlisted word counts
// survive.
func TestScan_MatchWordsKeepsOnlyAllowlisted(t *testing.T) {
	srv := noiseServer() // every miss answers the 4-word noiseBody
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchWordsNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Match only a word count the noise does NOT have — the noise is dropped
	// because its count is not in the allowlist (the inverse of --filter-words).
	out := captureStdout(t, func() {
		if err := runScan(matchWordsNoiseFlags(t, srv.URL, "99")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-words 99 should drop all 4-word noise, got:\n%s", out)
	}
}

// TestScan_MatchWordsKeepsMatchingNoise verifies that naming the noise's own
// word count in --match-words keeps the unconfirmed responses (the positive gate
// passes).
func TestScan_MatchWordsKeepsMatchingNoise(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchWordsNoiseFlags(t, srv.URL, "4")); err != nil { // noiseBody has 4 words
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-words 4 should keep the noise responses, got:\n%s", out)
	}
}

// TestScan_MatchWordsRangeKeeps verifies a range spec keeps a body whose word
// count falls inside it (the 4-word noise inside 2-6).
func TestScan_MatchWordsRangeKeeps(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchWordsNoiseFlags(t, srv.URL, "2-6")); err != nil { // 4 ∈ [2,6]
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("range match 2-6 should keep a 4-word body, got:\n%s", out)
	}
}

// TestScan_MatchWordsNeverDropsHits verifies a confirmed hit is reported even
// when --match-words names a count the hit's response body does NOT carry. The
// leaked passwd file is content-confirmed and must survive the match gate, which
// only governs the unconfirmed stream.
func TestScan_MatchWordsNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm (1 word)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read, 200
			return
		}
		_, _ = w.Write([]byte(noiseBody)) // uniform 4-word noise
	}))
	defer srv.Close()

	// Match only a count neither body has: this drops the noise AND would drop
	// the hit if the gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(matchWordsNoiseFlags(t, srv.URL, "99")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-words, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-words 99 should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchWordsComposesWithMatchCode verifies the positive match gates are
// a conjunction: an unconfirmed response is kept only if BOTH its word count is
// allowlisted AND its status is allowlisted. Here the word count matches but the
// code does not, so the response is dropped.
func TestScan_MatchWordsComposesWithMatchCode(t *testing.T) {
	srv := noiseServer() // 200, body is the 4-word noiseBody
	defer srv.Close()

	f := matchWordsNoiseFlags(t, srv.URL, "4") // word gate passes
	f.matchCode = "500"                        // status gate fails (noise is 200)
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the code gate must be dropped even when the word gate passes, got:\n%s", out)
	}
}

// TestScan_MatchWordsComposesWithFilterWords verifies the match gate runs before
// the suppression filters: --match-words keeps the allowlisted count, then
// --filter-words prunes it back out. With both naming the same count, the net
// result is suppression (the suppressor wins on the kept set).
func TestScan_MatchWordsComposesWithFilterWords(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	f := matchWordsNoiseFlags(t, srv.URL, "4") // keep: word count matches
	f.filterWords = "4"                        // then suppress: count also matches the filter
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-words must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchWordsInvalidSpecErrors verifies a malformed --match-words value
// fails before any requests fire.
func TestScan_MatchWordsInvalidSpecErrors(t *testing.T) {
	srv := noiseServer()
	defer srv.Close()

	err := runScan(matchWordsNoiseFlags(t, srv.URL, "20-10")) // reversed range
	if err == nil {
		t.Fatal("expected error for reversed --match-words range")
	}
	if !strings.Contains(err.Error(), "matchwords") {
		t.Fatalf("unexpected error: %v", err)
	}
}
