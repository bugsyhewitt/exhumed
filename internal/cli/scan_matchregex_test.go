package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchNoiseFlags builds scanFlags against the curated fixture DB that DO emit
// unconfirmed responses (onlyHits=false), so --match-regex is the only thing
// governing the "[responded]" stream. Chaining is disabled for determinism. The
// suppression filters are left empty so the positive match gate is exercised in
// isolation.
func matchNoiseFlags(t *testing.T, serverURL, matchRegex string) scanFlags {
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
		matchRegex:     matchRegex,
	}
}

// TestScan_MatchRegexKeepsOnlyMatching verifies that, without a match filter,
// the uniform soft-404 noise responses appear, and that naming a phrase the
// noise body does NOT contain drops them all — only matching bodies survive.
func TestScan_MatchRegexKeepsOnlyMatching(t *testing.T) {
	srv := regexNoiseServer() // 200 soft-404 body
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Match a phrase the noise body does NOT contain — every [responded] line
	// is dropped because none of the bodies match the require-regex.
	out := captureStdout(t, func() {
		if err := runScan(matchNoiseFlags(t, srv.URL, "this-phrase-never-appears")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-regex with a non-matching pattern should drop all noise, got:\n%s", out)
	}
}

// TestScan_MatchRegexKeepsMatchingNoise verifies that a match regex naming a
// phrase the noise body DOES contain keeps the unconfirmed responses (the
// positive gate passes).
func TestScan_MatchRegexKeepsMatchingNoise(t *testing.T) {
	srv := regexNoiseServer() // body contains "soft-404"
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchNoiseFlags(t, srv.URL, "soft-404")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-regex matching the body should keep the responses, got:\n%s", out)
	}
}

// TestScan_MatchRegexCaseInsensitive verifies an (?i) pattern matches the noise
// body regardless of case and therefore keeps it.
func TestScan_MatchRegexCaseInsensitive(t *testing.T) {
	srv := regexNoiseServer() // "soft-404 not found template"
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchNoiseFlags(t, srv.URL, "(?i)NOT FOUND")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("case-insensitive match should keep the responses, got:\n%s", out)
	}
}

// TestScan_MatchRegexNeverDropsHits verifies a confirmed hit is reported even
// when --match-regex names a phrase the hit body does NOT contain. The leaked
// passwd file is content-confirmed and must survive the match gate, which only
// governs the unconfirmed stream.
func TestScan_MatchRegexNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read
			return
		}
		_, _ = w.Write([]byte(noiseBody)) // uniform soft-404 noise page
	}))
	defer srv.Close()

	// The match regex names a phrase neither body class contains for the hit:
	// it would drop the unconfirmed noise but must NOT touch the confirmed hit.
	out := captureStdout(t, func() {
		if err := runScan(matchNoiseFlags(t, srv.URL, "this-phrase-never-appears")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-regex, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("non-matching --match-regex should drop every unconfirmed line, got:\n%s", out)
	}
}

// TestScan_MatchRegexComposesWithFilterRegex verifies the match gate runs before
// the suppression filters: --match-regex keeps the matching body, then
// --filter-regex prunes it back out. With both naming the same phrase the noise
// body carries, the net result is suppression (filter wins on the kept set).
func TestScan_MatchRegexComposesWithFilterRegex(t *testing.T) {
	srv := regexNoiseServer() // body contains "soft-404" and "not found"
	defer srv.Close()

	f := matchNoiseFlags(t, srv.URL, "soft-404") // keep: body matches
	f.filterRegex = "not found"                  // then suppress: body also matches the filter
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept body that also matches --filter-regex must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchRegexInvalidSpecErrors verifies a malformed --match-regex value
// fails before any requests fire.
func TestScan_MatchRegexInvalidSpecErrors(t *testing.T) {
	srv := regexNoiseServer()
	defer srv.Close()

	err := runScan(matchNoiseFlags(t, srv.URL, "(unclosed")) // invalid RE2
	if err == nil {
		t.Fatal("expected error for malformed --match-regex")
	}
	if !strings.Contains(err.Error(), "matchfilter") {
		t.Fatalf("unexpected error: %v", err)
	}
}
