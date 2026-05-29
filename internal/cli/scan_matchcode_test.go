package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// matchCodeNoiseFlags builds scanFlags against the curated fixture DB that DO
// emit unconfirmed responses (onlyHits=false), so --match-code is the only thing
// governing the "[responded]" stream. Chaining is disabled for determinism. The
// suppression filters and the regex match gate are left empty so the positive
// status-code gate is exercised in isolation.
func matchCodeNoiseFlags(t *testing.T, serverURL, matchCode string) scanFlags {
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
		matchCode:      matchCode,
	}
}

// TestScan_MatchCodeKeepsOnlyAllowlisted verifies that, without a match filter,
// the uniform-status noise responses appear, and that naming a code the noise
// does NOT carry drops them all — only allowlisted statuses survive.
func TestScan_MatchCodeKeepsOnlyAllowlisted(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound) // every miss answers 404
	defer srv.Close()

	// Baseline: no match filter — the noise should show up.
	baseline := captureStdout(t, func() {
		if err := runScan(matchCodeNoiseFlags(t, srv.URL, "")); err != nil {
			t.Fatalf("runScan baseline: %v", err)
		}
	})
	if !strings.Contains(baseline, "[responded]") {
		t.Fatalf("baseline produced no [responded] lines:\n%s", baseline)
	}

	// Match only 500 — the 404 noise is dropped because its status is not in
	// the allowlist (the inverse of --filter-code).
	out := captureStdout(t, func() {
		if err := runScan(matchCodeNoiseFlags(t, srv.URL, "500")); err != nil {
			t.Fatalf("runScan filtered: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-code 500 should drop all 404 noise, got:\n%s", out)
	}
}

// TestScan_MatchCodeKeepsMatchingNoise verifies that naming the noise's own
// status code in --match-code keeps the unconfirmed responses (the positive
// gate passes).
func TestScan_MatchCodeKeepsMatchingNoise(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound) // 404 noise
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchCodeNoiseFlags(t, srv.URL, "404")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("--match-code 404 should keep the 404 responses, got:\n%s", out)
	}
}

// TestScan_MatchCodeRangeKeeps verifies a range spec keeps a code that falls
// inside it (a 403 inside 400-499).
func TestScan_MatchCodeRangeKeeps(t *testing.T) {
	srv := codeNoiseServer(http.StatusForbidden) // 403
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := runScan(matchCodeNoiseFlags(t, srv.URL, "400-499")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[responded]") {
		t.Fatalf("range match 400-499 should keep a 403, got:\n%s", out)
	}
}

// TestScan_MatchCodeNeverDropsHits verifies a confirmed hit is reported even
// when --match-code names a code the hit's 200 response does NOT carry. The
// leaked passwd file is content-confirmed and must survive the match gate,
// which only governs the unconfirmed stream.
func TestScan_MatchCodeNeverDropsHits(t *testing.T) {
	const passwdBody = "root:x:0:0:root:/root:/bin/bash\n" // matches the fixture 'passwd' confirm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte(passwdBody)) // a genuine read, 200
			return
		}
		w.WriteHeader(http.StatusNotFound) // uniform 404 noise
		_, _ = w.Write([]byte(noiseBody))
	}))
	defer srv.Close()

	// Match only 500: this drops the 404 noise AND would drop the 200 hit if the
	// gate touched confirmed hits — it must not.
	out := captureStdout(t, func() {
		if err := runScan(matchCodeNoiseFlags(t, srv.URL, "500")); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if !strings.Contains(out, "[CONFIRMED]") {
		t.Fatalf("confirmed hit must survive --match-code, got:\n%s", out)
	}
	if strings.Contains(out, "[responded]") {
		t.Fatalf("--match-code 500 should drop every unconfirmed 404 line, got:\n%s", out)
	}
}

// TestScan_MatchCodeComposesWithMatchRegex verifies the two positive match gates
// are a conjunction: an unconfirmed response is kept only if BOTH its status is
// allowlisted AND its body matches the require-regex. Here the status matches
// but the regex does not, so the response is dropped.
func TestScan_MatchCodeComposesWithMatchRegex(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound) // 404, body is noiseBody
	defer srv.Close()

	f := matchCodeNoiseFlags(t, srv.URL, "404") // status gate passes
	f.matchRegex = "this-phrase-never-appears"  // body gate fails
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a response failing the regex gate must be dropped even when the code gate passes, got:\n%s", out)
	}
}

// TestScan_MatchCodeComposesWithFilterCode verifies the match gate runs before
// the suppression filters: --match-code keeps the allowlisted status, then
// --filter-code prunes it back out. With both naming the same code, the net
// result is suppression (the suppressor wins on the kept set).
func TestScan_MatchCodeComposesWithFilterCode(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound) // 404
	defer srv.Close()

	f := matchCodeNoiseFlags(t, srv.URL, "404") // keep: status matches
	f.filterCode = "404"                        // then suppress: status also matches the filter
	out := captureStdout(t, func() {
		if err := runScan(f); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})
	if strings.Contains(out, "[responded]") {
		t.Fatalf("a kept response that also matches --filter-code must be suppressed, got:\n%s", out)
	}
}

// TestScan_MatchCodeInvalidSpecErrors verifies a malformed --match-code value
// fails before any requests fire.
func TestScan_MatchCodeInvalidSpecErrors(t *testing.T) {
	srv := codeNoiseServer(http.StatusNotFound)
	defer srv.Close()

	err := runScan(matchCodeNoiseFlags(t, srv.URL, "600")) // out of the valid 100-599 range
	if err == nil {
		t.Fatal("expected error for out-of-range --match-code")
	}
	if !strings.Contains(err.Error(), "matchcode") {
		t.Fatalf("unexpected error: %v", err)
	}
}
